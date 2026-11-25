"""Explore real Odin application inputs and retain only confirmed failures."""

import argparse
import base64
import bisect
from collections import deque
from contextlib import contextmanager
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import random
import re
import resource
import shlex
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.4.0"
FORMAT_VERSION = 3
DEFAULT_BUDGET = 30.0
CASE_TIMEOUT = 2.0
BUILD_TIMEOUT = 120
CONFIRMATIONS = 2
MAX_FLAKY_CONFIRM_ATTEMPTS = 3
MAX_INPUT = 4096
MAX_LOG = 1024 * 1024
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024
MAX_SNAPSHOT_FILES = 4096
MAX_STEPS = 4
MAX_UI_FRAMES = 256
MAX_CORPUS = 128
MAX_TARGETED_QUEUE = 256
MAX_BRANCH_ATTEMPTS = 8
MAX_SHRINK_CHECKS = 24
MAX_SHRINK_SECONDS = 6.0
MAX_UNIX_SOCKET_BYTES = 96
SCAN_BATCH_SIZE = 64
SANITIZER_EXIT_CODE = 77
COVERAGE_MAGIC = b"OFC2"
COVERAGE_SHIM_C = r'''
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CMP_TABLE_BITS 11
#define CMP_TABLE_SIZE (1u << CMP_TABLE_BITS)
#define CMP_TABLE_MASK (CMP_TABLE_SIZE - 1u)
#define STR_TABLE_BITS 8
#define STR_TABLE_SIZE (1u << STR_TABLE_BITS)
#define STR_TABLE_MASK (STR_TABLE_SIZE - 1u)
#define STR_MAX_LEN 64

typedef struct {
    uint64_t pc;
    uint64_t a;
    uint64_t b;
    uint8_t width;
    uint8_t kind;
    uint8_t used;
} CmpEntry;

typedef struct {
    uint8_t a[STR_MAX_LEN];
    uint8_t b[STR_MAX_LEN];
    uint8_t a_len;
    uint8_t b_len;
    uint8_t used;
} StrCmpEntry;

typedef struct {
    const uint8_t *ptr;
    int64_t len;
} OdinStr;

static int g_enabled = 0;
static const char *g_cov_path = NULL;
static uintptr_t g_slide = 0;
static uint32_t g_num_guards = 1;
static uint32_t g_edge_cap = 0;
static uint16_t *g_edge_counts = NULL;
static uint64_t *g_edge_pcs = NULL;
static CmpEntry g_cmps[CMP_TABLE_SIZE];
static uint32_t g_cmp_count = 0;
static StrCmpEntry g_str_cmps[STR_TABLE_SIZE];
static uint32_t g_str_cmp_count = 0;

static void init_cov_env(void) {
    static int initialized = 0;
    if (initialized) return;
    initialized = 1;
    g_cov_path = getenv("ODIN_FUZZ_COV_FILE");
    if (g_cov_path && g_cov_path[0]) {
        g_slide = (uintptr_t)_dyld_get_image_vmaddr_slide(0);
        __atomic_store_n(&g_enabled, 1, __ATOMIC_RELEASE);
    }
}

void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
    init_cov_env();
    if (!__atomic_load_n(&g_enabled, __ATOMIC_ACQUIRE) || start == stop || *start) return;
    uint32_t needed = g_num_guards + (uint32_t)(stop - start) + 1u;
    if (needed > g_edge_cap) {
        uint32_t new_cap = g_edge_cap ? g_edge_cap : 1024u;
        while (new_cap < needed) new_cap *= 2u;
        uint16_t *new_counts = (uint16_t *)calloc(new_cap, sizeof(uint16_t));
        uint64_t *new_pcs = (uint64_t *)calloc(new_cap, sizeof(uint64_t));
        if (!new_counts || !new_pcs) {
            free(new_counts);
            free(new_pcs);
            __atomic_store_n(&g_enabled, 0, __ATOMIC_RELEASE);
            return;
        }
        if (g_edge_counts) {
            memcpy(new_counts, g_edge_counts, g_edge_cap * sizeof(uint16_t));
            free(g_edge_counts);
        }
        if (g_edge_pcs) {
            memcpy(new_pcs, g_edge_pcs, g_edge_cap * sizeof(uint64_t));
            free(g_edge_pcs);
        }
        g_edge_counts = new_counts;
        g_edge_pcs = new_pcs;
        g_edge_cap = new_cap;
    }
    for (uint32_t *x = start; x < stop; x++) {
        *x = g_num_guards++;
    }
}

void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
    if (!__atomic_load_n(&g_enabled, __ATOMIC_ACQUIRE)) return;
    uint32_t id = *guard;
    if (!id || id >= g_edge_cap) return;
    uint16_t cur = __atomic_load_n(&g_edge_counts[id], __ATOMIC_RELAXED);
    if (cur == 0) {
        __atomic_store_n(&g_edge_pcs[id], (uint64_t)((uintptr_t)__builtin_return_address(0) - g_slide), __ATOMIC_RELAXED);
    }
    if (cur < 65535u) __atomic_store_n(&g_edge_counts[id], (uint16_t)(cur + 1u), __ATOMIC_RELAXED);
}

static inline void record_cmp(void *ret_addr, uint64_t a, uint64_t b, uint8_t width, uint8_t kind) {
    if (!__atomic_load_n(&g_enabled, __ATOMIC_ACQUIRE) || __atomic_load_n(&g_cmp_count, __ATOMIC_RELAXED) >= (CMP_TABLE_SIZE - 64u)) return;
    uint64_t pc = (uint64_t)((uintptr_t)ret_addr - g_slide);
    uint64_t h = (pc * 11400714819323198485ULL) ^ (a * 14029467366897019727ULL) ^ (b * 1609587929392839161ULL);
    uint32_t idx = (uint32_t)(h >> (64 - CMP_TABLE_BITS)) & CMP_TABLE_MASK;
    for (uint32_t probe = 0; probe < 8u; probe++) {
        CmpEntry *slot = &g_cmps[(idx + probe) & CMP_TABLE_MASK];
        uint8_t state = __atomic_load_n(&slot->used, __ATOMIC_ACQUIRE);
        if (state == 0) {
            uint8_t expected = 0;
            if (__atomic_compare_exchange_n(&slot->used, &expected, 1, 0, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
                slot->pc = pc;
                slot->a = a;
                slot->b = b;
                slot->width = width;
                slot->kind = kind;
                __atomic_store_n(&slot->used, 2, __ATOMIC_RELEASE);
                __atomic_fetch_add(&g_cmp_count, 1, __ATOMIC_RELAXED);
                return;
            }
            state = expected;
        }
        if (state == 2 && slot->pc == pc && slot->a == a && slot->b == b) return;
    }
}

void __odin_fuzz_trace_string_eq(OdinStr a, OdinStr b) {
    if (!__atomic_load_n(&g_enabled, __ATOMIC_ACQUIRE) || __atomic_load_n(&g_str_cmp_count, __ATOMIC_RELAXED) >= (STR_TABLE_SIZE - 16u)) return;
    if (!a.ptr || !b.ptr || a.len <= 0 || b.len <= 0 || a.len > STR_MAX_LEN || b.len > STR_MAX_LEN) return;
    if (a.len == b.len && memcmp(a.ptr, b.ptr, (size_t)a.len) == 0) return;
    uint64_t h = 1469598103934665603ULL;
    for (int64_t i = 0; i < a.len; i++) h = (h ^ a.ptr[i]) * 1099511628211ULL;
    h ^= 0xFFULL;
    for (int64_t i = 0; i < b.len; i++) h = (h ^ b.ptr[i]) * 1099511628211ULL;
    uint32_t idx = (uint32_t)(h >> (64 - STR_TABLE_BITS)) & STR_TABLE_MASK;
    for (uint32_t probe = 0; probe < 8u; probe++) {
        StrCmpEntry *slot = &g_str_cmps[(idx + probe) & STR_TABLE_MASK];
        uint8_t state = __atomic_load_n(&slot->used, __ATOMIC_ACQUIRE);
        if (state == 0) {
            uint8_t expected = 0;
            if (__atomic_compare_exchange_n(&slot->used, &expected, 1, 0, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
                slot->a_len = (uint8_t)a.len;
                slot->b_len = (uint8_t)b.len;
                memcpy(slot->a, a.ptr, (size_t)a.len);
                memcpy(slot->b, b.ptr, (size_t)b.len);
                __atomic_store_n(&slot->used, 2, __ATOMIC_RELEASE);
                __atomic_fetch_add(&g_str_cmp_count, 1, __ATOMIC_RELAXED);
                return;
            }
            state = expected;
        }
        if (state == 2 && slot->a_len == (uint8_t)a.len && slot->b_len == (uint8_t)b.len &&
            memcmp(slot->a, a.ptr, (size_t)a.len) == 0 && memcmp(slot->b, b.ptr, (size_t)b.len) == 0) {
            return;
        }
    }
}

void __sanitizer_cov_trace_cmp1(uint8_t a, uint8_t b) { record_cmp(__builtin_return_address(0), a, b, 1, 1); }
void __sanitizer_cov_trace_cmp2(uint16_t a, uint16_t b) { record_cmp(__builtin_return_address(0), a, b, 2, 1); }
void __sanitizer_cov_trace_cmp4(uint32_t a, uint32_t b) { record_cmp(__builtin_return_address(0), a, b, 4, 1); }
void __sanitizer_cov_trace_cmp8(uint64_t a, uint64_t b) { record_cmp(__builtin_return_address(0), a, b, 8, 1); }
void __sanitizer_cov_trace_const_cmp1(uint8_t a, uint8_t b) { record_cmp(__builtin_return_address(0), a, b, 1, 2); }
void __sanitizer_cov_trace_const_cmp2(uint16_t a, uint16_t b) { record_cmp(__builtin_return_address(0), a, b, 2, 2); }
void __sanitizer_cov_trace_const_cmp4(uint32_t a, uint32_t b) { record_cmp(__builtin_return_address(0), a, b, 4, 2); }
void __sanitizer_cov_trace_const_cmp8(uint64_t a, uint64_t b) { record_cmp(__builtin_return_address(0), a, b, 8, 2); }
void __sanitizer_cov_trace_switch(uint64_t val, uint64_t *cases) {
    if (!__atomic_load_n(&g_enabled, __ATOMIC_ACQUIRE) || !cases) return;
    void *ret = __builtin_return_address(0);
    uint64_t count = cases[0];
    uint8_t width = (uint8_t)(cases[1] / 8u);
    if (width == 0) width = 8;
    if (count > 16u) count = 16u;
    for (uint64_t i = 0; i < count; i++) {
        uint64_t cval = cases[2u + i];
        if (cval != val) record_cmp(ret, val, cval, width, 3);
    }
}

static uint8_t count_bucket(uint16_t c) {
    if (c <= 1) return 1;
    if (c == 2) return 2;
    if (c == 3) return 3;
    if (c <= 7) return 4;
    if (c <= 15) return 5;
    if (c <= 31) return 6;
    if (c <= 127) return 7;
    return 8;
}

static void write_all(int fd, const void *buf, size_t n) {
    const uint8_t *p = (const uint8_t *)buf;
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w <= 0) return;
        p += (size_t)w;
        n -= (size_t)w;
    }
}

__attribute__((destructor)) static void dump_cov(void) {
    if (!__atomic_exchange_n(&g_enabled, 0, __ATOMIC_ACQ_REL) || !g_cov_path) return;
    int fd = open(g_cov_path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (fd < 0) return;
    uint32_t hit_edges = 0;
    for (uint32_t i = 1; i < g_num_guards && i < g_edge_cap; i++) {
        if (__atomic_load_n(&g_edge_counts[i], __ATOMIC_RELAXED) > 0) hit_edges++;
    }
    uint32_t cmp_total = 0;
    for (uint32_t i = 0; i < CMP_TABLE_SIZE; i++) {
        if (__atomic_load_n(&g_cmps[i].used, __ATOMIC_ACQUIRE) == 2) cmp_total++;
    }
    uint32_t str_total = 0;
    for (uint32_t i = 0; i < STR_TABLE_SIZE; i++) {
        if (__atomic_load_n(&g_str_cmps[i].used, __ATOMIC_ACQUIRE) == 2) str_total++;
    }
    uint8_t hdr[16];
    memcpy(hdr, "OFC2", 4);
    memcpy(hdr + 4, &hit_edges, 4);
    memcpy(hdr + 8, &cmp_total, 4);
    memcpy(hdr + 12, &str_total, 4);
    write_all(fd, hdr, sizeof(hdr));
    for (uint32_t i = 1; i < g_num_guards && i < g_edge_cap; i++) {
        uint16_t cnt = __atomic_load_n(&g_edge_counts[i], __ATOMIC_RELAXED);
        if (cnt == 0) continue;
        uint8_t rec[13];
        uint8_t b = count_bucket(cnt);
        uint64_t pc = __atomic_load_n(&g_edge_pcs[i], __ATOMIC_RELAXED);
        memcpy(rec, &i, 4);
        memcpy(rec + 4, &pc, 8);
        rec[12] = b;
        write_all(fd, rec, sizeof(rec));
    }
    for (uint32_t i = 0; i < CMP_TABLE_SIZE; i++) {
        if (__atomic_load_n(&g_cmps[i].used, __ATOMIC_ACQUIRE) != 2) continue;
        uint8_t rec[26];
        memcpy(rec, &g_cmps[i].pc, 8);
        memcpy(rec + 8, &g_cmps[i].a, 8);
        memcpy(rec + 16, &g_cmps[i].b, 8);
        rec[24] = g_cmps[i].width;
        rec[25] = g_cmps[i].kind;
        write_all(fd, rec, sizeof(rec));
    }
    for (uint32_t i = 0; i < STR_TABLE_SIZE; i++) {
        if (__atomic_load_n(&g_str_cmps[i].used, __ATOMIC_ACQUIRE) != 2) continue;
        uint8_t lens[2] = { g_str_cmps[i].a_len, g_str_cmps[i].b_len };
        write_all(fd, lens, 2);
        write_all(fd, g_str_cmps[i].a, g_str_cmps[i].a_len);
        write_all(fd, g_str_cmps[i].b, g_str_cmps[i].b_len);
    }
    close(fd);
}
'''
RUNTIME = ".odin-fuzz-runtime"
EXCLUDED = {"vendor", "node_modules", "build", "dist", "target", "__pycache__", "tests", "scripts", "notes", "docs"}
SNAPSHOT_EXCLUDED = {".git", ".work", ".tmp", "__pycache__", "node_modules", "out", "binaries", "build", "dist", "target"}
BASE_ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C", "TZ": "UTC"}
ASAN_OPTIONS = f"detect_leaks=0:abort_on_error=0:exitcode={SANITIZER_EXIT_CODE}:symbolize=1"
UBSAN_OPTIONS = f"halt_on_error=1:exitcode={SANITIZER_EXIT_CODE}:print_stacktrace=1"
FATAL_SIGNALS = {signal.SIGABRT, signal.SIGBUS, signal.SIGFPE, signal.SIGILL, signal.SIGSEGV, signal.SIGTRAP}
AUTO_DRIVEN = {"argv", "stdin", "files", "environment"}
OS_TAGS = {"darwin", "linux", "windows", "freebsd", "openbsd", "netbsd", "haiku", "js", "orca", "wasi", "freestanding", "unix"}
ACTIVE_OS_TAGS = {"darwin", "unix"}
ARCH_TAGS = {"amd64", "i386", "arm32", "arm64", "wasm32", "wasm64p32", "riscv64"}
DEFAULT_UI_KEYS = ["SPACE", "ESCAPE", "ENTER", "UP", "DOWN", "LEFT", "RIGHT", "S", "L"]
ADAPTER_KEYS = ("ui_events", "local_network", "local_ipc", "seed_env", "clock_env")
IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z_0-9]*")
RESERVED_ENV_PREFIXES = ("ASAN_", "UBSAN_", "DYLD_", "LLVM_", "ODIN_FUZZ_COV_")
ODIN_FAILURE_RE = re.compile(
    r"(?m)^(.+\.odin\(\d+:\d+\))\s+"
    r"(runtime assertion|panic|runtime panic|not yet implemented|unreachable|"
    r"bounds check failed|index \S+ is out of range|invalid slice indices|"
    r"invalid matrix indices|matrix indices|type assertion|invalid type assertion|"
    r"invalid slice length for make|invalid dynamic array parameters for make|"
    r"invalid map capacity for make|division by zero)(?::|\b|\s|$)",
    re.IGNORECASE,
)


class ToolError(Exception):
    """An infrastructure/support failure, never a confirmed application bug."""


class WorkspaceError(Exception):
    """A per-case workspace mutation/cleanup failure (recorded, not a confirmed bug)."""


def is_strict_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def is_strict_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def normalize_relative_path(value, *, allow_root=True, allow_hidden=True, label="project-relative path"):
    if not isinstance(value, str) or not value or "\0" in value:
        raise ToolError(f"expected a {label}: {value!r}")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise ToolError(f"expected a {label}: {value!r}")
    normalized = str(path)
    if not allow_root and normalized == ".":
        raise ToolError(f"{label} cannot be project root: {value!r}")
    if not allow_hidden and any(part.startswith(".") for part in path.parts if part != "."):
        raise ToolError(f"{label} cannot reference hidden paths: {value!r}")
    return normalized


def check_no_symlink_escape(project, rel):
    project_root = project.resolve()
    current = project
    for part in Path(rel).parts:
        if part == ".":
            continue
        current = current / part
        if current.is_symlink():
            raise ToolError(f"path cannot traverse symlinks: {rel}")
    resolved = (project / rel).resolve()
    if resolved != project_root and not resolved.is_relative_to(project_root):
        raise ToolError(f"path escapes project snapshot: {rel}")
    return resolved


def _open_dir_nofollow(parent_fd, name):
    """Open child directory inside parent_fd without following symlinks, tolerating read-only modes."""
    try:
        return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    except PermissionError:
        os.fchmod(parent_fd, 0o700)
        os.chmod(name, 0o700, dir_fd=parent_fd, follow_symlinks=False)
        return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)


def _unlink_entry(parent_fd, name):
    try:
        os.unlink(name, dir_fd=parent_fd)
    except PermissionError:
        os.fchmod(parent_fd, 0o700)
        os.unlink(name, dir_fd=parent_fd)


def _safe_rmtree_fd(parent_fd, name):
    """Recursively delete name inside parent_fd without ever following symlinks."""
    try:
        st = os.lstat(name, dir_fd=parent_fd)
    except FileNotFoundError:
        return
    if not stat.S_ISDIR(st.st_mode):
        _unlink_entry(parent_fd, name)
        return
    child_fd = _open_dir_nofollow(parent_fd, name)
    try:
        os.fchmod(child_fd, 0o700)
        for entry in os.listdir(child_fd):
            _safe_rmtree_fd(child_fd, entry)
    finally:
        os.close(child_fd)
    try:
        os.rmdir(name, dir_fd=parent_fd)
    except PermissionError:
        os.fchmod(parent_fd, 0o700)
        os.rmdir(name, dir_fd=parent_fd)


def safe_rmtree(path):
    """Remove a directory tree without following symlinks, tolerating read-only entries."""
    path = Path(path)
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    if not stat.S_ISDIR(st.st_mode):
        path.unlink(missing_ok=True)
        return
    parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        _safe_rmtree_fd(parent_fd, path.name)
    finally:
        os.close(parent_fd)


def _safe_workspace_parts(rel_str, label):
    path = Path(rel_str)
    parts = path.parts
    if path.is_absolute() or not parts or ".." in parts or any(p.startswith(".") for p in parts):
        raise WorkspaceError(f"refusing unsafe {label}: {rel_str!r}")
    return parts


def safe_workspace_write(workspace, rel_str, data):
    """Write data inside workspace strictly without following symlinks or opening special nodes."""
    parts = _safe_workspace_parts(rel_str, "workspace path")
    try:
        cur_fd = os.open(workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as error:
        raise WorkspaceError(f"cannot open workspace root: {error}") from error
    try:
        for part in parts[:-1]:
            try:
                st = os.lstat(part, dir_fd=cur_fd)
            except FileNotFoundError:
                try:
                    os.mkdir(part, 0o700, dir_fd=cur_fd)
                except PermissionError:
                    os.fchmod(cur_fd, 0o700)
                    os.mkdir(part, 0o700, dir_fd=cur_fd)
            else:
                if not stat.S_ISDIR(st.st_mode):
                    # Target created a symlink, regular file, or FIFO where a directory belongs.
                    _unlink_entry(cur_fd, part)
                    os.mkdir(part, 0o700, dir_fd=cur_fd)
            next_fd = _open_dir_nofollow(cur_fd, part)
            os.close(cur_fd)
            cur_fd = next_fd

        leaf = parts[-1]
        try:
            os.fchmod(cur_fd, 0o700)
        except OSError:
            pass
        try:
            st = os.lstat(leaf, dir_fd=cur_fd)
        except FileNotFoundError:
            pass
        else:
            if stat.S_ISDIR(st.st_mode):
                _safe_rmtree_fd(cur_fd, leaf)
            else:
                os.unlink(leaf, dir_fd=cur_fd)
        file_fd = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=cur_fd)
        with os.fdopen(file_fd, "wb") as handle:
            handle.write(data)
    except OSError as error:
        raise WorkspaceError(f"cannot write workspace file {rel_str}: {error}") from error
    finally:
        os.close(cur_fd)


def safe_workspace_delete(workspace, rel_str):
    """Delete a non-directory entry inside workspace without following symlinks."""
    parts = _safe_workspace_parts(rel_str, "workspace delete")
    try:
        cur_fd = os.open(workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as error:
        raise WorkspaceError(f"cannot open workspace root: {error}") from error
    try:
        for part in parts[:-1]:
            try:
                st = os.lstat(part, dir_fd=cur_fd)
            except FileNotFoundError:
                return
            if not stat.S_ISDIR(st.st_mode):
                return
            try:
                next_fd = _open_dir_nofollow(cur_fd, part)
            except OSError:
                return
            os.close(cur_fd)
            cur_fd = next_fd
        leaf = parts[-1]
        try:
            st = os.lstat(leaf, dir_fd=cur_fd)
        except FileNotFoundError:
            return
        if stat.S_ISDIR(st.st_mode):
            return
        _unlink_entry(cur_fd, leaf)
    except OSError as error:
        raise WorkspaceError(f"cannot delete workspace file {rel_str}: {error}") from error
    finally:
        os.close(cur_fd)


def clone_workspace(initial, destination):
    """Clone starting project files (excluding the read-only runtime dir) into a fresh workspace."""
    destination.mkdir(parents=True, exist_ok=True)
    entries = [entry for entry in sorted(initial.iterdir()) if entry.name != RUNTIME]
    if not entries:
        return
    if sys.platform == "darwin":
        result = subprocess.run(["/bin/cp", "-cPR", *(str(e) for e in entries), str(destination)],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result.returncode == 0:
            return
        safe_rmtree(destination)
        destination.mkdir(parents=True, exist_ok=True)
    for entry in entries:
        target = destination / entry.name
        if entry.is_symlink():
            raise ToolError(f"captured initial tree contains unexpected symlink: {entry.name}")
        if entry.is_dir():
            shutil.copytree(entry, target, symlinks=True)
        else:
            shutil.copy2(entry, target, follow_symlinks=False)


def workspace_files(root):
    """List ordinary non-hidden regular file paths without reading file contents or following symlinks."""
    found = set()
    for directory, subdirectories, files in os.walk(root, followlinks=False):
        kept = []
        for d in subdirectories:
            if d.startswith(".") or d == RUNTIME:
                continue
            try:
                if stat.S_ISDIR(os.lstat(os.path.join(directory, d)).st_mode):
                    kept.append(d)
            except OSError:
                pass
        subdirectories[:] = kept
        rel_dir = Path(directory).relative_to(root)
        for name in files:
            if name.startswith("."):
                continue
            try:
                if not stat.S_ISREG(os.lstat(os.path.join(directory, name)).st_mode):
                    continue
            except OSError:
                continue
            found.add(name if rel_dir == Path(".") else str(rel_dir / name))
    return found


def run(command, *, cwd, timeout, log, env=None, stdin=None, sandbox=None, fsize_limit=MAX_LOG):
    """Run a bounded process tree with separate, bounded stdout and stderr."""
    command = [str(arg) for arg in command]
    if sandbox:
        command = ["/usr/bin/sandbox-exec", "-p", sandbox, *command]
    log = Path(log)
    log.parent.mkdir(parents=True, exist_ok=True)
    stderr_path = log.with_suffix(".stderr")
    started = time.monotonic()

    def limits():
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if fsize_limit:
            resource.setrlimit(resource.RLIMIT_FSIZE, (fsize_limit, fsize_limit))

    with log.open("wb") as output, stderr_path.open("wb") as errors, open(stdin or os.devnull, "rb") as incoming:
        try:
            process = subprocess.Popen(command, cwd=cwd, env=env, stdin=incoming,
                                       stdout=output, stderr=errors, start_new_session=True, preexec_fn=limits)
        except OSError as error:
            raise ToolError(f"cannot execute {command[0]}: {error}") from error
        timed_out = False
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
        finally:
            # Also remove children left behind after an otherwise normal parent exit.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except PermissionError:
                # macOS can return EPERM from killpg on an exiting/reaped sandbox-exec group.
                if process.poll() is None:
                    try:
                        process.kill()
                    except OSError:
                        pass
            process.wait()
    return {"returncode": process.returncode, "timed_out": timed_out,
            "elapsed": time.monotonic() - started, "stdout": log.read_text(errors="replace"),
            "stderr": stderr_path.read_text(errors="replace"), "log": str(log), "stderr_log": str(stderr_path)}


def is_nix_store_path(path):
    if not path:
        return False
    return str(Path(path).resolve()).startswith("/nix/store/")


def llvm_tool_major(tool_path):
    if not tool_path:
        return None
    try:
        out = subprocess.check_output([tool_path, "--version"], stderr=subprocess.STDOUT, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    if "Apple clang" in out or "Apple LLVM" in out:
        return None
    match = re.search(r"(?:clang|LLVM)\s+version\s+(\d+)\.", out)
    return match.group(1) if match else None


def require_packaged_runtime():
    root_resolved = ROOT.resolve()
    if os.environ.get("ODIN_FUZZ_PACKAGED") != "1" or not is_nix_store_path(root_resolved):
        raise ToolError(
            "direct unpackaged execution is disabled; "
            "use the pinned Nix package (nix run . -- <args>) or a consumer Nix environment"
        )
    bundled = (root_resolved.parents[1] / "libexec" / "odin-fuzz-scan") if root_resolved.parent.name == "share" else None
    if not bundled or not bundled.is_file() or not is_nix_store_path(bundled):
        raise ToolError("packaged odin-fuzz is missing its immutable Nix scanner binary")
    env_scanner = os.environ.get("ODIN_FUZZ_SCANNER")
    if env_scanner and Path(env_scanner).resolve() != bundled.resolve():
        raise ToolError("packaged odin-fuzz refuses ODIN_FUZZ_SCANNER substitution")
    return bundled.resolve()


def toolchain(odin_override=None):
    require_packaged_runtime()
    pinned_odin = os.environ.get("ODIN")
    if not pinned_odin or not Path(pinned_odin).is_file() or not is_nix_store_path(pinned_odin):
        raise ToolError("packaged odin-fuzz requires the pinned Nix Odin compiler; reinstall or run via Nix")
    if odin_override:
        resolved_override = shutil.which(odin_override)
        if not resolved_override or Path(resolved_override).resolve() != Path(pinned_odin).resolve():
            raise ToolError("packaged odin-fuzz refuses compiler override; use the pinned Nix package toolchain")
    odin = pinned_odin
    report = subprocess.check_output([odin, "report"], text=True, timeout=15)
    match = re.search(r"Backend:\s+LLVM\s+(\d+)", report)
    if not match:
        raise ToolError("Odin report did not declare an LLVM backend major version")
    major = match.group(1)
    tools = {}
    for name in ("llvm-symbolizer", "clang", "dsymutil", "nm"):
        found = (shutil.which("nm") or shutil.which("llvm-nm")) if name == "nm" else shutil.which(name)
        if not found or not is_nix_store_path(found):
            raise ToolError(f"Nix-locked {name} is required on PATH; use the pinned Nix package")
        if name != "nm" and llvm_tool_major(found) != major:
            raise ToolError(f"Nix-locked {name} must match Odin LLVM major {major}")
        tools[name] = str(Path(found).resolve())
    return {
        "odin": str(Path(odin).resolve()),
        "odin_report": report,
        "symbolizer": tools["llvm-symbolizer"],
        "clang": tools["clang"],
        "dsymutil": tools["dsymutil"],
        "nm": tools["nm"],
    }


def scanner(chain):
    del chain
    return require_packaged_runtime()


def validate_env_name(value, label):
    if not isinstance(value, str) or not IDENT_RE.fullmatch(value):
        raise ToolError(f"{label} must be a valid environment variable name")
    if value.startswith(RESERVED_ENV_PREFIXES):
        raise ToolError(f"{label} cannot override instrumentation environment variables")


def validate_adapter_config(config):
    """Validate and normalize boundary adapter settings shared by explore and reproduce."""
    if not isinstance(config, dict):
        raise ToolError("adapter configuration must be an object")
    for key in ("seed_env", "clock_env"):
        if key in config:
            validate_env_name(config[key], key)
    if "ui_events" in config:
        ui = config["ui_events"]
        ui_allowed = {"mode", "path", "env", "format", "keys", "max_frames"}
        if not isinstance(ui, dict) or set(ui) - ui_allowed:
            raise ToolError(f"ui_events keys must be within {sorted(ui_allowed)}")
        if ui.get("mode", "file") not in {"file", "stdin", "env"}:
            raise ToolError("ui_events.mode must be 'file', 'stdin', or 'env'")
        if "path" in ui:
            ui["path"] = normalize_relative_path(ui["path"], allow_root=False, allow_hidden=False, label="ui_events.path")
        if "env" in ui:
            validate_env_name(ui["env"], "ui_events.env")
        if ui.get("format", "json") not in {"json", "jsonl"}:
            raise ToolError("ui_events.format must be 'json' or 'jsonl'")
        if "keys" in ui and (not isinstance(ui["keys"], list) or not ui["keys"] or any(not isinstance(k, str) or not k for k in ui["keys"])):
            raise ToolError("ui_events.keys must be a nonempty array of key names")
        if "max_frames" in ui and (not is_strict_int(ui["max_frames"]) or not 1 <= ui["max_frames"] <= MAX_UI_FRAMES):
            raise ToolError(f"ui_events.max_frames must be an integer in 1..{MAX_UI_FRAMES}")
    for section, env_keys in (("local_network", ("port_env", "host_env")), ("local_ipc", ("socket_env",))):
        if section not in config:
            continue
        block = config[section]
        allowed = {"role", *env_keys}
        if not isinstance(block, dict) or set(block) - allowed:
            raise ToolError(f"{section} keys must be within {sorted(allowed)}")
        if block.get("role", "server") not in {"server", "client"}:
            raise ToolError(f"{section}.role must be 'server' or 'client'")
        for k in env_keys:
            if k in block:
                validate_env_name(block[k], f"{section}.{k}")


def enabled_adapters(app):
    """Single source of truth for boundary adapters actually enabled on an application."""
    args_text = " ".join(app.get("args", []))
    enabled = set()
    if app.get("ui_events"):
        enabled.add("ui")
    if app.get("local_network"):
        enabled.add("network")
    if app.get("local_ipc"):
        enabled.add("ipc")
    if app.get("seed_env") or "{seed}" in args_text:
        enabled.add("randomness")
    if app.get("clock_env") or "{time}" in args_text:
        enabled.add("clock")
    return enabled


def validate_application_config(project, app):
    allowed = {"path", "name", "args", "files", "env", *ADAPTER_KEYS}
    if not isinstance(app, dict) or set(app) - allowed or "path" not in app:
        raise ToolError(f"application config keys must be within {sorted(allowed)} and include 'path'")
    app["path"] = normalize_relative_path(app["path"], allow_root=True, allow_hidden=False, label="application path")
    check_no_symlink_escape(project, app["path"])
    if not (project / app["path"]).is_dir():
        raise ToolError(f"application package does not exist: {app['path']}")
    if "name" in app and (not isinstance(app["name"], str) or not app["name"].strip()):
        raise ToolError("application name must be a nonempty string")
    if "args" in app and (not isinstance(app["args"], list) or any(
            not isinstance(v, str) or "\0" in v for v in app["args"])):
        raise ToolError("application args must be an array of strings without NUL bytes")
    if "files" in app:
        if not isinstance(app["files"], list):
            raise ToolError("application files must be an array of project-relative paths")
        app["files"] = [
            normalize_relative_path(f, allow_root=False, allow_hidden=False, label="application file")
            for f in app["files"]
        ]
    if "env" in app:
        if not isinstance(app["env"], list):
            raise ToolError("application env must be an array of environment variable names")
        for name in app["env"]:
            validate_env_name(name, "application env")
    validate_adapter_config(app)
    args_text = " ".join(app.get("args", []))
    if "{events}" in args_text and not app.get("ui_events"):
        raise ToolError("application args uses {events} without ui_events adapter configuration")
    if "{port}" in args_text and not app.get("local_network"):
        raise ToolError("application args uses {port} without local_network adapter configuration")
    if "{socket}" in args_text and not app.get("local_ipc"):
        raise ToolError("application args uses {socket} without local_ipc adapter configuration")


def project_settings(project):
    settings = {"collections": {}, "odin_flags": [], "linker_flags": [], "exclude": [], "applications": []}
    path = project / "odin-fuzz.json"
    if path.exists():
        supplied = json.loads(path.read_text())
        if not isinstance(supplied, dict) or set(supplied) - set(settings):
            raise ToolError("odin-fuzz.json must contain only collections, odin_flags, linker_flags, exclude, applications")
        settings.update(supplied)
    if not isinstance(settings["collections"], dict):
        raise ToolError("collections must map names to project-relative directories")
    ols_path = project / "ols.json"
    if ols_path.exists():
        ols = json.loads(ols_path.read_text())
        if not isinstance(ols, dict):
            raise ToolError("ols.json must be a JSON object")
        ols_collections = ols.get("collections", [])
        if not isinstance(ols_collections, list):
            raise ToolError("ols.json collections must be an array")
        for collection in ols_collections:
            if isinstance(collection, dict) and "name" in collection and "path" in collection:
                settings["collections"].setdefault(collection["name"], collection["path"])
    normalized_collections = {}
    for name, directory in settings["collections"].items():
        if not isinstance(name, str) or not IDENT_RE.fullmatch(name):
            raise ToolError("invalid collection name")
        rel = normalize_relative_path(directory, allow_root=True, allow_hidden=True, label="collection path")
        resolved = check_no_symlink_escape(project, rel)
        if not resolved.is_dir():
            raise ToolError(f"collection directory does not exist inside project snapshot: {directory}")
        normalized_collections[name] = rel
    settings["collections"] = normalized_collections
    for key in ("odin_flags", "linker_flags", "exclude"):
        if not isinstance(settings[key], list) or any(not isinstance(v, str) for v in settings[key]):
            raise ToolError(f"{key} must be an array of strings")
    for flag in settings["odin_flags"]:
        if not flag.startswith(("-define:", "-microarch:", "-target-features:")):
            raise ToolError(f"unsupported native project compiler flag: {flag}")
    settings["exclude"] = [
        normalize_relative_path(excluded, allow_root=False, allow_hidden=True, label="exclude path")
        for excluded in settings["exclude"]
    ]
    if not isinstance(settings["applications"], list):
        raise ToolError("applications must be an array of launch descriptions")
    for app in settings["applications"]:
        validate_application_config(project, app)
    return settings


def darwin_compatible(build_tags, *, ignored=False, machine=None):
    """Evaluate Odin #+ignore and #+build lines for macOS on the host architecture.

    In Odin, multiple #+build lines are ANDed; within a line, commas separate OR
    clauses, and whitespace within each clause separates AND terms.
    """
    if ignored:
        return False
    arch_raw = (machine or os.uname().machine).lower()
    host_arch = "arm64" if arch_raw in {"arm64", "aarch64"} else "amd64" if arch_raw in {"x86_64", "amd64"} else arch_raw

    def eval_term(term):
        negated = term.startswith("!")
        name = term[1:] if negated else term
        if name in OS_TAGS:
            val = name in ACTIVE_OS_TAGS
        elif name in ARCH_TAGS:
            val = name == host_arch
        else:
            return True
        return (not val) if negated else val

    for line in build_tags or []:
        or_clauses = [part.strip() for part in line.split(",") if part.strip()]
        if not or_clauses:
            continue
        if not any(all(eval_term(term) for term in clause.split()) for clause in or_clauses):
            return False
    return True


def interface_inventory(app):
    """Summarize discovered and adapter-configured interfaces for one application."""
    adapter_kinds = enabled_adapters(app)
    by_kind = {}
    for site in app["interfaces"]:
        kind = site["kind"]
        if kind in adapter_kinds:
            status = "adapter_driven"
        elif kind in AUTO_DRIVEN:
            status = "driven"
        elif kind in {"clock", "randomness"}:
            status = "nondeterministic_gap"
        else:
            status = "unsupported"
        entry = by_kind.setdefault(kind, {"kind": kind, "status": status, "sites": []})
        entry["sites"].append({"path": site["path"], "line": site["line"], "expression": site["expression"]})
    for kind in sorted(adapter_kinds):
        if kind not in by_kind:
            by_kind[kind] = {"kind": kind, "status": "adapter_driven", "sites": [{"path": "odin-fuzz.json", "line": 0, "expression": "adapter config"}]}
    return [by_kind[k] for k in sorted(by_kind)]


def discover(project, chain, work, settings):
    binary = scanner(chain)
    excluded_set = set(settings["exclude"])
    paths, excluded = [], []
    for directory, subdirectories, files in os.walk(project, followlinks=False):
        kept = []
        for name in sorted(subdirectories):
            path = Path(directory) / name
            relative = str(path.relative_to(project))
            if name.startswith(".") or name in EXCLUDED or path.is_symlink() or relative in excluded_set:
                excluded.append({"path": relative, "reason": "directory outside automatic application discovery"})
            else:
                kept.append(name)
        subdirectories[:] = kept
        for name in sorted(files):
            path = Path(directory) / name
            if path.suffix != ".odin":
                continue
            relative = str(path.relative_to(project))
            st = path.lstat()
            if not stat.S_ISREG(st.st_mode) or name.endswith("_test.odin") or st.st_size > MAX_SOURCE_BYTES or relative in excluded_set:
                excluded.append({"path": relative, "reason": "symlink, test, configured exclusion, or source size limit"})
            else:
                paths.append(path)
    records = []
    for offset in range(0, len(paths), SCAN_BATCH_SIZE):
        batch = paths[offset:offset + SCAN_BATCH_SIZE]
        result = run([binary, *batch], cwd=work, timeout=60, log=work / f"scanner-{offset}.log", fsize_limit=16 * 1024 * 1024)
        if result["returncode"]:
            raise ToolError("source discovery failed: " + result["stderr"])
        batch_records = json.loads(result["stdout"])
        for record, path in zip(batch_records, batch):
            rel = str(path.relative_to(project))
            record["path"] = rel
            record["darwin_active"] = darwin_compatible(record.get("build_tags"), ignored=bool(record.get("ignored")))
            for site in record.get("interfaces") or []:
                site["path"] = rel
            for branch in record.get("branches") or []:
                branch["path"] = rel
            records.append(record)

    packages = {}
    for source in records:
        packages.setdefault(str(Path(source["path"]).parent), []).append(source)
    descriptions = settings["applications"] or [
        {"path": p} for p, sources in sorted(packages.items())
        if any(s.get("entrypoint") and s.get("darwin_active", True) for s in sources)
    ]
    apps = []
    for description in descriptions:
        entry = normalize_relative_path(description["path"], allow_root=True, allow_hidden=False, label="application path")
        pending, visited, sources = [entry], set(), []
        while pending:
            directory = pending.pop()
            if directory in visited:
                continue
            visited.add(directory)
            for source in packages.get(directory, []):
                if not source.get("darwin_active", True):
                    continue
                sources.append(source)
                for imported in source.get("imports") or []:
                    path = imported["path"]
                    if ":" in path:
                        collection, suffix = path.split(":", 1)
                        if collection not in settings["collections"]:
                            continue
                        imported_dir = project / settings["collections"][collection] / suffix
                    else:
                        imported_dir = project / directory / path
                    try:
                        pending.append(str(imported_dir.resolve().relative_to(project)))
                    except ValueError:
                        pass
        enums = {}
        structs = {}
        for s in sources:
            for et in s.get("enums") or []:
                if et.get("name") and et.get("variants"):
                    enums[et["name"]] = et["variants"]
            for ss in s.get("structs") or []:
                if ss.get("name") and ss.get("fields"):
                    structs[ss["name"]] = ss["fields"]
        app = {
            **description,
            "path": entry,
            "name": description.get("name") or entry,
            "id": digest(json.dumps(description, sort_keys=True).encode())[:16],
            "sources": [s["path"] for s in sources],
            "packages": sorted({s["package_name"] for s in sources if s.get("package_name")}),
            "writes_files": any(s.get("writes_files") for s in sources) or bool(description.get("files")),
            "interfaces": [i for s in sources for i in (s.get("interfaces") or [])],
            "branches": [b for s in sources for b in (s.get("branches") or [])],
            "enums": enums,
            "structs": structs,
            "literals": list(dict.fromkeys(v for s in sources for v in (s.get("literals") or []))),
            "env_names": sorted(set([*(v for s in sources for v in (s.get("env_names") or [])), *(description.get("env") or [])])),
            "filenames": sorted(set([*(v for s in sources for v in (s.get("filenames") or [])), *(description.get("files") or [])])),
        }
        app["inventory"] = interface_inventory(app)
        apps.append(app)
    return {
        "sources": records,
        "applications": apps,
        "excluded": excluded,
        "limitations": [
            "Syntax inventory can miss aliased, foreign, generated, and vendored input sources; it is not a complete call graph.",
            "UI, network, and IPC interfaces require a minimal replayable boundary adapter in odin-fuzz.json; live external dependencies remain out of scope by default.",
        ],
    }


def snapshot_tree(project, destination, exclude=None):
    """Capture bounded ordinary files without following links or copying live outputs."""
    excluded = set(exclude or ())
    size, count, omitted = 0, 0, []
    top_sizes = {}
    destination.mkdir(parents=True)
    for directory, subdirectories, files in os.walk(project, followlinks=False):
        kept = []
        for d in sorted(subdirectories):
            full = Path(directory) / d
            rel = str(full.relative_to(project))
            if d.startswith(".") or d in SNAPSHOT_EXCLUDED or rel in excluded or full.is_symlink():
                omitted.append(rel)
            else:
                kept.append(d)
        subdirectories[:] = kept
        for name in sorted(files):
            path = Path(directory) / name
            relative = path.relative_to(project)
            rel_str = str(relative)
            st = path.lstat()
            if name.startswith(".") or rel_str in excluded or not stat.S_ISREG(st.st_mode):
                omitted.append(rel_str)
                continue
            file_size = st.st_size
            size += file_size
            count += 1
            top = relative.parts[0]
            top_sizes[top] = top_sizes.get(top, 0) + file_size
            if size > MAX_SNAPSHOT_BYTES or count > MAX_SNAPSHOT_FILES:
                largest = max(top_sizes, key=top_sizes.get) if top_sizes else "unknown"
                raise ToolError(
                    f"project snapshot exceeds 64 MiB or 4096 files (largest top-level entry: {largest}); "
                    "pass --exclude or set exclude in odin-fuzz.json"
                )
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target, follow_symlinks=False)
    return omitted


def tree_manifest(root, *, include_dirs=True):
    """Hash all regular files (and optionally record directories), rejecting symlinks or special nodes."""
    root = Path(root)
    if not root.is_dir() or root.is_symlink():
        raise ToolError(f"captured initial directory is invalid: {root}")
    manifest = {}
    for directory, subdirectories, files in os.walk(root, followlinks=False):
        subdirectories.sort()
        files.sort()
        for name in subdirectories:
            full = Path(directory) / name
            rel = str(full.relative_to(root))
            st = full.lstat()
            if not stat.S_ISDIR(st.st_mode):
                raise ToolError(f"captured initial tree contains unsupported entry (symlink or special node): {rel}")
            if include_dirs:
                manifest[rel + "/"] = "dir"
        for name in files:
            full = Path(directory) / name
            rel = str(full.relative_to(root))
            st = full.lstat()
            if not stat.S_ISREG(st.st_mode):
                raise ToolError(f"captured initial tree contains unsupported entry (symlink or special node): {rel}")
            manifest[rel] = digest(full.read_bytes())
    return manifest


def first_party_pc_ranges(binary, packages, nm_path):
    """Build sorted [start, end) unslid PC intervals for first-party Odin packages via nm."""
    if not nm_path or not packages:
        return [], []
    pkg_prefixes = tuple(f"{pkg}::" for pkg in packages if pkg)
    if not pkg_prefixes:
        return [], []
    try:
        out = subprocess.check_output([nm_path, "-n", str(binary)], text=True, stderr=subprocess.DEVNULL, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return [], []
    text_syms = []
    for line in out.splitlines():
        parts = line.split(None, 2)
        if len(parts) != 3 or parts[1] not in {"T", "t"}:
            continue
        try:
            addr = int(parts[0], 16)
        except ValueError:
            continue
        sym = parts[2].lstrip("_")
        text_syms.append((addr, sym))
    ranges = []
    for i, (addr, sym) in enumerate(text_syms):
        if not sym.startswith(pkg_prefixes):
            continue
        next_addr = text_syms[i + 1][0] if i + 1 < len(text_syms) else addr + 0x10000
        end = max(addr + 1, min(next_addr, addr + 0x100000))
        if ranges and addr <= ranges[-1][1]:
            ranges[-1] = (ranges[-1][0], max(ranges[-1][1], end))
        else:
            ranges.append((addr, end))
    return [r[0] for r in ranges], ranges


def is_first_party_pc(pc, starts, ranges):
    if not ranges:
        return True
    idx = bisect.bisect_right(starts, pc) - 1
    return idx >= 0 and ranges[idx][0] <= pc < ranges[idx][1]


def read_coverage(cov_path, starts, ranges, *, workspace=None):
    """Parse one step's OFC2 coverage+CMP+string-CMP binary into first-party feedback."""
    empty = {"edges": set(), "guards": set(), "pcs": set(), "cmps": [], "str_cmps": []}
    fd = -1
    try:
        # Never follow target-created symlinks (including intermediate dirs like .tmp) or open FIFOs/devices.
        if workspace is not None:
            rel = Path(cov_path).relative_to(Path(workspace))
            cur_fd = os.open(workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                for part in rel.parts[:-1]:
                    next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=cur_fd)
                    os.close(cur_fd)
                    cur_fd = next_fd
                fd = os.open(rel.parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=cur_fd)
            finally:
                os.close(cur_fd)
        else:
            fd = os.open(cov_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except (OSError, ValueError):
        return empty
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_SOURCE_BYTES:
            return empty
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            data = handle.read(MAX_SOURCE_BYTES)
    except OSError:
        return empty
    finally:
        if fd >= 0:
            os.close(fd)
    if len(data) < 16 or data[:4] != COVERAGE_MAGIC:
        return empty
    edge_count, cmp_count, str_count = struct.unpack_from("<III", data, 4)
    offset = 16
    edges, guards, pcs = set(), set(), set()
    for _ in range(edge_count):
        if offset + 13 > len(data):
            break
        guard_id, pc, bucket = struct.unpack_from("<IQB", data, offset)
        offset += 13
        if is_first_party_pc(pc, starts, ranges):
            edges.add((guard_id, bucket))
            guards.add(guard_id)
            pcs.add(pc)
    cmps = []
    for _ in range(cmp_count):
        if offset + 26 > len(data):
            break
        pc, arg1, arg2, width, kind = struct.unpack_from("<QQQBB", data, offset)
        offset += 26
        if is_first_party_pc(pc, starts, ranges):
            cmps.append((pc, arg1, arg2, width, kind))
    str_cmps = []
    for _ in range(str_count):
        if offset + 2 > len(data):
            break
        a_len, b_len = data[offset], data[offset + 1]
        offset += 2
        if offset + a_len + b_len > len(data):
            break
        a_bytes = data[offset:offset + a_len]
        b_bytes = data[offset + a_len:offset + a_len + b_len]
        offset += a_len + b_len
        str_cmps.append((a_bytes, b_bytes))
    return {"edges": edges, "guards": guards, "pcs": pcs, "cmps": cmps, "str_cmps": str_cmps}


def _instrument_string_eq_ir(ll_path):
    """Hook runtime::string_eq in the emitted LLVM IR module to capture dynamic string comparisons."""
    try:
        text = ll_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    pattern = re.compile(
        r'(define\b[^\n]*@"runtime::string_eq"\(\[2 x i64\] (%\w+), \[2 x i64\] (%\w+)\)[^\n]*\{\n(?:[A-Za-z0-9_.$]+:\n)?)'
    )
    match = pattern.search(text)
    if not match:
        return
    p0, p1 = match.group(2), match.group(3)
    decl = "declare void @__odin_fuzz_trace_string_eq([2 x i64], [2 x i64])\n" if "@__odin_fuzz_trace_string_eq" not in text else ""
    call_line = f"  call void @__odin_fuzz_trace_string_eq([2 x i64] {p0}, [2 x i64] {p1})\n"
    patched = text[:match.start()] + decl + text[match.start():match.end()] + call_line + text[match.end():]
    ll_path.write_text(patched, encoding="utf-8")


def symbolize_pcs(binary, symbolizer, pcs, build_root):
    """Batch-resolve unslid return-address PCs to project-relative (path, line) pairs via llvm-symbolizer."""
    if not symbolizer or not pcs:
        return {}
    ordered = sorted(pcs)
    # Subtract 4 bytes on arm64/1 byte otherwise so return addresses map to the call instruction itself.
    step = 4 if os.uname().machine.lower() in {"arm64", "aarch64"} else 1
    stdin_text = "\n".join(f"0x{max(0, pc - step):x}" for pc in ordered) + "\n"
    try:
        proc = subprocess.run(
            [symbolizer, "-e", str(binary), "--no-inlines", "--functions=none"],
            input=stdin_text, text=True, capture_output=True, timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return {}
    if proc.returncode != 0:
        return {}
    prefix = str(Path(build_root).resolve()).rstrip("/") + "/"
    lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    resolved = {}
    for pc, raw in zip(ordered, lines):
        match = re.match(r"^(.+?):(\d+)(?::\d+)?$", raw)
        if not match:
            continue
        file_path, line_no = match.group(1), int(match.group(2))
        if line_no <= 0 or file_path == "??":
            continue
        if file_path.startswith(prefix):
            file_path = file_path[len(prefix):]
        resolved[pc] = (file_path, line_no)
    return resolved


def build_application(app, initial, chain, settings, directory):
    runtime = initial / RUNTIME
    runtime.mkdir()
    binary = runtime / "app"
    flags = [f"-collection:{name}={initial / path}" for name, path in settings["collections"].items()]
    coverage_mode = "none"

    if chain.get("clang"):
        ir_dir = directory / "ir"
        ir_dir.mkdir(parents=True, exist_ok=True)
        ir_res = run(
            [chain["odin"], "build", initial / app["path"], "-debug", "-sanitize:address",
             "-build-mode:llvm-ir", "-use-single-module", "-thread-count:2",
             f"-out:{ir_dir}", *flags, *settings["odin_flags"]],
            cwd=initial, timeout=BUILD_TIMEOUT, log=directory / "coverage-ir.log", fsize_limit=None,
        )
        ll_files = sorted(ir_dir.glob("*.ll")) if ir_res["returncode"] == 0 else []
        if ll_files:
            shim_c = ir_dir / "cov_shim.c"
            shim_c.write_text(COVERAGE_SHIM_C, encoding="utf-8")
            shim_o = ir_dir / "cov_shim.o"
            shim_res = run([chain["clang"], "-c", "-O2", str(shim_c), "-o", str(shim_o)],
                           cwd=ir_dir, timeout=BUILD_TIMEOUT, log=directory / "coverage-shim.log", fsize_limit=None)
            objs = []
            obj_ok = shim_res["returncode"] == 0
            for idx, ll in enumerate(ll_files):
                if not obj_ok:
                    break
                _instrument_string_eq_ir(ll)
                obj = ir_dir / f"mod-{idx}.o"
                o_res = run(
                    [chain["clang"], "-c", "-x", "ir", str(ll),
                     "-fsanitize-coverage=edge,trace-pc-guard,trace-cmp", "-Wno-override-module", "-o", str(obj)],
                    cwd=ir_dir, timeout=BUILD_TIMEOUT, log=directory / f"coverage-obj-{idx}.log", fsize_limit=None,
                )
                if o_res["returncode"] != 0:
                    obj_ok = False
                else:
                    objs.append(str(obj))
            if obj_ok:
                link_res = run(
                    [chain["clang"], *objs, str(shim_o), "-fsanitize=address", *settings["linker_flags"], "-o", str(binary)],
                    cwd=initial, timeout=BUILD_TIMEOUT, log=directory / "coverage-link.log", fsize_limit=None,
                )
                if link_res["returncode"] == 0 and binary.is_file():
                    dsymutil = chain.get("dsymutil") or shutil.which("dsymutil")
                    if dsymutil:
                        run([dsymutil, str(binary)], cwd=initial, timeout=BUILD_TIMEOUT,
                            log=directory / "coverage-dsym.log", fsize_limit=None)
                    coverage_mode = "llvm_sancov"
        safe_rmtree(ir_dir)

    if coverage_mode == "none":
        fallback_flags = list(flags)
        if settings["linker_flags"]:
            fallback_flags.append("-extra-linker-flags:" + shlex.join(settings["linker_flags"]))
        result = run([chain["odin"], "build", initial / app["path"], "-debug", "-sanitize:address", "-thread-count:2",
                      f"-out:{binary}", *fallback_flags, *settings["odin_flags"]], cwd=initial,
                     timeout=BUILD_TIMEOUT, log=directory / "build.log", fsize_limit=None)
        if result["returncode"]:
            raise ToolError(f"application build failed; see {result['stderr_log']}")

    os.chmod(binary, 0o555)
    starts, ranges = first_party_pc_ranges(binary, app.get("packages") or [], chain.get("nm")) if coverage_mode == "llvm_sancov" else ([], [])
    return {"binary": binary, "coverage_mode": coverage_mode, "pc_starts": starts, "pc_ranges": ranges}


def seatbelt_quote(path):
    """Emit a UTF-8 Seatbelt string literal without ASCII \\uXXXX escapes."""
    text = str(Path(path).resolve())
    if "\0" in text or "\n" in text or "\r" in text:
        raise ToolError(f"unsupported control character in sandbox path: {text!r}")
    return json.dumps(text, ensure_ascii=False)


def sandbox_profile(workspace, *, runtime_dir=None, tcp_port=None, unix_socket_dir=None):
    if sys.platform != "darwin" or not Path("/usr/bin/sandbox-exec").is_file():
        raise ToolError("application execution requires macOS sandbox-exec")
    # Deny external network, external writes, and reading file data outside the
    # disposable workspace, read-only runtime dir, and system runtime directories.
    # file-read-metadata stays permitted so dyld and getcwd/realpath can resolve ancestor paths.
    trusted = [
        "/System", "/usr", "/bin", "/sbin", "/Library", "/opt/homebrew", "/nix/store",
        "/dev", "/private/var/db", "/private/var/run", "/private/etc",
    ]
    read_paths = [workspace, *trusted]
    if runtime_dir is not None:
        read_paths.append(runtime_dir)
    read_rules = [f"(subpath {seatbelt_quote(path)})" for path in read_paths]
    read_rules.append('(literal "/")')
    write_rules = [f"(subpath {seatbelt_quote(workspace)})", '(literal "/dev/null")']
    net_allows = []
    if tcp_port is not None:
        net_allows.extend([
            f'(allow network-outbound (remote ip "localhost:{tcp_port}"))',
            f'(allow network-inbound (local ip "localhost:{tcp_port}"))',
            f'(allow network-bind (local ip "localhost:{tcp_port}"))',
        ])
    if unix_socket_dir is not None:
        sock_dir_q = seatbelt_quote(unix_socket_dir)
        read_rules.append(f"(subpath {sock_dir_q})")
        write_rules.append(f"(subpath {sock_dir_q})")
        net_allows.extend([
            f"(allow network* (remote unix-socket (subpath {sock_dir_q})))",
            f"(allow network* (local unix-socket (subpath {sock_dir_q})))",
        ])
    lines = [
        "(version 1)",
        "(allow default)",
        "(deny network*)",
        *net_allows,
        "(deny signal)",
        "(allow signal (target same-sandbox))",
        f"(deny file-read-data (require-not (require-any {' '.join(read_rules)})))",
        f"(deny file-read-xattr (require-not (require-any {' '.join(read_rules)})))",
        f"(deny file-write* (require-not (require-any {' '.join(write_rules)})))",
    ]
    return "\n".join(lines) + "\n"


def normalize_site(site, *, build_root=None, workspace_root=None):
    """Strip exact build/workspace prefixes and hex addresses while keeping sanitizer bug classes."""
    text = site.strip()
    for root in (build_root, workspace_root):
        if root:
            prefix = str(Path(root)).rstrip("/") + "/"
            text = text.replace(prefix, "")
    if not build_root:
        # Legacy fallback for v2 bundles recorded without build_root.
        text = re.sub(r"/\S*/applications/[0-9a-f]{16}/initial/", "", text)
    return re.sub(r"0x[0-9a-fA-F]+", "<address>", text).strip()


def failure_identity(result, *, build_root=None, workspace_root=None):
    """Only fatal runtime evidence, never arbitrary output or ordinary rejection."""
    if result["timed_out"] or result["returncode"] == 0:
        return None
    rc = result["returncode"]
    is_fatal_signal = rc < 0 and -rc in FATAL_SIGNALS
    stderr = result["stderr"]
    asan = re.search(r"(?m)^SUMMARY: AddressSanitizer: (.+)$", stderr)
    if asan and re.search(r"(?m)^==\d+==ERROR: AddressSanitizer:", stderr) and (rc == SANITIZER_EXIT_CODE or is_fatal_signal):
        return {"kind": "address_sanitizer", "site": normalize_site(asan.group(1), build_root=build_root, workspace_root=workspace_root)}
    ubsan = re.search(r"(?m)^SUMMARY: UndefinedBehaviorSanitizer: (.+)$", stderr)
    if ubsan and (rc == SANITIZER_EXIT_CODE or is_fatal_signal):
        return {"kind": "undefined_behavior_sanitizer", "site": normalize_site(ubsan.group(1), build_root=build_root, workspace_root=workspace_root)}
    if not is_fatal_signal:
        return None
    runtime = ODIN_FAILURE_RE.search(stderr)
    if runtime:
        kind = runtime.group(2).lower()
        if kind.startswith("index "):
            kind = "bounds check failed"
        return {"kind": kind, "site": normalize_site(runtime.group(1), build_root=build_root, workspace_root=workspace_root)}
    # A raw signal without a stable diagnostic site remains unconfirmed.
    return None


def encode(data):
    return base64.b64encode(data).decode("ascii")


def decode(data):
    if not isinstance(data, str):
        raise ToolError("recorded base64 field must be a string")
    return base64.b64decode(data, validate=True)


def validate_step(step):
    allowed = {
        "argv", "stdin", "files", "delete_files", "environment",
        "ui_events", "network_messages", "ipc_messages", "seed", "clock",
    }
    required = {"argv", "stdin", "files", "environment"}
    if not isinstance(step, dict) or not required.issubset(step) or set(step) - allowed:
        raise ToolError("invalid recorded input step")
    if not isinstance(step["argv"], list) or any(not isinstance(v, str) or "\0" in v for v in step["argv"]):
        raise ToolError("recorded argv must contain strings without NUL")
    if not isinstance(step["environment"], dict) or any(
            not isinstance(k, str) or not isinstance(v, str) or not k or "=" in k or "\0" in k + v
            for k, v in step["environment"].items()):
        raise ToolError("invalid recorded environment")
    if any(k.startswith(RESERVED_ENV_PREFIXES) for k in step["environment"]):
        raise ToolError("instrumentation environment cannot be mutated")
    decode(step["stdin"])
    if not isinstance(step["files"], dict):
        raise ToolError("recorded files must be an object")
    normalized_files = {}
    for filename, contents in step["files"].items():
        norm = normalize_relative_path(filename, allow_root=False, allow_hidden=False, label="recorded file path")
        decode(contents)
        normalized_files[norm] = contents
    step["files"] = normalized_files
    if "delete_files" in step:
        if not isinstance(step["delete_files"], list):
            raise ToolError("recorded delete_files must be a list")
        step["delete_files"] = [
            normalize_relative_path(filename, allow_root=False, allow_hidden=False, label="recorded delete_files path")
            for filename in step["delete_files"]
        ]
    if "ui_events" in step and step["ui_events"] is not None:
        if not isinstance(step["ui_events"], list) or len(step["ui_events"]) > MAX_UI_FRAMES:
            raise ToolError("invalid recorded ui_events")
    for key in ("network_messages", "ipc_messages"):
        if key in step and step[key] is not None:
            if not isinstance(step[key], list):
                raise ToolError(f"recorded {key} must be a list of base64 messages")
            for chunk in step[key]:
                decode(chunk)
    for key in ("seed", "clock"):
        if key in step and step[key] is not None and not is_strict_int(step[key]):
            raise ToolError(f"recorded {key} must be an integer")


def normalize_case(case):
    """Support v3 multi-step cases and v2 single-step cases."""
    if not isinstance(case, dict):
        raise ToolError("recorded case must be an object")
    if "steps" in case:
        if set(case) != {"steps"} or not isinstance(case["steps"], list) or not 1 <= len(case["steps"]) <= MAX_STEPS:
            raise ToolError("recorded multi-step case is invalid")
        for step in case["steps"]:
            validate_step(step)
        return case
    validate_step(case)
    return {"steps": [case]}


def deliver_socket_messages(sock_obj, messages):
    """Deliver recorded byte chunks cleanly over an accepted/connected local socket."""
    try:
        sock_obj.settimeout(0.02)
        for chunk in messages:
            if chunk:
                sock_obj.sendall(chunk)
            try:
                sock_obj.recv(4096)
            except (TimeoutError, socket.timeout, BlockingIOError):
                pass
        try:
            sock_obj.shutdown(socket.SHUT_WR)
        except OSError:
            pass
    except OSError:
        pass
    finally:
        try:
            sock_obj.close()
        except OSError:
            pass


@contextmanager
def _socket_endpoint(role, decoded, timeout, *, bind_server=None, connect_client=None):
    """Run one background server accept loop or client connect loop for a local fixture."""
    stop = threading.Event()
    server = None
    if role == "server":
        server = bind_server()
        server.listen(4)
        server.settimeout(0.1)

        def worker():
            deadline = time.monotonic() + timeout + 0.5
            while not stop.is_set() and time.monotonic() < deadline:
                try:
                    conn, _ = server.accept()
                except (TimeoutError, socket.timeout):
                    continue
                except OSError:
                    break
                deliver_socket_messages(conn, decoded)
    else:
        def worker():
            deadline = time.monotonic() + timeout
            while not stop.is_set() and time.monotonic() < deadline:
                conn = connect_client()
                if conn is None:
                    time.sleep(0.02)
                    continue
                deliver_socket_messages(conn, decoded)
                return

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        stop.set()
        if server is not None:
            try:
                server.close()
            except OSError:
                pass
        thread.join(timeout=1.0)


@contextmanager
def local_network_fixture(config, messages, timeout):
    """Run a disposable 127.0.0.1 TCP endpoint for one step; never touches external hosts."""
    if not config:
        yield None
        return
    role = config.get("role", "server")
    decoded = [decode(m) for m in (messages or [])]
    if role == "server":
        port_box = []

        def bind_server():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", 0))
            port_box.append(s.getsockname()[1])
            return s

        with _socket_endpoint("server", decoded, timeout, bind_server=bind_server):
            yield port_box[0]
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]

        def connect_client():
            try:
                return socket.create_connection(("127.0.0.1", port), timeout=0.2)
            except OSError:
                return None

        with _socket_endpoint("client", decoded, timeout, connect_client=connect_client):
            yield port


@contextmanager
def local_ipc_fixture(config, scratch, messages, timeout):
    """Run a disposable local Unix domain socket endpoint outside the immutable runtime dir."""
    if not config:
        yield None, None
        return
    role = config.get("role", "server")
    decoded = [decode(m) for m in (messages or [])]
    ipc_dir = (Path(scratch).resolve() / "ipc")
    candidate = ipc_dir / "s"
    temp_dir = None
    # macOS sockaddr_un.sun_path is limited to 104 UTF-8 bytes; fall back to a short private temp dir.
    if len(os.fsencode(str(candidate))) <= MAX_UNIX_SOCKET_BYTES:
        # A previous step may have replaced the entire adapter directory.
        safe_rmtree(ipc_dir)
        ipc_dir.mkdir(mode=0o700, parents=True)
        sock_path = candidate
        sock_dir = ipc_dir
    else:
        temp_dir = Path(tempfile.mkdtemp(prefix="ofz-"))
        os.chmod(temp_dir, 0o700)
        sock_path = temp_dir / "s"
        sock_dir = temp_dir
    if sock_path.exists() or sock_path.is_symlink():
        safe_rmtree(sock_path)

    def bind_server():
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(str(sock_path))
        return s

    def connect_client():
        try:
            if sock_dir.is_symlink():
                return None
            st = os.lstat(sock_path)
        except OSError:
            return None
        if not stat.S_ISSOCK(st.st_mode):
            return None
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.settimeout(0.2)
            s.connect(str(sock_path))
            return s
        except OSError:
            s.close()
            return None

    try:
        with _socket_endpoint(role, decoded, timeout, bind_server=bind_server, connect_client=connect_client):
            yield str(sock_path), sock_dir
    finally:
        sock_dir_fd = -1
        try:
            # The target can replace sock_dir itself; never traverse it by path during cleanup.
            sock_dir_fd = os.open(sock_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            os.fchmod(sock_dir_fd, 0o700)
            _safe_rmtree_fd(sock_dir_fd, sock_path.name)
        except OSError:
            pass
        finally:
            if sock_dir_fd >= 0:
                os.close(sock_dir_fd)
        if temp_dir and (temp_dir.exists() or temp_dir.is_symlink()):
            safe_rmtree(temp_dir)


def serialize_ui_events(events, fmt):
    if fmt == "jsonl":
        return ("\n".join(json.dumps(e, separators=(",", ":")) for e in events) + "\n").encode("utf-8")
    return (json.dumps(events, separators=(",", ":")) + "\n").encode("utf-8")


def execute_case(initial, case, scratch, environment, timeout, app_config=None, *,
                 initial_files=None, track_created=True, build_root=None,
                 collect_coverage=False, pc_starts=None, pc_ranges=None):
    """Execute an ordered 1..N step sequence on one fresh disposable copy of initial."""
    normalized = normalize_case(case)
    app_config = app_config or {}
    initial_raw = Path(initial)
    if initial_raw.is_symlink():
        raise WorkspaceError(f"refusing symlink initial directory: {initial_raw}")
    initial = initial_raw.parent.resolve() / initial_raw.name
    if initial.is_symlink():
        raise WorkspaceError(f"refusing symlink initial directory: {initial}")
    scratch_raw = Path(scratch)
    if scratch_raw.is_symlink():
        raise WorkspaceError(f"refusing symlink scratch directory: {scratch_raw}")
    scratch = scratch_raw.parent.resolve() / scratch_raw.name
    if scratch.is_symlink():
        raise WorkspaceError(f"refusing symlink scratch directory: {scratch}")
    try:
        if scratch.exists():
            safe_rmtree(scratch)
        scratch.mkdir(parents=True)
    except OSError as error:
        raise WorkspaceError(f"cannot prepare scratch directory: {error}") from error
    workspace = scratch / "workspace"
    try:
        clone_workspace(initial, workspace)
        (workspace / ".home").mkdir(exist_ok=True)
        (workspace / ".tmp").mkdir(exist_ok=True)
    except OSError as error:
        raise WorkspaceError(f"cannot clone disposable workspace: {error}") from error
    before_files = initial_files if initial_files is not None else (workspace_files(workspace) if track_created else set())
    runtime_dir = initial / RUNTIME
    app_binary = runtime_dir / "app"
    effective_build_root = build_root or str(initial)

    step_results = []
    final_result = None
    failing_step = None
    final_identity = None
    cov_edges, cov_guards, cov_pcs, cov_cmps, cov_str_cmps = set(), set(), set(), [], []

    for idx, step in enumerate(normalized["steps"]):
        for filename in step.get("delete_files", []):
            safe_workspace_delete(workspace, filename)
        for filename, contents in step["files"].items():
            safe_workspace_write(workspace, filename, decode(contents))

        stdin_bytes = decode(step["stdin"])
        events_rel = None
        ui_cfg = app_config.get("ui_events")
        if ui_cfg and step.get("ui_events") is not None:
            payload = serialize_ui_events(step["ui_events"], ui_cfg.get("format", "json"))
            mode = ui_cfg.get("mode", "file")
            if mode == "stdin":
                stdin_bytes = payload
            else:
                events_rel = ui_cfg.get("path", "events.json")
                safe_workspace_write(workspace, events_rel, payload)

        stdin_path = scratch / f"step-{idx}-stdin.bin"
        stdin_path.write_bytes(stdin_bytes)

        with local_network_fixture(app_config.get("local_network"), step.get("network_messages"), timeout) as tcp_port, \
             local_ipc_fixture(app_config.get("local_ipc"), scratch, step.get("ipc_messages"), timeout) as (sock_path, sock_dir):
            env = {
                **environment,
                **step["environment"],
                "HOME": str(workspace / ".home"),
                "TMPDIR": str(workspace / ".tmp") + "/",
            }
            cov_file = None
            if collect_coverage:
                cov_file = workspace / ".tmp" / f"cov-{idx}.bin"
                env["ODIN_FUZZ_COV_FILE"] = str(cov_file)
            if ui_cfg and events_rel and ui_cfg.get("mode") == "env":
                env[ui_cfg.get("env", "ODIN_FUZZ_EVENTS")] = str(workspace / events_rel)
            if tcp_port is not None:
                net_cfg = app_config["local_network"]
                if "port_env" in net_cfg or not any("{port}" in a for a in step["argv"]):
                    env[net_cfg.get("port_env", "ODIN_FUZZ_PORT")] = str(tcp_port)
                if "host_env" in net_cfg:
                    env[net_cfg["host_env"]] = "127.0.0.1"
            if sock_path is not None:
                ipc_cfg = app_config["local_ipc"]
                if "socket_env" in ipc_cfg or not any("{socket}" in a for a in step["argv"]):
                    env[ipc_cfg.get("socket_env", "ODIN_FUZZ_SOCKET")] = sock_path
            if step.get("seed") is not None and app_config.get("seed_env"):
                env[app_config["seed_env"]] = str(step["seed"])
            if step.get("clock") is not None and app_config.get("clock_env"):
                env[app_config["clock_env"]] = str(step["clock"])

            subs = {
                "{events}": events_rel,
                "{port}": str(tcp_port) if tcp_port is not None else None,
                "{socket}": sock_path,
                "{seed}": str(step["seed"]) if step.get("seed") is not None else None,
                "{time}": str(step["clock"]) if step.get("clock") is not None else None,
            }
            argv = []
            for arg in step["argv"]:
                for placeholder, replacement in subs.items():
                    if replacement is not None:
                        arg = arg.replace(placeholder, replacement)
                argv.append(arg)

            profile = sandbox_profile(workspace, runtime_dir=runtime_dir, tcp_port=tcp_port, unix_socket_dir=sock_dir)
            result = run([app_binary, *argv], cwd=workspace,
                         timeout=timeout, log=scratch / f"step-{idx}.stdout", env=env, stdin=stdin_path,
                         sandbox=profile)
            step_results.append(result)
            final_result = result
            if cov_file is not None:
                step_cov = read_coverage(cov_file, pc_starts or [], pc_ranges or [], workspace=workspace)
                cov_edges.update(step_cov["edges"])
                cov_guards.update(step_cov["guards"])
                cov_pcs.update(step_cov["pcs"])
                if len(cov_cmps) < 512:
                    cov_cmps.extend(step_cov["cmps"][:512 - len(cov_cmps)])
                if len(cov_str_cmps) < 256:
                    cov_str_cmps.extend(step_cov["str_cmps"][:256 - len(cov_str_cmps)])
            identity = failure_identity(result, build_root=effective_build_root, workspace_root=str(workspace))
            if identity:
                failing_step = idx
                final_identity = identity
                break
            if result["timed_out"]:
                break

    created_files = sorted(workspace_files(workspace) - before_files) if track_created else []
    return {
        "steps": step_results,
        "final": final_result,
        "failing_step": failing_step,
        "identity": final_identity,
        "created_files": created_files,
        "coverage": {"edges": cov_edges, "guards": cov_guards, "pcs": cov_pcs, "cmps": cov_cmps, "str_cmps": cov_str_cmps} if collect_coverage else None,
        "timed_out": any(r["timed_out"] for r in step_results),
        "returncode": final_result["returncode"] if final_result else 0,
        "stdout": final_result["stdout"] if final_result else "",
        "stderr": final_result["stderr"] if final_result else "",
    }


def build_app_context(app, initial):
    """Collect per-application seeds, snapshots, schemas, and sanitized interface lists in one pass."""
    values = [
        b"", b"0", b"1", b"-1", b"2", b"255", b"2147483647", b"-2147483648", b"4294967295",
        b"{}", b"[]", b"null", b"true", b"false", b"\n", b"\x00\x01\x02\x03",
        bytes(16), bytes([255]) * 16, b"A" * 128,
    ]
    for lit in app["literals"]:
        if lit and len(lit) <= 128 and "\0" not in lit:
            values.append(lit.encode("utf-8"))
    existing_bytes = {}
    for path in sorted(initial.rglob("*")):
        try:
            st = path.lstat()
        except OSError:
            continue
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_INPUT:
            continue
        rel = path.relative_to(initial)
        if any(part.startswith(".") for part in rel.parts):
            continue
        raw = path.read_bytes()
        if len(existing_bytes) < 32:
            existing_bytes[str(rel)] = raw
        if len(values) < 192 and path.suffix in {".json", ".txt", ".csv", ".cbor", ".odin", ".ini", ".toml"}:
            values.append(raw)
        if len(existing_bytes) >= 32 and len(values) >= 192:
            break
    payloads = list(dict.fromkeys(v[:MAX_INPUT] for v in values))[:256]
    base_filenames = list(dict.fromkeys([
        *(n for n in (_eligible_candidate_file(initial, f) for f in app["filenames"]) if n is not None),
        "input", "input.json", "input.odin",
    ]))[:24]
    env_names = [
        v for v in app["env_names"]
        if IDENT_RE.fullmatch(v) and not v.startswith(RESERVED_ENV_PREFIXES)
    ][:16]
    return {
        "app": app,
        "kinds": {i["kind"] for i in app["interfaces"]},
        "adapters": enabled_adapters(app),
        "payloads": payloads,
        "existing_bytes": existing_bytes,
        "literals": app["literals"],
        "schemas": {"enums": app.get("enums") or {}, "structs": app.get("structs") or {}},
        "env_names": env_names,
        "base_filenames": base_filenames,
        "dynamic_files": set(),
        "dynamic_strings": [],
    }


def mutate_bytes(rng, payloads, base=None):
    data = bytearray(base if base is not None else rng.choice(payloads))
    for _ in range(rng.randint(1, 4)):
        choice = rng.randrange(5)
        if choice == 0:
            offset = rng.randrange(len(data) + 1)
            data[offset:offset] = bytes([rng.randrange(256)])
        elif choice == 1 and data:
            offset = rng.randrange(len(data))
            data[offset] ^= 1 << rng.randrange(8)
        elif choice == 2:
            offset = rng.randrange(len(data) + 1)
            splice = rng.choice(payloads)[:64]
            data[offset:offset + 1] = splice
        elif choice == 3 and data:
            start = rng.randrange(len(data))
            end = min(len(data), start + rng.randint(1, 16))
            del data[start:end]
        else:
            data.extend(rng.choice([b"\n", b" ", b",", b"}", b"]", b"\xff" * 4]))
    return bytes(data[:MAX_INPUT])


def _synth_schema_value(rng, type_name, enums, structs, words, nums, depth=0):
    t = (type_name or "").strip()
    if t.startswith("[]"):
        if depth >= 2:
            return []
        elem = t[2:]
        return [_synth_schema_value(rng, elem, enums, structs, words, nums, depth + 1) for _ in range(rng.randint(0, 3))]
    if t in enums and enums[t]:
        return rng.choice(enums[t])
    if t in structs and depth < 2:
        return _synth_schema_struct(rng, structs[t], enums, structs, words, nums, depth + 1)
    if t in {"bool", "b8", "b16", "b32", "b64"}:
        return rng.choice([True, False])
    if t in {"int", "i8", "i16", "i32", "i64", "uint", "u8", "u16", "u32", "u64", "uintptr"}:
        return rng.choice(nums) if not t.startswith("u") else abs(rng.choice(nums))
    if t in {"f16", "f32", "f64"}:
        return rng.choice([0.0, 1.0, -1.0, 0.5, 10.0, -50.0, round(rng.uniform(-100.0, 100.0), 2)])
    if t in {"string", "cstring"}:
        return rng.choice(words)
    return rng.choice([rng.choice(nums), rng.choice(words), True, False])


def _synth_schema_struct(rng, fields, enums, structs, words, nums, depth=0):
    named = [f for f in fields[:16] if f.get("name")]
    obj = {}
    for f in named:
        fname, ftype = f["name"], f.get("type_name", "")
        # Always populate enum/kind fields; optionally populate others for realistic partial JSON.
        if ftype in enums or fname in {"kind", "type", "action", "op", "command"} or rng.random() < 0.65:
            obj[fname] = _synth_schema_value(rng, ftype, enums, structs, words, nums, depth)
    if not obj and named:
        f = named[0]
        obj[f["name"]] = _synth_schema_value(rng, f.get("type_name", ""), enums, structs, words, nums, depth)
    return obj


def structured_json_payload(rng, literals, schemas=None):
    """Build schema-guided or generic valid/malformed JSON objects/arrays."""
    nums = [0, 1, -1, 2, 3, 7, 42, 255, 1024, -999999, 2147483647, -2147483648]
    enums = (schemas or {}).get("enums") or {}
    structs = (schemas or {}).get("structs") or {}
    enum_words = [v for variants in enums.values() for v in variants]
    words = list(dict.fromkeys([*enum_words, *(v for v in literals if len(v) <= 48 and "\n" not in v)])) or ["init", "start", "step", "load", "save", "end"]

    if structs and rng.random() < 0.75:
        # Prefer command/event/request-like structs (especially those with enum fields).
        weighted = []
        for sname, fields in structs.items():
            w = 1.0
            if any(f.get("type_name") in enums for f in fields):
                w += 3.0
            if any(f.get("name") in {"kind", "type", "action", "command", "op"} for f in fields):
                w += 3.0
            if any(k in sname.lower() for k in ("cmd", "command", "req", "request", "event", "msg", "input", "action")):
                w += 3.0
            weighted.append((sname, fields, w))
        chosen_name, chosen_fields, _ = rng.choices(weighted, weights=[x[2] for x in weighted], k=1)[0]
        if rng.random() < 0.65:
            items = [_synth_schema_struct(rng, chosen_fields, enums, structs, words, nums, 0) for _ in range(rng.randint(1, 5))]
            raw = json.dumps(items).encode("utf-8")
        else:
            obj = _synth_schema_struct(rng, chosen_fields, enums, structs, words, nums, 0)
            raw = json.dumps(obj).encode("utf-8")
        if rng.random() < 0.12 and len(raw) > 2:
            raw = raw[:rng.randrange(1, len(raw))]
        return raw[:MAX_INPUT]

    def rand_val():
        pick = rng.randrange(6)
        if pick == 0:
            return rng.choice(words)
        if pick == 1:
            return rng.choice(nums)
        if pick == 2:
            return rng.choice([True, False, None])
        if pick == 3:
            return round(rng.uniform(-1000.0, 1000.0), 3)
        if pick == 4:
            return [rng.choice(nums), rng.choice(words)]
        return {rng.choice(words): rng.choice(nums)}

    if rng.random() < 0.65:
        count = rng.randint(1, 4)
        items = []
        for _ in range(count):
            obj = {"kind": rng.choice(words), "i": rng.choice(nums), "j": rng.choice(nums)}
            if rng.random() < 0.5:
                obj[rng.choice(words)] = rand_val()
            items.append(obj)
        raw = json.dumps(items).encode("utf-8")
    else:
        obj = {rng.choice(words): rand_val() for _ in range(rng.randint(1, 4))}
        raw = json.dumps(obj).encode("utf-8")
    if rng.random() < 0.2 and len(raw) > 2:
        raw = raw[:rng.randrange(1, len(raw))]
    return raw[:MAX_INPUT]


def generate_ui_events(rng, ui_cfg, index):
    keys = ui_cfg.get("keys") or DEFAULT_UI_KEYS
    max_frames = ui_cfg.get("max_frames", 32)
    if index == 0:
        return [{"frame": 0, "dt": 0.016, "keys_down": [], "keys_pressed": [], "close": True}]
    frame_count = 1 if max_frames <= 1 else rng.randint(2, min(max_frames, 12 if index < 32 else 24))
    events = []
    width, height = rng.choice([(800, 600), (1280, 720), (320, 240), (0, 0), (1920, 1080)])
    held = set()
    for frame in range(frame_count):
        pressed = []
        if rng.random() < 0.7:
            k = rng.choice(keys)
            pressed.append(k)
            if rng.random() < 0.5:
                held.add(k)
        if held and rng.random() < 0.35:
            held.discard(rng.choice(sorted(held)))
        if rng.random() < 0.15:
            width, height = rng.choice([(800, 600), (1280, 720), (1, 1), (0, 0), (4096, 2160)])
        event = {
            "frame": frame,
            "dt": rng.choice([0.016, 0.033, 0.0, 0.1, 1.0]),
            "keys_down": sorted(held),
            "keys_pressed": pressed,
            "mouse": {
                "x": rng.randint(-10, max(10, width + 10)),
                "y": rng.randint(-10, max(10, height + 10)),
                "left": rng.random() < 0.35,
                "right": rng.random() < 0.15,
                "wheel": rng.choice([0.0, -1.0, 1.0, -12.0, 12.0]),
            },
            "viewport": [width, height],
            "close": frame == frame_count - 1 and rng.random() < 0.85,
        }
        events.append(event)
    return events


def payload_for_name(rng, name, payloads, literals, existing_bytes, schemas=None):
    if name in existing_bytes and rng.random() < 0.45:
        return mutate_bytes(rng, payloads, base=existing_bytes[name])
    if name.endswith(".json") and rng.random() < 0.70:
        return structured_json_payload(rng, literals, schemas=schemas)
    if rng.random() < 0.45:
        return rng.choice(payloads)
    return mutate_bytes(rng, payloads)


def _step_messages(rng, force_data, payloads, literals, schemas=None):
    if force_data is not None:
        return [encode(force_data)]
    return [
        encode(structured_json_payload(rng, literals, schemas=schemas) if rng.random() < 0.35 else mutate_bytes(rng, payloads))
        for _ in range(rng.randint(1, 4))
    ]


def _eligible_candidate_file(initial, raw_name):
    try:
        norm = normalize_relative_path(raw_name, allow_root=False, allow_hidden=False, label="candidate file")
    except ToolError:
        return None
    target = initial / norm
    if target.is_dir():
        return None
    for parent in Path(norm).parents:
        if parent != Path(".") and (initial / parent).is_file():
            return None
    return norm


def input_cases(ctx, seed):
    rng = random.Random(seed)
    app = ctx["app"]
    kinds, adapters = ctx["kinds"], ctx["adapters"]
    payloads, existing_bytes = ctx["payloads"], ctx["existing_bytes"]
    literals, schemas = ctx["literals"], ctx["schemas"]
    env_names, base_filenames = ctx["env_names"], ctx["base_filenames"]
    dynamic_files = ctx["dynamic_files"]
    default_file = base_filenames[0]
    default_file2 = base_filenames[1] if len(base_filenames) > 1 else base_filenames[0]

    flags = [v for v in literals if re.fullmatch(r"--?[A-Za-z][\w-]*", v)][:24]
    templates = [[]]
    if "args" in app:
        templates = [app["args"]]
    elif "argv" in kinds:
        templates += [["{file}"], ["{text}"], ["{file}", "{file2}"], ["src"], ["input.odin"]]
        for flag in flags:
            templates.extend([[flag], [flag, "{file}"], [flag, "{text}"], [flag, "{text}", "{file}"]])
    has_files = "files" in kinds or bool(app.get("files")) or any("{file" in a for t in templates for a in t)
    has_stdin = "stdin" in kinds
    has_ui, has_net, has_ipc = "ui" in adapters, "network" in adapters, "ipc" in adapters
    has_seed, has_clock = "randomness" in adapters, "clock" in adapters

    def make_step(step_idx, template, force_data=None, allow_empty_files=False):
        all_candidates = list(dict.fromkeys([*base_filenames, *sorted(dynamic_files)]))[:32]
        primary_file = rng.choice(all_candidates) if step_idx > 0 or force_data is None else default_file
        secondary_file = rng.choice(all_candidates) if len(all_candidates) > 1 else default_file2
        data = force_data if force_data is not None else (
            payloads[step_idx] if step_idx < len(payloads) else mutate_bytes(rng, payloads)
        )
        text = data.decode("utf-8", errors="replace").replace("\0", "")[:256]

        files = {}
        if has_files and not allow_empty_files:
            chosen = []
            if any("{file}" in a for a in template):
                chosen.append(primary_file)
            if any("{file2}" in a for a in template) and secondary_file not in chosen:
                chosen.append(secondary_file)
            extra_count = rng.randint(0 if chosen else 1, 2)
            for _ in range(extra_count):
                cand = rng.choice(all_candidates)
                if cand not in chosen:
                    chosen.append(cand)
            for fname in chosen:
                fbytes = force_data if (force_data is not None and fname == chosen[0]) else payload_for_name(rng, fname, payloads, literals, existing_bytes, schemas=schemas)
                files[fname] = encode(fbytes)

        stdin_bytes = b""
        if has_stdin:
            if force_data is not None:
                stdin_bytes = force_data
            elif rng.random() < 0.35:
                lines = [rng.choice(payloads).decode("utf-8", errors="replace").replace("\0", "") for _ in range(rng.randint(1, 5))]
                stdin_bytes = ("\n".join(lines) + "\n").encode("utf-8")[:MAX_INPUT]
            elif rng.random() < 0.40:
                stdin_bytes = structured_json_payload(rng, literals, schemas=schemas)
            else:
                stdin_bytes = mutate_bytes(rng, payloads)

        env = {}
        if env_names:
            mode = rng.randrange(3)
            chosen_env = [rng.choice(env_names)] if mode == 1 else rng.sample(env_names, k=min(len(env_names), rng.randint(1, 3))) if mode == 2 else []
            for name in chosen_env:
                env[name] = mutate_bytes(rng, payloads).decode("utf-8", errors="replace").replace("\0", "")[:128]

        argv = [
            a.replace("{file}", primary_file).replace("{file2}", secondary_file).replace("{text}", text)
            for a in template
        ]
        step = {"argv": argv, "stdin": encode(stdin_bytes), "files": files, "environment": env}
        if has_ui:
            step["ui_events"] = generate_ui_events(rng, app["ui_events"], step_idx)
        if has_net:
            step["network_messages"] = _step_messages(rng, force_data, payloads, literals, schemas=schemas)
        if has_ipc:
            step["ipc_messages"] = _step_messages(rng, force_data, payloads, literals, schemas=schemas)
        if has_seed:
            seed_choices = [0, 1, 42, -1, 2147483647, rng.randint(0, 2**31 - 1)]
            step["seed"] = seed_choices[step_idx % len(seed_choices)] if step_idx < len(seed_choices) else rng.randint(0, 2**31 - 1)
        if has_clock:
            clock_choices = [0, 1, 1700000000, 2147483647, rng.randint(0, 2**31 - 1)]
            step["clock"] = clock_choices[step_idx % len(clock_choices)] if step_idx < len(clock_choices) else rng.randint(0, 2**31 - 1)
        return step

    # Case 0: untouched captured snapshot baseline (catches genuine startup failures).
    yield {"steps": [make_step(0, templates[0], force_data=b"", allow_empty_files=True)]}

    index = 0
    while True:
        multi_step_chance = 0.45 if (app.get("writes_files") or dynamic_files) else 0.25
        if index >= 2 and rng.random() < multi_step_chance:
            step_count = rng.randint(2, 3)
            steps = []
            for s in range(step_count):
                tpl = rng.choice(templates)
                step = make_step(index + s, tpl)
                if s > 0 and rng.random() < 0.55:
                    step["files"] = {}
                elif s > 0 and dynamic_files and rng.random() < 0.4:
                    target = rng.choice(sorted(dynamic_files))
                    step["files"] = {target: encode(payload_for_name(rng, target, payloads, literals, existing_bytes, schemas=schemas))}
                steps.append(step)
            yield {"steps": steps}
        else:
            seed_bytes = payloads[index] if index < len(payloads) else None
            tpl = templates[index % len(templates)] if index < len(templates) * 2 else rng.choice(templates)
            yield {"steps": [make_step(index, tpl, force_data=seed_bytes)]}
        index += 1


def replay_app_config(app):
    """Extract only the boundary driver config required to replay a finding."""
    return {k: app[k] for k in ADAPTER_KEYS if k in app}


def preserve_finding(directory, initial, case, identity, failing_step, execution, confirmations,
                     environment, timeout, app, *, minimized=False, shrink_checks=0):
    directory.mkdir(parents=True)
    shutil.copytree(initial, directory / "initial", symlinks=True)
    write_json(directory / "case.json", case)
    observations = [execution, *confirmations]
    for i, obs in enumerate(observations):
        for s_idx, step_res in enumerate(obs["steps"]):
            (directory / f"observation-{i}-step-{s_idx}.stderr").write_text(step_res["stderr"])
            (directory / f"observation-{i}-step-{s_idx}.stdout").write_text(step_res["stdout"])
    app_cfg = replay_app_config(app)
    metadata = {
        "format_version": FORMAT_VERSION,
        "tool_version": VERSION,
        "application": app["name"],
        "application_path": app["path"],
        "build_root": str(Path(initial).resolve()),
        "identity": identity,
        "failing_step": failing_step,
        "step_count": len(case["steps"]),
        "minimized": minimized,
        "shrink_checks": shrink_checks,
        "app_config": app_cfg,
        "environment": environment,
        "timeout": timeout,
        "platform": sys.platform,
        "machine": os.uname().machine,
        "initial_sha256": tree_manifest(directory / "initial", include_dirs=True),
        "case_sha256": digest((directory / "case.json").read_bytes()),
        "confirmations": len(confirmations),
        "returncodes": [obs["returncode"] for obs in observations],
    }
    write_json(directory / "finding.json", metadata)
    command = shlex.join([sys.executable, str(ROOT / "odin-fuzz"), "reproduce", str(directory)])
    (directory / "REPLAY.md").write_text(
        "# Confirmed application failure\n\n"
        f"Application: `{app['name']}` (`{app['path']}`)\n\n"
        f"Failure: `{identity['kind']}` at `{identity['site']}` (step {failing_step + 1} of {len(case['steps'])}).\n\n"
        f"Replay from a fresh captured state:\n\n```sh\n{command}\n```\n\n"
        "`case.json` records the ordered step sequence (argv, stdin, per-step file replacements/deletions, environment overrides, "
        "and any configured UI event, local loopback network, local IPC, seed, or clock deliveries). "
        "`initial/` retains the compiled application and starting files; replay checks their SHA-256 manifest against `finding.json` "
        "and executes inside a disposable copy. This detects drift or partial modification of `initial/` or `case.json` relative to "
        "`finding.json`; it is not a cryptographic signature against rewriting `finding.json` itself. "
        "System libraries and the installed sanitizer runtime remain host dependencies.\n"
    )
    return {
        "application": app["name"],
        "kind": identity["kind"],
        "site": identity["site"],
        "failing_step": failing_step,
        "step_count": len(case["steps"]),
        "minimized": minimized,
        "shrink_checks": shrink_checks,
        "directory": str(directory),
        "replay": command,
    }


def _signed_int(value, width):
    bits = max(8, min(64, int(width) * 8))
    mask = (1 << bits) - 1
    v = value & mask
    if v >= (1 << (bits - 1)):
        return v - (1 << bits)
    return v


def _plausible_cmp_targets(a, b, width, kind):
    """Return concrete candidate integer values to flip an observed runtime comparison."""
    # Note: LLVM trace_const_cmp passes the constant in Arg1 (a) and variable in Arg2 (b);
    # trace_switch passes tested value in a and case constant in b.
    ordered = (b,) if kind == 3 else (a, b) if kind == 2 else (b, a)
    candidates = []
    for raw in ordered:
        sval = _signed_int(raw, width)
        if abs(sval) > 10**12 and raw > 0xFFFFFFFF:
            continue
        for v in (sval, sval - 1, sval + 1):
            if v not in candidates:
                candidates.append(v)
    return candidates[:6]


def _replace_bytes_once(data, old_bytes, new_bytes):
    if not old_bytes or old_bytes == new_bytes or old_bytes not in data:
        return None
    return data.replace(old_bytes, new_bytes, 1)[:MAX_INPUT]


def _replace_in_case(parent_case, byte_pairs, *, old_text="", new_text="", min_sub=2, old_int=None, new_int=None, allow_argv=True):
    """Input-to-state replacement across argv, files, stdin, messages, env, seed, and clock."""
    variants = []
    can_text = bool(old_text and new_text and old_text != new_text)

    for s_idx, step in enumerate(parent_case["steps"]):
        if can_text:
            if allow_argv:
                for a_idx, arg in enumerate(step["argv"]):
                    if arg == old_text or (len(old_text) >= min_sub and old_text in arg):
                        cand = copy.deepcopy(parent_case)
                        cand["steps"][s_idx]["argv"][a_idx] = (new_text if arg == old_text else arg.replace(old_text, new_text, 1))[:256]
                        variants.append(cand)
                        break
            for ename, eval_s in step["environment"].items():
                if eval_s == old_text or (len(old_text) >= min_sub and old_text in eval_s):
                    cand = copy.deepcopy(parent_case)
                    cand["steps"][s_idx]["environment"][ename] = (new_text if eval_s == old_text else eval_s.replace(old_text, new_text, 1))[:128]
                    variants.append(cand)
                    break
        for fname, b64 in list(step["files"].items())[:4]:
            raw = decode(b64)
            for ob, nb in byte_pairs:
                replaced = _replace_bytes_once(raw, ob, nb)
                if replaced is not None:
                    cand = copy.deepcopy(parent_case)
                    cand["steps"][s_idx]["files"][fname] = encode(replaced)
                    variants.append(cand)
                    break
        stdin_raw = decode(step["stdin"])
        for ob, nb in byte_pairs:
            replaced = _replace_bytes_once(stdin_raw, ob, nb)
            if replaced is not None:
                cand = copy.deepcopy(parent_case)
                cand["steps"][s_idx]["stdin"] = encode(replaced)
                variants.append(cand)
                break
        for mkey in ("network_messages", "ipc_messages"):
            for m_idx, b64 in enumerate((step.get(mkey) or [])[:4]):
                raw = decode(b64)
                for ob, nb in byte_pairs:
                    replaced = _replace_bytes_once(raw, ob, nb)
                    if replaced is not None:
                        cand = copy.deepcopy(parent_case)
                        cand["steps"][s_idx][mkey][m_idx] = encode(replaced)
                        variants.append(cand)
                        break
        if old_int is not None and new_int is not None:
            for key in ("seed", "clock"):
                if step.get(key) == old_int:
                    cand = copy.deepcopy(parent_case)
                    cand["steps"][s_idx][key] = new_int
                    variants.append(cand)
    return variants[:4]


def _append_ui_frame(events, key, max_frames):
    """Append a fresh UI frame pressing key while clearing premature close on prior frames."""
    updated = [dict(ev) for ev in (events or [])]
    if len(updated) >= max_frames:
        updated = [] if max_frames <= 1 else updated[-(max_frames - 1):]
    for i, ev in enumerate(updated):
        ev["frame"] = i
        ev["close"] = False
    last_vp = updated[-1].get("viewport", [800, 600]) if updated else [800, 600]
    updated.append({
        "frame": len(updated),
        "dt": 0.016,
        "keys_down": [key] if key else [],
        "keys_pressed": [key] if key else [],
        "mouse": {"x": 100, "y": 100, "left": False, "right": False, "wheel": 0.0},
        "viewport": last_vp,
        "close": True,
    })
    return updated


def _inject_token_into_case(parent_case, token, ctx):
    """Build targeted variants of parent_case injecting a branch-guard token (str or int)."""
    variants = []
    token_str = str(token).replace("\0", "")[:128]
    if not token_str:
        return variants
    app, kinds, adapters = ctx["app"], ctx["kinds"], ctx["adapters"]
    env_names, base_filenames = ctx["env_names"], ctx["base_filenames"]
    s_idx = len(parent_case["steps"]) - 1
    step = parent_case["steps"][s_idx]

    if "ui" in adapters:
        ui_cfg = app["ui_events"]
        keys = ui_cfg.get("keys") or DEFAULT_UI_KEYS
        if token_str in keys:
            cand = copy.deepcopy(parent_case)
            cand["steps"][s_idx]["ui_events"] = _append_ui_frame(step.get("ui_events"), token_str, ui_cfg.get("max_frames", 32))
            variants.append(cand)

    if "argv" in kinds and "args" not in app:
        if len(step["argv"]) < 8:
            cand = copy.deepcopy(parent_case)
            cand["steps"][s_idx]["argv"].append(token_str)
            variants.append(cand)
        if step["argv"]:
            cand = copy.deepcopy(parent_case)
            cand["steps"][s_idx]["argv"][-1] = token_str
            variants.append(cand)

    if ("files" in kinds or app.get("files")) and not ("ui" in adapters and not app.get("files")):
        target_files = list(step["files"].keys())[:2] or base_filenames[:1]
        for fname in target_files:
            cand = copy.deepcopy(parent_case)
            if fname.endswith(".json") and fname in step["files"]:
                try:
                    parsed = json.loads(decode(step["files"][fname]).decode("utf-8"))
                    if isinstance(parsed, list) and parsed and isinstance(parsed[-1], dict):
                        parsed[-1]["i" if isinstance(token, int) else "kind"] = token if isinstance(token, int) else token_str
                        cand["steps"][s_idx]["files"][fname] = encode(json.dumps(parsed).encode("utf-8")[:MAX_INPUT])
                        variants.append(cand)
                        continue
                except (ValueError, UnicodeDecodeError):
                    pass
            cand["steps"][s_idx]["files"][fname] = encode(token_str.encode("utf-8"))
            variants.append(cand)

    if "stdin" in kinds:
        existing = decode(step["stdin"])
        sep = b"\n" if existing and not existing.endswith(b"\n") else b""
        for payload in ((existing + sep + token_str.encode("utf-8") + b"\n")[:MAX_INPUT], token_str.encode("utf-8")):
            cand = copy.deepcopy(parent_case)
            cand["steps"][s_idx]["stdin"] = encode(payload)
            variants.append(cand)

    if env_names:
        cand = copy.deepcopy(parent_case)
        cand["steps"][s_idx]["environment"][env_names[0]] = token_str
        variants.append(cand)

    for adapter_kind, msg_key in (("network", "network_messages"), ("ipc", "ipc_messages")):
        if adapter_kind in adapters:
            cand = copy.deepcopy(parent_case)
            cand["steps"][s_idx][msg_key] = [encode(token_str.encode("utf-8"))]
            variants.append(cand)

    if isinstance(token, int):
        for adapter_kind, field in (("randomness", "seed"), ("clock", "clock")):
            if adapter_kind in adapters:
                cand = copy.deepcopy(parent_case)
                cand["steps"][s_idx][field] = token
                variants.append(cand)

    if app.get("writes_files") and len(parent_case["steps"]) < MAX_STEPS and "argv" in kinds and "args" not in app:
        cand = copy.deepcopy(parent_case)
        cand["steps"].append({"argv": [token_str], "stdin": "", "files": {}, "environment": {}})
        variants.append(cand)

    return variants[:6]


def _branch_is_untaken(branch, covered_lines):
    """True when a branch's body lines have not been hit globally."""
    lines = covered_lines.get(branch["path"])
    if not lines:
        return True
    start, end = branch["body_start"], branch["body_end"]
    if end > branch["line"] and start <= branch["line"]:
        start = branch["line"] + 1
    return not any(line in lines for line in range(start, end + 1))


def _branch_on_frontier(branch, lines_map, covered_lines, *, slack=1):
    """True when a branch header was hit in lines_map while its body remains globally untaken."""
    hit_lines = lines_map.get(branch["path"])
    if not hit_lines:
        return False
    return any(line in hit_lines for line in range(branch["line"] - slack, branch["line"] + 2)) and _branch_is_untaken(branch, covered_lines)


def _is_printable_token(raw):
    if not 2 <= len(raw) <= 64 or b"\x00" in raw:
        return False
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return all(32 <= ord(ch) < 127 for ch in text)


def enqueue_targeted_cases(entry, ctx, covered_lines, branch_attempts, cmp_attempts, str_attempts, targeted_queue, seen_targeted):
    """Enqueue targeted inputs for untaken runtime CMPs, runtime string CMPs, and Odin AST frontier branches."""
    app, dynamic_strings = ctx["app"], ctx["dynamic_strings"]
    allow_argv = "args" not in app
    parent_case = entry["case"]
    fresh = []

    def add_target(mode, case_obj):
        key = digest(json.dumps(case_obj, sort_keys=True).encode("utf-8"))
        if key in seen_targeted:
            return False
        seen_targeted.add(key)
        fresh.append((mode, case_obj))
        return True

    # 1. Runtime string comparison (runtime::string_eq) I2S + dynamic runtime string targeting.
    added_str = 0
    for a_bytes, b_bytes in entry.get("str_cmps") or []:
        if added_str >= 12:
            break
        skey = (a_bytes, b_bytes)
        if str_attempts.get(skey, 0) >= 2:
            continue
        str_attempts[skey] = str_attempts.get(skey, 0) + 1
        matched_i2s = False
        for old_b, new_b in ((a_bytes, b_bytes), (b_bytes, a_bytes)):
            if not old_b or not new_b or old_b == new_b:
                continue
            old_t = old_b.decode("utf-8", errors="ignore").replace("\0", "")
            new_t = new_b.decode("utf-8", errors="ignore").replace("\0", "")
            for variant in _replace_in_case(parent_case, [(old_b, new_b)], old_text=old_t, new_text=new_t, min_sub=2, allow_argv=allow_argv):
                if add_target("str_cmp_i2s", variant):
                    added_str += 1
                    matched_i2s = True
        for raw_b in (b_bytes, a_bytes):
            if _is_printable_token(raw_b):
                txt = raw_b.decode("utf-8")
                if txt not in dynamic_strings and len(dynamic_strings) < 64:
                    dynamic_strings.append(txt)
                if added_str < (12 if matched_i2s else 8):
                    for variant in _inject_token_into_case(parent_case, txt, ctx)[:(2 if matched_i2s else 1)]:
                        if add_target("str_cmp_inject", variant):
                            added_str += 1

    # 2. Runtime trace-cmp / trace-switch targeting: prioritize multi-byte / non-bool comparisons.
    ordered_cmps = sorted(
        entry["cmps"],
        key=lambda c: (0 if (c[3] >= 2 and max(abs(_signed_int(c[1], c[3])), abs(_signed_int(c[2], c[3]))) > 2) else 1, -c[3]),
    )
    added_cmp = 0
    for pc, arg1, arg2, width, kind in ordered_cmps:
        if added_cmp >= 12:
            break
        if arg1 == arg2 or (width == 1 and arg1 <= 1 and arg2 <= 1):
            continue
        ckey = (pc, arg1, arg2)
        if cmp_attempts.get(ckey, 0) >= 2:
            continue
        cmp_attempts[ckey] = cmp_attempts.get(ckey, 0) + 1
        s1, s2 = _signed_int(arg1, width), _signed_int(arg2, width)
        for target_val in _plausible_cmp_targets(arg1, arg2, width, kind):
            for old_val in (s1, s2):
                if target_val == old_val:
                    continue
                old_s, new_s = str(old_val), str(target_val)
                bpairs = [(old_s.encode("utf-8"), new_s.encode("utf-8"))]
                if width in (2, 4, 8):
                    mask = (1 << (width * 8)) - 1
                    for endian in ("little", "big"):
                        ob = (old_val & mask).to_bytes(width, endian)
                        nb = (target_val & mask).to_bytes(width, endian)
                        if ob != nb and any(x != 0 for x in ob):
                            bpairs.append((ob, nb))
                for variant in _replace_in_case(parent_case, bpairs, old_text=old_s, new_text=new_s, min_sub=3, old_int=old_val, new_int=target_val, allow_argv=allow_argv):
                    if add_target("cmp_i2s", variant):
                        added_cmp += 1
            for variant in _inject_token_into_case(parent_case, target_val, ctx)[:2]:
                if add_target("cmp_inject", variant):
                    added_cmp += 1
            if added_cmp >= 12:
                break

    # 3. Odin AST untaken frontier branches reached by this corpus entry.
    ui_keys = set((app.get("ui_events") or {}).get("keys") or DEFAULT_UI_KEYS)
    added_branch = 0
    for b_idx, branch in enumerate(app.get("branches") or []):
        if added_branch >= 12:
            break
        if not _branch_on_frontier(branch, entry["lines"], covered_lines, slack=3):
            continue
        if branch_attempts.get(b_idx, 0) >= MAX_BRANCH_ATTEMPTS:
            continue
        branch_attempts[b_idx] = branch_attempts.get(b_idx, 0) + 1
        tokens = list(dict.fromkeys([
            *(branch.get("strings") or []),
            *(v for n in (branch.get("ints") or []) for v in (n, n - 1, n + 1)),
            *(ident for ident in (branch.get("idents") or []) if ident in ui_keys),
        ]))
        for tok in tokens:
            for variant in _inject_token_into_case(parent_case, tok, ctx)[:2]:
                if add_target("frontier_branch", variant):
                    added_branch += 1
                if added_branch >= 12:
                    break
            if added_branch >= 12:
                break

    # Push newly unlocked targets to the front so deeper breakthroughs run immediately.
    for item in reversed(fresh):
        targeted_queue.appendleft(item)
    while len(targeted_queue) > MAX_TARGETED_QUEUE:
        targeted_queue.pop()


def evolve_corpus_case(rng, corpus, ctx, covered_lines):
    """Select an energetic corpus parent and apply structure-aware evolutionary mutations."""
    app = ctx["app"]
    kinds, adapters = ctx["kinds"], ctx["adapters"]
    payloads, literals, schemas = ctx["payloads"], ctx["literals"], ctx["schemas"]
    env_names, base_filenames = ctx["env_names"], ctx["base_filenames"]
    dynamic_files, dynamic_strings = ctx["dynamic_files"], ctx["dynamic_strings"]

    weights = [
        max(0.1, entry["energy"] * (
            3.0 if any(_branch_on_frontier(b, entry["lines"], covered_lines) for b in (app.get("branches") or [])) else 1.0
        ))
        for entry in corpus
    ]
    parent = rng.choices(corpus, weights=weights, k=1)[0]
    parent["energy"] = max(0.25, parent["energy"] * 0.92)
    cand = copy.deepcopy(parent["case"])
    s_idx = rng.randrange(len(cand["steps"]))
    step = cand["steps"][s_idx]

    cmp_ints = [t for _, a, b, w, k in parent["cmps"][:16] for t in _plausible_cmp_targets(a, b, w, k)[:2]]
    all_literals = list(dict.fromkeys([*dynamic_strings, *literals]))

    ops = []
    if "ui" in adapters:
        ops.extend(["ui_extend", "ui_extend", "ui_mutate"])
    if "argv" in kinds and "args" not in app:
        ops.extend(["argv_mutate", "argv_append"])
    if "files" in kinds or app.get("files"):
        ops.append("file_mutate")
    if "stdin" in kinds:
        ops.append("stdin_mutate")
    if env_names:
        ops.append("env_mutate")
    for adapter_kind, op_name in (("network", "net_mutate"), ("ipc", "ipc_mutate"), ("randomness", "seed_mutate"), ("clock", "clock_mutate")):
        if adapter_kind in adapters:
            ops.append(op_name)
    if len(cand["steps"]) < MAX_STEPS and (app.get("writes_files") or dynamic_files or rng.random() < 0.25):
        ops.append("step_extend")
    if len(corpus) >= 2:
        ops.append("splice")
    if not ops:
        return cand
    op = rng.choice(ops)

    def pick_token(fallback_int=False):
        if cmp_ints and rng.random() < 0.45:
            return str(rng.choice(cmp_ints))
        if all_literals and rng.random() < 0.55:
            return rng.choice(all_literals)
        if fallback_int:
            return str(rng.choice([0, 1, -1, 42]))
        return mutate_bytes(rng, payloads).decode("utf-8", errors="replace").replace("\0", "")[:128]

    if op in {"ui_extend", "ui_mutate"}:
        ui_cfg = app["ui_events"]
        keys = ui_cfg.get("keys") or DEFAULT_UI_KEYS
        events = step.get("ui_events") or []
        if op == "ui_extend":
            for _ in range(rng.randint(1, 2)):
                events = _append_ui_frame(events, rng.choice(keys), ui_cfg.get("max_frames", 32))
            step["ui_events"] = events
        elif events:
            ev = events[rng.randrange(len(events))]
            k = rng.choice(keys)
            ev["keys_pressed"] = [k] if rng.random() < 0.8 else []
            ev["keys_down"] = [k] if rng.random() < 0.5 else []
            if rng.random() < 0.25:
                ev["viewport"] = rng.choice([[800, 600], [1280, 720], [0, 0], [320, 240]])
        else:
            step["ui_events"] = generate_ui_events(rng, ui_cfg, 1)
    elif op == "argv_mutate":
        tok = pick_token()
        if step["argv"]:
            step["argv"][rng.randrange(len(step["argv"]))] = tok
        else:
            step["argv"].append(tok)
    elif op == "argv_append":
        if len(step["argv"]) < 8:
            step["argv"].append(pick_token(fallback_int=True))
        elif step["argv"]:
            step["argv"].pop()
    elif op == "file_mutate":
        cands = list(dict.fromkeys([*step["files"].keys(), *base_filenames, *sorted(dynamic_files)]))
        if cands:
            fname = rng.choice(cands)
            base = decode(step["files"][fname]) if fname in step["files"] else None
            payload = structured_json_payload(rng, all_literals, schemas=schemas) if (fname.endswith(".json") and rng.random() < 0.65) else mutate_bytes(rng, payloads, base=base)
            step["files"][fname] = encode(payload)
    elif op == "stdin_mutate":
        base = decode(step["stdin"])
        step["stdin"] = encode(structured_json_payload(rng, all_literals, schemas=schemas) if rng.random() < 0.4 else mutate_bytes(rng, payloads, base=base or None))
    elif op == "env_mutate" and env_names:
        step["environment"][rng.choice(env_names)] = pick_token()
    elif op in {"net_mutate", "ipc_mutate"}:
        mkey = "network_messages" if op == "net_mutate" else "ipc_messages"
        msgs = list(step.get(mkey) or [])
        base = decode(rng.choice(msgs)) if msgs else None
        mutated = encode(mutate_bytes(rng, payloads, base=base))
        if msgs and rng.random() < 0.6:
            msgs[rng.randrange(len(msgs))] = mutated
        else:
            msgs.append(mutated)
        step[mkey] = msgs[:4]
    elif op in {"seed_mutate", "clock_mutate"}:
        field = "seed" if op == "seed_mutate" else "clock"
        step[field] = rng.choice(cmp_ints) if (cmp_ints and rng.random() < 0.5) else rng.randint(0, 2**31 - 1)
    elif op == "step_extend":
        extra = copy.deepcopy(cand["steps"][-1])
        extra["files"] = {} if rng.random() < 0.6 else extra["files"]
        if "argv" in kinds and "args" not in app and literals:
            extra["argv"] = [rng.choice(literals)]
        cand["steps"].append(extra)
    elif op == "splice":
        other = rng.choice(corpus)["case"]
        other_step = copy.deepcopy(other["steps"][rng.randrange(len(other["steps"]))])
        if len(cand["steps"]) < MAX_STEPS and rng.random() < 0.5:
            cand["steps"].append(other_step)
        elif "ui" in adapters and other_step.get("ui_events"):
            max_f = app["ui_events"].get("max_frames", 32)
            merged = (list(cand["steps"][s_idx].get("ui_events") or [])[:4] + list(other_step["ui_events"]))[:max_f]
            for i, ev in enumerate(merged):
                ev["frame"] = i
                ev["close"] = i == len(merged) - 1
            cand["steps"][s_idx]["ui_events"] = merged
        elif other_step["files"] and ("args" in app or rng.random() < 0.5):
            cand["steps"][s_idx]["files"].update(other_step["files"])
        elif "args" not in app:
            cand["steps"][s_idx]["argv"] = other_step["argv"]
    return cand


def load_corpus_cases(corpus_dir, app_id):
    """Load previously saved valid cases for one application from --corpus-dir."""
    if not corpus_dir:
        return []
    app_dir = corpus_dir / app_id
    if app_dir.is_symlink() or not app_dir.is_dir():
        return []
    loaded = []
    for path in sorted(app_dir.glob("*.json"))[:MAX_CORPUS]:
        if path.is_symlink() or not path.is_file():
            continue
        try:
            raw = json.loads(path.read_text())
            loaded.append(normalize_case(raw))
        except (OSError, ValueError, TypeError, ToolError):
            continue
    return loaded


def save_corpus_cases(corpus_dir, app_id, corpus):
    """Persist coverage-winning corpus cases for one application under --corpus-dir."""
    if not corpus_dir or not corpus:
        return 0
    app_dir = corpus_dir / app_id
    app_dir.mkdir(parents=True, exist_ok=True)
    saved = 0
    for entry in corpus[:MAX_CORPUS]:
        case_obj = entry["case"]
        name = digest(json.dumps(case_obj, sort_keys=True).encode("utf-8"))[:16] + ".json"
        target = app_dir / name
        if not target.exists():
            write_json(target, case_obj)
        saved += 1
    return saved


def minimize_case(case, identity, failing_step, fixed_args, run_clean):
    """Shrink a confirmed failing case while preserving the exact failure identity."""
    started = time.monotonic()
    checks = 0
    best = copy.deepcopy(case)
    best_step = failing_step
    best_exec = None
    changed = False

    def budget_left():
        return checks < MAX_SHRINK_CHECKS and (time.monotonic() - started) < MAX_SHRINK_SECONDS

    def try_candidate(cand, expected_step):
        nonlocal checks, best, best_step, best_exec, changed
        if not budget_left():
            return False
        checks += 1
        try:
            res = run_clean(cand)
        except WorkspaceError:
            return False
        if res["identity"] == identity and res["failing_step"] == expected_step:
            best, best_step, best_exec, changed = cand, expected_step, res, True
            return True
        return False

    # 1. Drop trailing steps after failing_step, then non-essential earlier steps.
    if len(best["steps"]) > best_step + 1:
        try_candidate({"steps": copy.deepcopy(best["steps"][:best_step + 1])}, best_step)
    idx = 0
    while idx < best_step and budget_left():
        cand = {"steps": copy.deepcopy(best["steps"][:idx] + best["steps"][idx + 1:])}
        if not try_candidate(cand, best_step - 1):
            idx += 1

    # 2. Shrink per-step fields.
    for s_idx in range(len(best["steps"])):
        if not budget_left():
            break
        for dkey in ("files", "environment"):
            if best["steps"][s_idx][dkey]:
                cand = copy.deepcopy(best)
                cand["steps"][s_idx][dkey] = {}
                if not try_candidate(cand, best_step):
                    for key in list(best["steps"][s_idx][dkey].keys()):
                        if not budget_left():
                            break
                        cand = copy.deepcopy(best)
                        cand["steps"][s_idx][dkey].pop(key, None)
                        try_candidate(cand, best_step)
        for fkey, empty_val in (("stdin", ""), ("delete_files", [])):
            if best["steps"][s_idx].get(fkey):
                cand = copy.deepcopy(best)
                cand["steps"][s_idx][fkey] = empty_val
                try_candidate(cand, best_step)
        if not fixed_args and best["steps"][s_idx]["argv"]:
            cand = copy.deepcopy(best)
            cand["steps"][s_idx]["argv"] = []
            if not try_candidate(cand, best_step):
                for a_idx in range(len(best["steps"][s_idx]["argv"]) - 1, -1, -1):
                    if not budget_left():
                        break
                    cand = copy.deepcopy(best)
                    cand["steps"][s_idx]["argv"].pop(a_idx)
                    try_candidate(cand, best_step)
        for lkey in ("network_messages", "ipc_messages", "ui_events"):
            items = best["steps"][s_idx].get(lkey) or []
            for item_idx in range(len(items) - 1, -1, -1):
                if not budget_left() or len(best["steps"][s_idx].get(lkey) or []) <= 1:
                    break
                cand = copy.deepcopy(best)
                cand["steps"][s_idx][lkey].pop(item_idx)
                try_candidate(cand, best_step)
        for fname, b64 in list(best["steps"][s_idx]["files"].items()):
            if not budget_left():
                break
            raw = decode(b64)
            if fname.endswith(".json") and len(raw) > 2:
                try:
                    parsed = json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, ValueError):
                    parsed = None
                if isinstance(parsed, list) and len(parsed) > 1:
                    for e_idx in range(len(parsed) - 1, -1, -1):
                        if not budget_left() or len(parsed) <= 1:
                            break
                        trial = parsed[:e_idx] + parsed[e_idx + 1:]
                        cand = copy.deepcopy(best)
                        cand["steps"][s_idx]["files"][fname] = encode(json.dumps(trial).encode("utf-8"))
                        if try_candidate(cand, best_step):
                            parsed = trial
            elif len(raw) > 64:
                cand = copy.deepcopy(best)
                cand["steps"][s_idx]["files"][fname] = encode(raw[:len(raw) // 2])
                try_candidate(cand, best_step)

    return best, best_step, best_exec, changed, checks


def explore_application(app, initial, directory, environment, seconds, seed, max_cases, timeout, build_info, chain, corpus_dir=None):
    started = time.monotonic()
    rng = random.Random(seed ^ 0x9E3779B9)
    findings, diagnostics, confirmed_keys = [], [], set()
    flaky_attempts = {}
    executions = multi_step_executions = rejections = timeouts = workspace_errors = 0
    targeted_executions = evolved_executions = 0
    initial_files = workspace_files(initial)
    app_cfg = replay_app_config(app)
    build_root = str(Path(initial).resolve())
    cov_enabled = build_info["coverage_mode"] == "llvm_sancov"
    pc_starts, pc_ranges = build_info["pc_starts"], build_info["pc_ranges"]
    binary = build_info["binary"]
    ctx = build_app_context(app, initial)

    def run_clean(case_obj):
        return execute_case(
            initial, case_obj, directory / "scratch", environment, timeout, app_cfg,
            initial_files=initial_files, track_created=False, build_root=build_root, collect_coverage=False,
        )

    global_edges, global_guards = set(), set()
    pc_loc, covered_lines = {}, {}
    branch_attempts, cmp_attempts, str_attempts = {}, {}, {}
    corpus = []
    targeted_queue = deque()
    seen_targeted = set()
    persisted_cases = load_corpus_cases(corpus_dir, app["id"])
    persisted_queue = deque(persisted_cases)
    corpus_loaded = len(persisted_cases)
    seed_iter = input_cases(ctx, seed)
    initial_warmup = min(12, max(4, len(ctx["payloads"]) // 4))

    while True:
        if executions and (time.monotonic() - started >= seconds or (max_cases and executions >= max_cases)):
            break
        source_mode = "seed"
        if executions == 0:
            case = next(seed_iter)
        elif persisted_queue:
            source_mode, case = "corpus", persisted_queue.popleft()
        elif targeted_queue:
            source_mode, case = targeted_queue.popleft()
        elif executions >= initial_warmup and corpus and rng.random() < 0.75:
            source_mode, case = "evolved", evolve_corpus_case(rng, corpus, ctx, covered_lines)
        else:
            case = next(seed_iter)

        try:
            execution = execute_case(
                initial, case, directory / "scratch", environment, timeout, app_cfg,
                initial_files=initial_files, track_created=True, build_root=build_root,
                collect_coverage=cov_enabled, pc_starts=pc_starts, pc_ranges=pc_ranges,
            )
        except WorkspaceError as error:
            workspace_errors += 1
            diagnostics.append({"reason": f"workspace operation failed: {error}"})
            continue
        executions += 1
        if source_mode in {"cmp_i2s", "cmp_inject", "str_cmp_i2s", "str_cmp_inject", "frontier_branch"}:
            targeted_executions += 1
        elif source_mode == "evolved":
            evolved_executions += 1
        if len(case["steps"]) > 1:
            multi_step_executions += 1
        for fname in execution["created_files"][:4]:
            if len(ctx["dynamic_files"]) >= 16:
                break
            norm = _eligible_candidate_file(initial, fname)
            if norm is not None:
                ctx["dynamic_files"].add(norm)

        # Evolution + untaken-branch frontier update on newly discovered coverage.
        cov = execution.get("coverage")
        if cov_enabled and cov and not execution["timed_out"]:
            new_edges = cov["edges"] - global_edges
            new_guards = cov["guards"] - global_guards
            if new_edges or new_guards:
                global_edges.update(new_edges)
                global_guards.update(new_guards)
                unknown_pcs = [pc for pc in cov["pcs"] if pc not in pc_loc]
                if unknown_pcs:
                    resolved = symbolize_pcs(binary, chain.get("symbolizer"), unknown_pcs, build_root)
                    for pc in unknown_pcs:
                        pc_loc[pc] = resolved.get(pc)
                entry_lines = {}
                for pc in cov["pcs"]:
                    loc = pc_loc.get(pc)
                    if loc:
                        entry_lines.setdefault(loc[0], set()).add(loc[1])
                        covered_lines.setdefault(loc[0], set()).add(loc[1])
                entry = {
                    "case": case,
                    "guards": cov["guards"],
                    "pcs": cov["pcs"],
                    "cmps": cov["cmps"],
                    "str_cmps": cov.get("str_cmps") or [],
                    "lines": entry_lines,
                    "energy": 2.0 if new_guards else 1.0,
                }
                if len(corpus) >= MAX_CORPUS:
                    corpus.pop(0)
                corpus.append(entry)
                if new_guards:
                    enqueue_targeted_cases(
                        entry, ctx, covered_lines, branch_attempts, cmp_attempts, str_attempts, targeted_queue, seen_targeted,
                    )

        identity = execution["identity"]
        failing_step = execution["failing_step"]
        if execution["timed_out"]:
            timeouts += 1
        elif execution["returncode"] and not identity:
            rejections += 1
        if not identity:
            continue
        key = json.dumps({"identity": identity}, sort_keys=True)
        if key in confirmed_keys or flaky_attempts.get(key, 0) >= MAX_FLAKY_CONFIRM_ATTEMPTS:
            continue
        try:
            confirmations = [run_clean(case) for _ in range(CONFIRMATIONS)]
        except WorkspaceError as error:
            workspace_errors += 1
            diagnostics.append({"reason": f"confirmation workspace operation failed: {error}", "identity": identity})
            continue
        if all(c["identity"] == identity and c["failing_step"] == failing_step for c in confirmations):
            confirmed_keys.add(key)
            final_case, final_step, final_exec, final_confs = case, failing_step, execution, confirmations
            was_minimized = False
            min_case, min_step, min_exec, shrunk, shrink_checks = minimize_case(case, identity, failing_step, "args" in app, run_clean)
            if shrunk:
                try:
                    min_confs = [run_clean(min_case) for _ in range(CONFIRMATIONS)]
                    if all(r["identity"] == identity and r["failing_step"] == min_step for r in min_confs):
                        final_case, final_step = min_case, min_step
                        final_exec, final_confs = min_exec, min_confs
                        was_minimized = True
                except WorkspaceError:
                    pass
            finding = preserve_finding(
                directory / "findings" / digest(key.encode())[:16], initial, final_case,
                identity, final_step, final_exec, final_confs, environment, timeout, app,
                minimized=was_minimized, shrink_checks=shrink_checks,
            )
            findings.append(finding)
        else:
            flaky_attempts[key] = flaky_attempts.get(key, 0) + 1
            diagnostics.append({
                "reason": "failure identity or failing step did not repeat identically across fresh-state replays",
                "identity": identity,
                "failing_step": failing_step,
            })
    corpus_saved = save_corpus_cases(corpus_dir, app["id"], corpus)
    try:
        safe_rmtree(directory / "scratch")
    except OSError as error:
        workspace_errors += 1
        diagnostics.append({"reason": f"incomplete scratch cleanup: {error}"})
    write_json(directory / "diagnostics.json", diagnostics)
    driven = [item["kind"] for item in app["inventory"] if item["status"] in {"driven", "adapter_driven"}]
    branches = app.get("branches") or []
    untaken_frontier_all = []
    if cov_enabled:
        seen_frontier = set()
        for b in branches:
            fkey = (b["path"], b["line"], b["kind"])
            if fkey in seen_frontier or not _branch_on_frontier(b, covered_lines, covered_lines):
                continue
            seen_frontier.add(fkey)
            clues = [*(b.get("strings") or [])[:4], *(b.get("ints") or [])[:4], *(b.get("idents") or [])[:2]][:6]
            untaken_frontier_all.append({"path": b["path"], "line": b["line"], "kind": b["kind"], "clues": clues})
    return {
        "name": app["name"],
        "path": app["path"],
        "status": "explored",
        "coverage_mode": build_info["coverage_mode"],
        "executions": executions,
        "evolved_executions": evolved_executions,
        "targeted_executions": targeted_executions,
        "multi_step_executions": multi_step_executions,
        "corpus_size": len(corpus),
        "corpus_loaded": corpus_loaded,
        "corpus_saved": corpus_saved,
        "first_party_edges_hit": len(global_guards),
        "ast_branches_total": len(branches),
        "ast_branches_covered": sum(1 for b in branches if not _branch_is_untaken(b, covered_lines)) if cov_enabled else 0,
        "frontier_branches_remaining": len(untaken_frontier_all),
        "untaken_frontier": untaken_frontier_all[:20],
        "ordinary_or_unclassified_exits": rejections,
        "timeouts": timeouts,
        "workspace_errors": workspace_errors,
        "unconfirmed_withheld": len(diagnostics),
        "findings": findings,
        "inventory": app["inventory"],
        "driven_interfaces": driven,
    }


def validate_replay_metadata(metadata, case):
    if not isinstance(metadata, dict):
        raise ToolError("finding.json must be a JSON object")
    fmt = metadata.get("format_version")
    if not is_strict_int(fmt) or fmt not in {2, FORMAT_VERSION}:
        raise ToolError("replay requires a supported captured format version")
    if metadata.get("platform") != sys.platform or metadata.get("machine") != os.uname().machine:
        raise ToolError("replay requires the captured operating system and architecture")
    timeout = metadata.get("timeout")
    if not is_strict_number(timeout) or timeout <= 0:
        raise ToolError("invalid recorded timeout in finding.json")
    env = metadata.get("environment")
    if not isinstance(env, dict) or any(
            not isinstance(k, str) or not isinstance(v, str) or not k or "=" in k or "\0" in k + v or k.startswith(("DYLD_", "ODIN_FUZZ_COV_"))
            for k, v in env.items()):
        raise ToolError("invalid recorded environment in finding.json")
    app_cfg = metadata.get("app_config", {})
    if not isinstance(app_cfg, dict) or set(app_cfg) - set(ADAPTER_KEYS):
        raise ToolError("invalid recorded app_config in finding.json")
    validate_adapter_config(app_cfg)
    identity = metadata.get("identity")
    if not isinstance(identity, dict) or not isinstance(identity.get("kind"), str) or not isinstance(identity.get("site"), str):
        raise ToolError("invalid recorded failure identity in finding.json")
    failing_step = metadata.get("failing_step", 0)
    if not is_strict_int(failing_step) or not 0 <= failing_step < len(case["steps"]):
        raise ToolError("invalid recorded failing_step in finding.json")
    build_root = metadata.get("build_root")
    if build_root is not None and (not isinstance(build_root, str) or not build_root or "\0" in build_root):
        raise ToolError("invalid recorded build_root in finding.json")
    return app_cfg, failing_step, build_root


def _read_regular_bundle_file(path, label):
    fd = -1
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ToolError(f"{label} in finding bundle must be a regular non-symlink file; refusing replay")
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            return handle.read()
    except ToolError:
        raise
    except OSError as error:
        raise ToolError(f"missing, symlinked, or unreadable {label} in finding bundle: {error}") from error
    finally:
        if fd >= 0:
            os.close(fd)


def reproduce(directory):
    if not directory.is_dir():
        raise ToolError(f"finding directory does not exist: {directory}")
    replay_dir = directory / "replay"
    if replay_dir.is_symlink():
        raise ToolError("replay directory in finding bundle cannot be a symlink; refusing replay")
    metadata = json.loads(_read_regular_bundle_file(directory / "finding.json", "finding.json").decode("utf-8"))
    if not isinstance(metadata, dict):
        raise ToolError("finding.json must be a JSON object")
    case_bytes = _read_regular_bundle_file(directory / "case.json", "case.json")
    if digest(case_bytes) != metadata.get("case_sha256"):
        raise ToolError("captured application, starting files, or input case changed; refusing replay")
    case = normalize_case(json.loads(case_bytes.decode("utf-8")))
    app_cfg, expected_step, build_root = validate_replay_metadata(metadata, case)
    include_dirs = metadata["format_version"] >= 3
    if tree_manifest(directory / "initial", include_dirs=include_dirs) != metadata.get("initial_sha256"):
        raise ToolError("captured application, starting files, or input case changed; refusing replay")
    try:
        execution = execute_case(
            directory / "initial", case, directory / "replay",
            metadata["environment"], metadata["timeout"], app_cfg,
            track_created=False, build_root=build_root,
        )
    except WorkspaceError as error:
        raise ToolError(f"replay workspace failed: {error}") from error
    print(execution["stderr"], end="", file=sys.stderr)
    matched = execution["identity"] == metadata["identity"] and execution["failing_step"] == expected_step
    print("Confirmed failure reproduced." if matched else "Recorded failure did not reproduce.")
    try:
        safe_rmtree(directory / "replay" / "workspace")
    except OSError as error:
        print(f"odin-fuzz: incomplete replay workspace cleanup: {error}", file=sys.stderr)
    return 1 if matched else 2


def summary_data(report, status):
    """Build a compact QA summary with metrics and paths only (no raw crash sites or payloads)."""
    finding_dirs = [
        finding["directory"]
        for result in report["applications"]
        for finding in result.get("findings", [])
    ]
    apps = [
        {
            "name": result.get("name") or result["path"],
            "path": result["path"],
            "status": result["status"],
            "finding_count": len(result.get("findings", [])),
            "executions": result.get("executions", 0),
            "coverage_mode": result.get("coverage_mode", "none"),
            "first_party_edges_hit": result.get("first_party_edges_hit", 0),
            "corpus_loaded": result.get("corpus_loaded", 0),
            "corpus_saved": result.get("corpus_saved", 0),
            "frontier_branches_remaining": result.get("frontier_branches_remaining", 0),
            "ordinary_or_unclassified_exits": result.get("ordinary_or_unclassified_exits", 0),
            "timeouts": result.get("timeouts", 0),
            "workspace_errors": result.get("workspace_errors", 0),
            "unconfirmed_withheld": result.get("unconfirmed_withheld", 0),
        }
        for result in report["applications"]
    ]
    run_dir = Path(report["run_directory"])
    return {
        "status": status,
        "run_directory": str(run_dir),
        "report_md": str(run_dir / "report.md"),
        "report_json": str(run_dir / "report.json"),
        "finding_count": len(finding_dirs),
        "finding_dirs": finding_dirs,
        "applications": apps,
    }


def report_text(report):
    lines = ["# odin-fuzz report", "", f"Project: `{report['project']}`", "", "## Confirmed bugs", ""]
    findings = [finding for result in report["applications"] for finding in result.get("findings", [])]
    if not findings:
        lines.append("No confirmed bugs found within this run. This does not establish correctness or complete input coverage.")
    for i, finding in enumerate(findings, 1):
        step_info = f"step {finding['failing_step'] + 1}/{finding['step_count']}"
        lines.extend([
            f"{i}. **{finding['kind']}** in `{finding['application']}` at `{finding['site']}` ({step_info})",
            "",
            f"   Replay: `{finding['replay']}`",
            "",
        ])
    lines.extend(["", "## Execution and interface inventory", ""])
    for result in report["applications"]:
        label = result.get("name") or result["path"]
        inv = ", ".join(f"{item['kind']}={item['status']}" for item in result.get("inventory", [])) or "none detected"
        extra_parts = []
        if result.get("coverage_mode") == "llvm_sancov":
            corpus_io = ""
            if result.get("corpus_loaded") or result.get("corpus_saved"):
                corpus_io = f", loaded={result.get('corpus_loaded', 0)}, saved={result.get('corpus_saved', 0)}"
            extra_parts.append(
                f"coverage=llvm_sancov (edges={result.get('first_party_edges_hit', 0)}, "
                f"corpus={result.get('corpus_size', 0)}{corpus_io}, targeted={result.get('targeted_executions', 0)}, "
                f"evolved={result.get('evolved_executions', 0)}, "
                f"frontier_untaken={result.get('frontier_branches_remaining', 0)})"
            )
        if result.get("workspace_errors"):
            extra_parts.append(f"workspace_errors={result['workspace_errors']}")
        extra = ("; " + "; ".join(extra_parts)) if extra_parts else ""
        lines.append(
            f"- `{label}` (`{result['path']}`): {result['status']}; "
            f"{result.get('executions', 0)} cases ({result.get('multi_step_executions', 0)} multi-step){extra}; "
            f"interfaces: {inv}. {result.get('reason', '')}"
        )
    frontier_rows = [
        (result.get("name") or result["path"], b)
        for result in report["applications"]
        for b in (result.get("untaken_frontier") or [])[:15]
    ]
    if frontier_rows:
        lines.extend(["", "## Untaken frontier branches", ""])
        for app_label, b in frontier_rows[:25]:
            clue_str = f" — clues: {', '.join(repr(c) for c in b['clues'])}" if b.get("clues") else ""
            lines.append(f"- `{app_label}`: `{b['path']}:{b['line']}` (`{b['kind']}`){clue_str}")
    lines.extend(["", "## Coverage gaps", ""])
    for gap in report["gaps"]:
        lines.append(f"- {gap}")
    lines.extend([
        "",
        "Only failures repeating with the same diagnostic identity and step index in two fresh-state replays are listed as bugs. "
        "Ordinary nonzero exits and unconfirmed failures are excluded. No source-line, assertion, or exhaustive interface coverage is claimed.",
        "",
    ])
    return "\n".join(lines)


def arguments(argv):
    parser = argparse.ArgumentParser(description="Explore Odin application inputs and report confirmed interface-reachable failures.")
    parser.add_argument("--version", action="version", version=f"odin-fuzz {VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("scan", "explore", "doctor"):
        p = sub.add_parser(name)
        p.add_argument("--odin")
        if name != "doctor":
            p.add_argument("project", type=Path)
            p.add_argument("--work-dir", type=Path)
            p.add_argument("--exclude", action="append", default=[], help="project-relative path to exclude from discovery and snapshot")
        if name == "explore":
            p.add_argument("--budget", type=float, default=DEFAULT_BUDGET, help="exploration seconds excluding builds and final confirmation")
            p.add_argument("--seed", type=int, default=1)
            p.add_argument("--max-cases", type=int, default=0, help="per application; 0 uses the time budget")
            p.add_argument("--timeout", type=float, default=CASE_TIMEOUT, help="seconds per process")
            p.add_argument("--corpus-dir", type=Path, help="persistent directory to load and save coverage-winning corpus cases")
    p = sub.add_parser("reproduce")
    p.add_argument("finding_directory", type=Path)
    return parser.parse_args(argv)


def main(argv=None):
    try:
        args = arguments(argv)
        if sys.platform != "darwin":
            raise ToolError("odin-fuzz supports macOS only")
        require_packaged_runtime()
        if args.command == "reproduce":
            return reproduce(args.finding_directory.resolve())
        chain = toolchain(args.odin)
        if args.command == "doctor":
            print(json.dumps(chain, indent=2))
            return 0
        project = args.project.resolve()
        if not project.is_dir():
            raise ToolError(f"project directory does not exist: {project}")
        if args.command == "explore" and (not math.isfinite(args.budget) or args.budget <= 0 or
                not math.isfinite(args.timeout) or args.timeout <= 0 or args.max_cases < 0 or args.seed < 0):
            raise ToolError("budget and timeout must be finite and positive; max-cases and seed must be nonnegative")
        work = (args.work_dir or project / ".work" / "odin-fuzz").resolve()
        corpus_dir = args.corpus_dir.resolve() if (args.command == "explore" and args.corpus_dir) else None
        settings = project_settings(project)
        excludes = [
            *settings["exclude"],
            *(normalize_relative_path(item, allow_root=False, allow_hidden=True, label="exclude path") for item in args.exclude),
        ]
        # Prevent recursive snapshotting and phantom discovery when --work-dir or --corpus-dir sits inside project.
        for label, out_dir in (("work", work), ("corpus", corpus_dir)):
            if out_dir is None:
                continue
            if out_dir == project or project.is_relative_to(out_dir):
                raise ToolError(f"{label} directory cannot contain the project")
            if out_dir.is_relative_to(project):
                excludes.append(str(out_dir.relative_to(project)))
        settings["exclude"] = list(dict.fromkeys(excludes))
        run_dir = work / "runs" / (time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8])
        run_dir.mkdir(parents=True)
        discovery = discover(project, chain, run_dir, settings)
        write_json(run_dir / "discovery.json", discovery)
        if args.command == "scan":
            print(json.dumps(discovery, indent=2))
            return 2 if any(s["error"] for s in discovery["sources"]) else 0
        sandbox_profile(run_dir)  # Fail before building targets if execution is unavailable.
        original = run_dir / "captured"
        omitted = snapshot_tree(project, original, exclude=settings["exclude"])
        environment = {**BASE_ENV, "ASAN_OPTIONS": ASAN_OPTIONS, "UBSAN_OPTIONS": UBSAN_OPTIONS}
        if chain["symbolizer"]:
            environment["ASAN_SYMBOLIZER_PATH"] = chain["symbolizer"]
        report = {
            "format_version": FORMAT_VERSION,
            "tool_version": VERSION,
            "project": str(project),
            "toolchain": chain,
            "applications": [],
            "gaps": list(discovery["limitations"]),
            "run_directory": str(run_dir),
        }
        if omitted:
            report["gaps"].append("Snapshot omitted hidden, excluded, or non-regular entries: " + ", ".join(omitted[:20]))
        for source in discovery["sources"]:
            if source["error"]:
                report["gaps"].append(f"Parse error in {source['path']}: {source['error']}")
        apps = discovery["applications"]
        if not apps:
            report["gaps"].append("No macOS application main found; identify an application package with applications[].path.")
        explorable_count = sum(
            1 for app in apps
            if not any(i["kind"] == "ui" and i["status"] == "unsupported" for i in app["inventory"])
        )
        for app in apps:
            unsupported = [i["kind"] for i in app["inventory"] if i["status"] == "unsupported"]
            nondet = [i["kind"] for i in app["inventory"] if i["status"] == "nondeterministic_gap"]
            for kind in unsupported:
                report["gaps"].append(f"{app['name']} ({app['path']}): {kind} input is inventoried without a replayable boundary adapter.")
            for kind in nondet:
                report["gaps"].append(f"{app['name']} ({app['path']}): {kind} usage has no deterministic seed/clock boundary; nondeterministic failures will be withheld.")
            # Never launch an interactive window without a replayable UI event boundary.
            if "ui" in unsupported:
                report["applications"].append({
                    "name": app["name"],
                    "path": app["path"],
                    "status": "unsupported",
                    "inventory": app["inventory"],
                    "reason": "UI interface has no replayable ui_events boundary adapter configured",
                })
                continue
            directory = run_dir / "applications" / app["id"]
            directory.mkdir(parents=True)
            initial = directory / "initial"
            shutil.copytree(original, initial, symlinks=True)
            print(f"Building application {app['name']} ({app['path']})", file=sys.stderr, flush=True)
            try:
                build_info = build_application(app, initial, chain, settings, directory)
                if build_info["coverage_mode"] == "none":
                    report["gaps"].append(f"{app['name']} ({app['path']}): coverage-guided build fell back to uninstrumented ASan build.")
                print(f"Exploring application inputs for {app['name']} ({app['path']})", file=sys.stderr, flush=True)
                result = explore_application(
                    app, initial, directory, environment,
                    args.budget / max(1, explorable_count), args.seed, args.max_cases, args.timeout,
                    build_info, chain, corpus_dir=corpus_dir,
                )
            except ToolError as error:
                result = {
                    "name": app["name"],
                    "path": app["path"],
                    "status": "infrastructure_error",
                    "inventory": app["inventory"],
                    "reason": str(error),
                }
            report["applications"].append(result)
        write_json(run_dir / "report.json", report)
        (run_dir / "report.md").write_text(report_text(report))
        has_findings = any(r.get("findings") for r in report["applications"])
        has_error = not apps or any(r["status"] != "explored" for r in report["applications"]) or any(s["error"] for s in discovery["sources"])
        status = "findings" if has_findings else ("error" if has_error else "ok")
        write_json(run_dir / "summary.json", summary_data(report, status))
        write_json(work / "latest.json", {"run_directory": str(run_dir)})
        print(f"Summary: {run_dir / 'summary.json'}")
        print(f"Report: {run_dir / 'report.md'}")
        if has_findings:
            return 1
        if has_error:
            return 2
        return 0
    except (ToolError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(f"odin-fuzz: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
