# Implemented behavior

This document describes the current whole-application confirmed fuzzing implementation in this repository and its explicit limitations.

## Discovery and interface inventory

The Python orchestrator (`tools/odin_fuzz.py`) walks the project tree and invokes the Odin parser-based scanner (`src/`) in batches of up to 64 files.

Discovery rules:

1. Hidden directories, symlinked directories, `vendor`, `node_modules`, `build`, `dist`, `target`, `__pycache__`, `tests`, `scripts`, `notes`, `docs`, and configured/CLI `--exclude` paths are not traversed automatically.
2. Symlinked `.odin` files, `*_test.odin` files, configured exclusions, and files larger than 4 MiB are excluded.
3. For each `.odin` file, `src/functions/functions.odin` parses the AST via `core:odin/parser`, evaluates `#+build`/`#+ignore` file tags, detects `main :: proc` declarations (including inside `when` blocks), extracts AST branch sites (`if`, `else`, `case` header/body lines and guarding string/integer/identifier clues), extracts Odin `enum` variants and `struct` field schemas (including `json:"..."` tags), and extracts imports, interface clues (`argv`, `stdin`, `files`, `environment`, `ui`, `network`, `ipc`, `clock`, `randomness`), file-write clues (`writes_files`), string literals, env-var names, and filename literals.
4. Files marked `#+ignore` or whose `#+build` lines exclude macOS on the host architecture (comma = OR, whitespace = AND, multiple lines = AND) are recorded with `darwin_active: false` and do not contribute macOS entrypoints or interfaces.
5. Application packages are discovered automatically from macOS-active `main` packages unless explicitly listed under `odin-fuzz.json` `applications[]`. Reachable project packages are collected by following relative and collection imports.
6. Each application receives an explicit `inventory` classifying every discovered or configured interface as:
   - `driven`: automatically driven (`argv`, `stdin`, `files`, `environment`).
   - `adapter_driven`: driven via an enabled minimal boundary in `odin-fuzz.json` (`ui_events`, `local_network`, `local_ipc`, `seed_env`/`{seed}`, `clock_env`/`{time}`). Orphan `{events}`, `{port}`, or `{socket}` placeholders without their matching adapter block are rejected at config validation.
   - `unsupported`: detected without a replayable boundary (`ui`, `network`, `ipc`).
   - `nondeterministic_gap`: `clock` or `randomness` detected without a deterministic boundary; the app may still be explored, and any failure that fails to repeat identically in two fresh-state replays is withheld.

Applications with an `unsupported` UI interface are not launched (avoiding uncontrolled GUI windows) and are reported as `unsupported` with an explicit coverage gap.

## Snapshot and application build

Before exploring, `snapshot_tree` captures ordinary non-hidden files up to 64 MiB and 4096 files (without following symlinks), skipping `.git`, `.work`, `.tmp`, `__pycache__`, `node_modules`, `out`, `binaries`, `build`, `dist`, `target`, symlinks, any configured/CLI `--exclude` paths (normalized), and any `--work-dir`/`--corpus-dir` located inside the project directory. Non-hidden files in other project directories (such as `src/`, `vendor/`, `tests/`, `scripts/`, `notes/`, `docs/`, or unexcluded config/data files) are included in the snapshot and copied into finding bundles. Omitted entries are disclosed in the report's coverage gaps.

Each supported application package is compiled once inside its `initial/` snapshot directory. **`scanner`, `discover`, and `build_application` execute outside `sandbox-exec` with the inherited host environment.** Compile-time Odin features (`#load`, `foreign import`, `@(extra_linker_flags)`) and `odin-fuzz.json` `linker_flags` therefore execute with host user privileges before target sandboxing starts; `explore` is intended for trusted local projects rather than untrusted source trees. When matching LLVM `clang` is available, `build_application` builds coverage-instrumented ASan binaries via:

```sh
odin build <app-package> -debug -sanitize:address -build-mode:llvm-ir -use-single-module -out:<ir-dir> ...
clang -c -x ir <ir-dir>/*.ll -fsanitize-coverage=edge,trace-pc-guard,trace-cmp -o <mod.o>
clang <mod.o> <cov_shim.o> -fsanitize=address -o <initial>/.odin-fuzz-runtime/app
dsymutil <initial>/.odin-fuzz-runtime/app
```

If IR compilation or linking fails for a target, `odin-fuzz` falls back automatically to direct `odin build ... -debug -sanitize:address` and records a coverage gap in the report.

The compiled binary stays read-only (`0555`) under `initial/.odin-fuzz-runtime/app`, outside the mutable per-case workspace so target execution cannot overwrite its own executable and macOS does not re-verify a cloned executable inode on every case. Before assembling the emitted LLVM IR, `odin-fuzz` injects a single call to `__odin_fuzz_trace_string_eq` at the entry of Odin's `runtime::string_eq` so runtime string comparisons are recorded alongside integer `trace-cmp` operands. During exploration runs only, `ODIN_FUZZ_COV_FILE` points inside `<workspace>/.tmp/` so the coverage shim (`OFC2`) writes hit edge IDs, ASLR-adjusted (`_dyld_get_image_vmaddr_slide`) PCs, runtime `trace-cmp`/`trace-switch` operands, and runtime `runtime::string_eq` string pairs on exit; `ODIN_FUZZ_COV_FILE` is unset during confirmation replays, shrinking checks, and `odin-fuzz reproduce`. Each case clones the remaining starting files into a fresh disposable workspace (using APFS copy-on-write `cp -cPR` with `shutil.copytree` fallback). All host writes and deletions inside the disposable workspace walk directories with `O_NOFOLLOW | O_DIRECTORY` and `O_CREAT | O_EXCL | O_NOFOLLOW` so target-created symlinks, FIFOs, read-only directories, or directory collisions cannot escape the sandbox or stall host setup/cleanup.

## Evolution-guided exploration, untaken-branch targeting, and boundary drivers

Every recorded input case (`format_version: 3`) is an ordered list of 1 to 4 steps (`case.steps`) executed sequentially against one disposable workspace so files and saves written by step `k` persist into step `k + 1`.

Generation and feedback behavior:

1. **Baseline, persistent corpus (`--corpus-dir`), and seed warmup**: Step 0 runs once against untouched snapshot files to detect genuine startup bugs. When `--corpus-dir` is supplied, previously saved valid corpus cases for each application are replayed immediately after baseline to restore coverage and frontier state, and coverage-winning cases discovered during the run are persisted back on completion. Initial seed payloads follow (boundary values, discovered literals, small snapshot files, AST schema-synthesized JSON objects/arrays built from extracted Odin `enum`/`struct` types, and UI seeds).
2. **Evolution-guided corpus (`llvm_sancov`)**: First-party function address ranges are identified via `nm -n` from discovered project packages. Whenever an execution hits a new first-party CFG edge or edge-count bucket, the case is promoted into a bounded corpus (`MAX_CORPUS = 128`). Evolution selects corpus parents weighted by energy and active untaken frontier branches, applying interface-aware mutations (mutating/appending `argv`, mutating per-file bytes or AST schema-guided JSON, extending multi-step restart sequences, extending/mutating `ui_events` frame sequences, mutating stdin/env/network/IPC/seed/clock, and splicing corpus entries).
3. **Untaken-branch targeted testing (LIFO breakthrough queue)**: Whenever a case hits a genuinely new first-party edge (`new_guards`), `odin-fuzz` batch-symbolizes new PCs via `llvm-symbolizer` and immediately prioritizes targeted variants of that parent aimed at flipping untaken branches:
   - **Runtime `runtime::string_eq` I2S & dynamic string feedback**: records unmatched runtime string comparisons — including dynamically constructed strings that never appear as source literals — substitutes observed strings directly into matching input slots, injects printable runtime tokens, and feeds them into the evolutionary dictionary.
   - **Runtime `trace-cmp` / `trace-switch` input-to-state (I2S)**: inspects non-boolean unmatched runtime comparisons `(a, b)` — including values computed at runtime that never appear as source literals — and substitutes/injects target values (`v`, `v - 1`, `v + 1`) in ASCII and binary encodings across `argv`, files, stdin, env, network/IPC messages, and seed/clock.
   - **Odin AST frontier targeting & reporting**: matches hit lines against AST `Branch_Site` records whose body lines remain globally uncovered, injects guarding strings, integer thresholds, or UI key presses into the parent sequence, and reports remaining untaken frontier branches (`file.odin:line`, branch kind, and clues) in `report.md` and `report.json`. Each `explore` run also writes a compact `summary.json` alongside `report.md` and `report.json` with high-level QA status, finding counts/directories, and per-application execution/coverage metrics without raw sanitizer crash sites, stack traces, or mutated payloads.
4. **Per-file distinct payloads and multi-step sequences**: Candidate files (`input`, `input.json`, `input.odin`, safe discovered/configured filenames, and regular files dynamically created by earlier runs) each receive independently chosen or mutated payloads; multi-step sequences persist application-written files across restarts. (Recorded cases also support explicit `delete_files` entries for replay/fixtures, though the automatic generator does not currently emit random deletions.)
5. **Minimal boundary drivers**:
   - `ui_events`: generates and evolves ordered multi-frame JSON or JSONL event sequences (`frame`, `dt`, `keys_down`, `keys_pressed`, `mouse`, `viewport`, `close`) delivered via file, stdin, or env path.
   - `local_network`: binds an ephemeral disposable `127.0.0.1:<port>` TCP listener (or connects as a local client) for the duration of a step and delivers recorded byte chunks.
   - `local_ipc`: binds a disposable Unix domain socket under `<scratch>/ipc/s` (falling back to a short private temp directory when the UTF-8 byte length exceeds macOS's 104-byte `sun_path` limit) and delivers recorded byte chunks.
   - `seed_env`/`{seed}` and `clock_env`/`{time}`: supplies deterministic integer seeds and timestamps recorded per step.

## Sandbox isolation

All target executions and replays run with a sanitized base environment (`PATH=/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin`, `LC_ALL=C`, `TZ=UTC`, workspace-local `HOME` and `TMPDIR`, and sanitizer options—never inheriting the host user's `os.environ`) under macOS `/usr/bin/sandbox-exec` (with UTF-8 Seatbelt path quoting supporting non-ASCII workspace paths).

The Seatbelt profile starts from `(allow default)` and applies explicit denials:

- Denies all network access by default (`(deny network*)`).
- Denies signals targeting processes outside the sandbox (`(deny signal)` with `(allow signal (target same-sandbox))`).
- Denies reading file data (`file-read-data`) and extended attributes (`file-read-xattr`) outside the disposable workspace, read-only `initial/.odin-fuzz-runtime`, `/`, and system/Nix/Homebrew runtime directories (`/System`, `/usr`, `/bin`, `/sbin`, `/Library`, `/opt/homebrew`, `/nix/store`, `/dev`, `/private/var/db`, `/private/var/run`, `/private/etc`). Directory listing (`readdir`) outside those paths is blocked by `file-read-data`, while `file-read-metadata` remains permitted so `dyld` and `getcwd`/`realpath` can resolve ancestor paths.
- Denies all writes (`file-write*`) outside the disposable workspace and `/dev/null`.
- When `local_network` is configured, allows only `localhost:<ephemeral_port>` loopback traffic (the host fixture binds/connects on `127.0.0.1`). When `local_ipc` is configured, allows reads, writes, and Unix sockets under the disposable socket directory; in `role: "client"`, the host connector checks `lstat`/`S_ISSOCK` on the socket path before `connect` (noting macOS `connect(2)` has no `O_NOFOLLOW`, leaving a narrow kernel TOCTOU window for a racing hostile target). External network hosts remain denied.
- Because the profile uses `(allow default)`, operations not explicitly denied—including `file-read-metadata`, Mach/XPC service lookups, POSIX/SysV IPC, IOKit, `sysctl`, and reading files under the allowed system/Homebrew runtime directories—remain accessible. The sandbox is practical local containment, not a hostile-malware VM.
- Process trees run in their own session (`start_new_session=True`), with `RLIMIT_CORE = 0`, `RLIMIT_FSIZE = 1 MiB` for target runs (unlimited for compiler builds), and `SIGKILL` cleanup of the process group on exit or timeout.
- Host-side workspace writes, deletions, coverage reads (`read_coverage`), and cleanup (`safe_rmtree`) walk directories with `O_NOFOLLOW | O_DIRECTORY` to prevent target-created symlinks (including replacing `.tmp`) or read-only/special nodes from escaping the workspace.

## Failure classification, confirmation, and replay

`failure_identity` recognizes only fatal runtime diagnostics:

1. **AddressSanitizer**: `==<pid>==ERROR: AddressSanitizer:` with `SUMMARY: AddressSanitizer: <summary>` **and** configured ASan exit code (`77`) or a fatal signal (ordinary `exit(1)` printing spoofed ASan text is rejected). Exact `build_root` and workspace path prefixes and hex addresses are normalized while preserving the ASan bug class.
2. **UndefinedBehaviorSanitizer**: `SUMMARY: UndefinedBehaviorSanitizer: <summary>` with configured sanitizer exit code (`77`) or a fatal signal.
3. **Odin runtime failures on fatal signals** (`SIGABRT`, `SIGBUS`, `SIGFPE`, `SIGILL`, `SIGSEGV`, `SIGTRAP`): `file.odin(line:col)` followed by `runtime assertion`, `panic`, `runtime panic`, `not yet implemented`, `unreachable`, `Bounds check failed`, `Index ... is out of range`, `Invalid slice indices`, `Invalid matrix indices`, `Matrix indices`, `type assertion`, `Invalid type assertion`, `Invalid slice length for make`, `Invalid dynamic array parameters for make`, `Invalid map capacity for make`, or `division by zero`.

Ordinary nonzero exits, timeouts, and raw signals without a diagnostic site return no failure identity.

When a new failure identity is observed at `failing_step`, `odin-fuzz` replays the entire ordered `case` twice from fresh disposable copies of `initial/`. Only if both replays produce the exact same `identity` and `failing_step` is the finding confirmed. Confirmed findings then undergo bounded automatic input shrinking (`minimize_case`, dropping non-essential steps, files, environment entries, stdin, arguments, UI frames, or JSON array elements while preserving the exact failure identity), and any minimized case is re-confirmed across fresh-state replays before preserving the finding bundle under `runs/<run-id>/applications/<app-id>/findings/<hash>/`. Non-repeating failures are written to `diagnostics.json` and excluded from Confirmed Bugs (with up to 3 confirmation attempts per site so an earlier flaky occurrence does not permanently suppress a later deterministic one).

Each finding bundle retains `initial/` (the full captured non-hidden project snapshot plus the prebuilt Mach-O binary in `initial/.odin-fuzz-runtime/app` and its `.dSYM` debug bundle), `case.json`, `finding.json` (format version, platform, architecture, absolute `build_root`, SHA-256 + directory manifest, boundary `app_config`, recorded `environment` including `ASAN_SYMBOLIZER_PATH`, timeout, identity, failing step), per-observation per-step stdout/stderr logs, and `REPLAY.md` (with absolute host replay paths). Review bundle contents—especially snapshotted project files, logs, DWARF paths, and `finding.json`/`REPLAY.md` host paths—before sharing externally. `odin-fuzz reproduce <finding-dir>` validates `finding.json` metadata (`timeout`, `environment`, `app_config`, `failing_step`, `identity`), rejects symlink or non-regular `finding.json`, `case.json`, `replay/`, and any symlink or special node inside `initial/`, and verifies the `initial/` and `case.json` manifest against `finding.json` before executing the prebuilt binary in a fresh disposable copy. This detects drift or partial tampering of `initial/` or `case.json` relative to `finding.json`; it is not a cryptographic signature against rewriting `finding.json` and the prebuilt executable together, so untrusted finding bundles must be treated like untrusted native executables.

## Source map

| Location | Responsibility |
| --- | --- |
| `odin-fuzz` | Python command entry point. |
| `tools/odin_fuzz.py` | Toolchain discovery, configuration validation, discovery orchestration, snapshotting, ASan builds, sandboxed single/multi-step execution, boundary drivers, confirmation, finding bundles, replay, and reports. |
| `src/main.odin` | Odin scanner entry point. |
| `src/effects/effects.odin` | Scanner file reading and JSON output. |
| `src/functions/functions.odin` | Pure Odin AST/token inspection and interface/literal extraction. |
| `src/state/state.odin` | Scanner metadata types. |
| `tests/test_odin_fuzz.py` | Behavior-level verification fixtures covering discovery, assertions, ASan UAF, bounds checks, unreachable internal counterexamples, multi-step stateful sequences, `ui_events`, `local_network`, `local_ipc`, deterministic seed/clock, sandbox enforcement, and tamper rejection. |

## Known limitations

1. Discovery is syntax/import-based, not a whole-program call graph; aliased, foreign, or vendored input reads can be missed.
2. Upstream `core:odin/parser` can occasionally reject syntax accepted by the Odin compiler (for example, an inline statement immediately following `{` in a `for` loop header); such files are disclosed as parse-error coverage gaps rather than silently ignored.
3. Coverage-guided evolution and untaken-branch targeting use SanitizerCoverage (`trace-pc-guard`, `trace-cmp`), runtime `runtime::string_eq` instrumentation, and Odin AST branch/schema extraction; full SMT/symbolic constraint solving and multi-worker `--jobs N` execution are not yet implemented.
4. Delivery timing across socket/stdin streams is bounded but not real-time deterministic; failures sensitive to wall-clock scheduling may be withheld as unconfirmed.
5. System libraries and the installed LLVM/ASan sanitizer runtime remain host dependencies during replay.
