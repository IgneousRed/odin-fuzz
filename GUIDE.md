# Adopting `odin-fuzz` in Odin projects

Prepare target projects so `odin-fuzz` discovers entrypoints, keeps `llvm_sancov` coverage active, synthesizes valid inputs, and confirms failures identically across two fresh-state replays.

## Commands and two-stage workflow

- Check toolchain resolution first: `odin-fuzz doctor` (or `python3 odin-fuzz doctor` from a checkout).
- Inspect discovered macOS entrypoints, interfaces, and `core:odin/parser` syntax errors: `odin-fuzz scan <project> [--work-dir <dir>] [--exclude <relpath>]`.
- Run automated exploration: `odin-fuzz explore <project> --budget 30 [--corpus-dir <dir>] [--work-dir <dir>] [--exclude <relpath>] [--seed N] [--max-cases N] [--timeout 2.0] [--thread-count N]` (exit `0` ok, `1` confirmed findings, `2` config/build/parse/unsupported error; pass `--thread-count 1` per invocation to compile target apps with `-thread-count:1`).
- Stage 1 (setup and verification): inspect `<run-dir>/summary.json` (`status`, `finding_count`, `finding_dirs`, `run_directory`, `report_md`, `report_json`, and `applications[]` entries with `name`, `path`, `status`, `finding_count`, `executions`, `coverage_mode`, `first_party_edges_hit`, `corpus_loaded`, `corpus_saved`, `frontier_branches_remaining`, `ordinary_or_unclassified_exits`, `timeouts`, `workspace_errors`, `unconfirmed_withheld`), and confirm `coverage_mode == "llvm_sancov"`.
- Stage 2 (failure triage or gap review): when `finding_count > 0` or investigating gaps, inspect `<run-dir>/report.md` (confirmed failures, coverage gaps, untaken frontier branches) and `findings/<id>/` (`REPLAY.md`, `case.json`, `finding.json`, `observation-*.stderr`), and replay with `odin-fuzz reproduce <finding-dir>`.
- Reuse `--corpus-dir` across runs so sessions build on prior coverage.

## Optional `odin-fuzz.json` (project root)

- `collections`: `{name: relpath}` (merged with `ols.json`; `odin-fuzz.json` takes precedence) so first-party packages are tracked for coverage.
- `odin_flags`: accepts only `-define:`, `-microarch:`, and `-target-features:`.
- `linker_flags`: add required C libraries/frameworks so `clang` IR linking (`llvm_sancov`) succeeds instead of falling back to uninstrumented ASan.
- `exclude`: exact project-relative paths (no globs) to skip heavy/generated/non-active directories and stay under the 64 MiB / 4096-file snapshot cap (4 MiB per `.odin` file).
- `applications[]`: `{path, name?, args?, files?, env?, seed_env?, clock_env?, ui_events?, local_network?, local_ipc?}` focuses `--budget` (split evenly across explorable apps); omit `args` unless a fixed template (`{file}`, `{file2}`, `{text}`, `{events}`, `{port}`, `{socket}`, `{seed}`, `{time}`) is needed because setting `args` disables freeform `argv` mutation.
- Unknown keys, `..`/symlink escapes, orphan adapter placeholders, and `ASAN_*`/`UBSAN_*`/`DYLD_*`/`LLVM_*` env overrides are rejected.

## Target preparation

- Assert state invariants with `assert(...)` at state transitions; `odin-fuzz` builds with `-debug -sanitize:address` and ignores ordinary nonzero exits as normal input rejection.
- Reserve `assert`, `panic`, `unreachable`, and `unimplemented` for broken invariants, and do not catch or silence fatal runtime crashes or Odin's `file.odin(line:col)` stderr diagnostic.
- Always exit normally on completion, EOF, or `close: true` within `--timeout` (default `2.0s`); timeouts and abnormal exits skipping C destructors drop coverage and corpus feedback.
- For Raylib/SDL/GLFW apps, expose an opt-in headless mode reading `ui_events` JSON/JSONL (`frame`, `dt`, `keys_down`, `keys_pressed`, `mouse`, `viewport`, `close`) and declare `ui_events` (`mode`: `"file"`|`"stdin"`|`"env"`, `path`, `env`, `format`: `"json"`|`"jsonl"`, `keys`, `max_frames`: `1..256`); otherwise GUI apps are skipped as `ui=unsupported`.
- Alternatively, expose a separate headless `main` package outside `tests/`/`scripts/` to test core logic without a GUI adapter.
- Wire `seed_env` / `clock_env` (or `{seed}` / `{time}` in `args`) for any RNG or time dependency so failures repeat identically across two fresh-state replays instead of being withheld.
- For network or IPC apps, support loopback `127.0.0.1:<port>` (`local_network`: `role`, `port_env`/`host_env`) or a configurable Unix socket path (`local_ipc`: `role`, `socket_env`), set `role` to `"server"` when `odin-fuzz` listens or `"client"` when your app listens, and exit cleanly on peer `SHUT_WR` EOF.
- Model JSON/command protocols with typed Odin `enum` and `struct` definitions (within 16 fields and nesting depth 2) and name files `*.json` for schema-guided synthesis and JSON-array shrinking.
- Favor `enum` fields, discriminator names (`kind`, `type`, `action`, `command`, `op`), or command/event/request-like struct names for schema weighting, and put `json:"..."` tags on single-name field declarations (multi-name declarations fall back to Odin field names).
- Use standard Odin string `==` (tracked up to 64 bytes by `runtime::string_eq` I2S) and literal strings, ints, or `ui_events.keys` identifiers in `if`/`else`/`case` conditions so runtime I2S and AST frontier targeting flip untaken branches.
- Write CLI flags (`--flag`, `-f`) and `core:os` env/file names as string literals for automatic discovery, or list wrapped/aliased names in `applications[].env` and `applications[].files`.
- Keep minimal valid inputs and headers well under `4 KiB` (generated files/stdin/messages cap at 4096 bytes, `argv` items at 256, env values at 128) and commit at least one small (`<= 4 KiB`) valid seed file (`.json`, `.txt`, `.csv`, `.cbor`, `.odin`, `.ini`, `.toml`) per format.
- Avoid symlinks; keep runtime I/O inside relative paths, `$HOME`, or `$TMPDIR` (`LC_ALL=C`, `TZ=UTC`), avoid unconditional startup sleeps, keep file writes under 1 MiB, and write persisted state to non-hidden workspace files so multi-step runs (1–4 steps) mutate and reload it.
