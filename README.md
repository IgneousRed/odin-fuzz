# odin-fuzz

First-party automated integration and invariant testing for Odin applications on macOS. Point it at an Odin project directory (with optional boundary configuration in `odin-fuzz.json`); it compiles each application with `-debug -sanitize:address`, explores single-step and ordered multi-step inputs across real application interfaces in disposable workspaces, and reports only failures that repeat identically across two fresh-state replays.

Ongoing maintenance and compatibility are not promised.

## Scope and finding model

`odin-fuzz` drives whole-application inputs through real interfaces: CLI arguments, standard input, environment variables, files (including state persisted across invocations), and—when declared in `odin-fuzz.json`—frame/UI event streams (`ui_events`), disposable local loopback connections (`local_network`), disposable local Unix-socket IPC (`local_ipc`), and deterministic seed/clock inputs. Standalone library API testing is outside scope.

Only failures that reproduce with the exact same diagnostic identity and failing step across two fresh-state replays are reported as confirmed findings. Normal rejection of invalid input (ordinary nonzero exit codes), timeouts, and non-repeating failures are excluded and recorded in `diagnostics.json`. Unsupported or nondeterministic interfaces remain visible as coverage gaps; zero findings does not establish correctness or exhaustive coverage.

## Requirements and setup

One-time system prerequisites (no third-party Python packages, credentials, sibling checkouts, or pre-existing caches required):

1. **macOS 26+ (`aarch64-darwin`)** with `/usr/bin/sandbox-exec`. Apple Silicon macOS is the only supported host platform.
2. **Nix** (with flakes enabled) to provide the locked **Odin** (`dev-2026-11a:9a6991685`), matching **LLVM 23.1.6** (`clang`, `llvm-symbolizer`, `dsymutil`, `llvm-nm`), and **Python 3.15.2** toolchain via `nix/llvm23/`.

```sh
nix run . -- doctor
```

Consumers install or run the canonical Nix package (`packages.<system>.default` / `apps.<system>.default` / `lib.mkOdinFuzz`), which ships an immutable prebuilt scanner (`libexec/odin-fuzz-scan`) and exposes a single `odin-fuzz` executable locked to its pinned Nix `ODIN`, `ODIN_FUZZ_SCANNER`, and matching LLVM tools. Direct unpackaged checkout execution, ambient/Homebrew tool or scanner fallbacks, and environment substitutions all fail closed.

## Usage

```sh
python3 odin-fuzz doctor
python3 odin-fuzz scan /path/to/project
python3 odin-fuzz explore /path/to/project --budget 30
python3 odin-fuzz reproduce /path/to/finding-directory
```

- `doctor` prints the resolved `odin`, `odin_report`, `symbolizer`, `clang`, `dsymutil`, and `nm` paths.
- `scan` inspects macOS-active Odin sources, inventories application packages and interfaces, and writes `discovery.json`.
- `explore` snapshots the project, builds each supported application with `-debug -sanitize:address`, evolves single-step and multi-step inputs using SanitizerCoverage (`edge,trace-pc-guard,trace-cmp`), runtime `runtime::string_eq` feedback, and Odin AST branch/schema extraction, confirms and shrinks failures across fresh-state replays, and writes:
  - `summary.json`: high-level QA metrics and run/finding paths (`status`, `finding_count`, `finding_dirs`, and per-app counts) for automated verification.
  - `report.md` and `report.json`: confirmed findings, interface inventory, coverage gaps, and remaining untaken frontier branches.
  - `findings/<id>/`: self-contained finding bundles with `REPLAY.md`, `case.json`, `finding.json`, captured snapshot, and step logs.
- `reproduce` verifies a finding bundle's manifest and replays its recorded step sequence in a fresh disposable workspace.

Common options:

- `--odin /path/to/odin` (or `ODIN` env var): select the Odin compiler.
- `--work-dir /path/to/output`: override output root (defaults to `<project>/.work/odin-fuzz/`).
- `--corpus-dir /path/to/corpus`: persistent directory on `explore` to load prior coverage-winning cases and save newly discovered cases.
- `--exclude <relpath>` (repeatable on `scan`/`explore`): exclude a project-relative file or directory without editing the target project.
- `--budget SECONDS` (default `30`), `--seed N` (default `1`), `--max-cases N` (`0` uses `--budget`), `--timeout SECONDS` (default `2.0` per step).

| Exit code | Meaning |
| --- | --- |
| `0` | Completed with all discovered applications explored, no parse errors, and no confirmed findings within the budget. |
| `1` | `explore` confirmed one or more interface-reachable failures; `reproduce` reproduced the recorded failure at the recorded step. |
| `2` | Configuration, toolchain, discovery/parse, build, unsupported-application, or replay verification problem. |

## Project adoption and documentation

- See [GUIDE.md](GUIDE.md) for the self-contained target adoption checklist, minimal `odin-fuzz.json` reference, and two-stage verification/triage workflow.
- See [docs/behavior.md](docs/behavior.md) for architecture details, sandbox containment boundaries, replay verification, finding-bundle sharing notes, and known limitations. Only run `odin-fuzz` on trusted projects.

## Development verification

Run verification commands through the canonical Nix launcher (`scripts/dev`), which realizes the locked toolchain into `.work/nix/environment`:

```sh
scripts/dev odin check src -vet -vet-tabs -vet-using-param -vet-nil-deref -vet-uninitialized -vet-atomic-access -strict-style -warnings-as-errors -vet-unused-procedures -vet-packages:src,effects,functions,state -strict-style-packages:src,effects,functions,state
scripts/dev python3 -m unittest -v tests/test_odin_fuzz.py
```

Before every commit, run the read-only dependency freshness check (reports available upstream updates without mutating locks; fails on network errors):

```sh
scripts/check-deps
```

## License

Licensed under the [Zero-Clause BSD License](LICENSE).
