# lancer-modelscan — Claude Code guide

## Build commands

```
build.bat                          # Windows → build\lancer-modelscan.exe
build-linux.sh                     # Linux   → build/lancer-modelscan
build-mac.sh                       # macOS   → build/lancer-modelscan[.app]
cargo build --release              # bare cargo
cargo build -p lancer-modelscan-py # PyO3 bindings (needs Python toolchain)
```

**Do not run the build** unless the user explicitly asks — this project is Windows-primary and builds are user-triggered.

Test:
```
cargo test --workspace             # all unit + integration tests
cargo test -p ms-formats           # single crate
```

## Workspace layout

Six crates — dependency order bottom-up:

| Crate | Role |
|---|---|
| `ms-formats` | Parse-only format parsers. Defines `Event`, `Parser` trait, `ParseError`, `PickleOpcode`, `Limits`. The pickle walker (`pickle::walk`) is the core — symbolic stack machine, never executes. |
| `ms-detectors` | `Severity`, `Issue`, `Detector` trait, `Allowlist`, `defaults` (unsafe_globals + safe-rebuild table). 7 detectors via `define_detectors!`. |
| `ms-report` | `ScanReport` + console/json/html(Tera)/SARIF emitters. |
| `ms-core` | `ModelScan`, `ScanResult`, `Settings`, walker/sniff/scan pipeline (rayon), `exitcode`. |
| `lancer-modelscan` | Binary: `cli.rs` (clap), `gui.rs` (egui 0.29), `server.rs` (tiny_http), `explain.rs` (Claude API). GUI/net are default features; `--cli` forces headless. |
| `lancer-modelscan-py` | PyO3 0.22 bindings; excluded from `default-members`. |

## Architecture

- **Parse-only**: nothing in this codebase calls `pickle.load`, `torch.load`, `import_module`, `getattr`, or any `__reduce__`. Parsers only read and walk bytes.
- **Event flow**: `Parser::parse_path` → `Vec<Event>` → `Detector::evaluate` (per event, per detector) → `Vec<Issue>` → `ScanReport::render`.
- **Contracts** live in `ms-formats/src/lib.rs` (`Event`, `Parser`, `ParseError`, `PickleOpcode`) and `ms-detectors/src/lib.rs` (`Issue`, `Severity`, `Detector`, `Allowlist`). Do not change these without updating all callers.
- **Sniff order** in `ms-core/src/sniff.rs` is intentional: safetensors → gguf → pytorch → keras → hdf5 → **tensorflow before onnx** (both match `0x08` magic; TF claims `.pb` by name first) → joblib/dill/cloudpickle → pickle (last-resort fallback).
- **Exit codes**: two schemes — upstream parity (`0/1/2/3/4`) for plain `--cli` use, and Lancer severity-mapped (`0-4`) for `--ci/--fail-on`. Both live in `ms-core/src/exitcode.rs`.
- **Deterministic output**: issues are sorted by `(file_path, source, offset, detector, module, name)` and deduped by stable `MS-xxxx-yyyy` id (SHA-256-derived) before emission.

## Key files

- `ms-formats/src/pickle.rs` — the symbolic pickle stack machine (protocols 0–5). Bomb limits: max 10k stack depth, 100k memo entries, 16 MB strings, 10M opcodes.
- `ms-detectors/src/defaults.rs` — the upstream-parity `UNSAFE_GLOBALS` table and `SAFE_REBUILD_CALLS` allowlist seed. Parity tests pin this against `protectai/modelscan`.
- `ms-core/src/settings.rs` — `DEFAULT_SETTINGS_TOML` (written by `create-settings-file`) and `Settings::build_allowlist()`.
- `lancer-modelscan/src/cli.rs` — all upstream parity flags (`-p/-l/--settings-file/-r/-o/--show-skipped`, `create-settings-file` subcommand) plus Lancer extensions.

## Dependencies pinned (workspace)

- egui/eframe **0.29** — `ComboBox::from_id_salt` (renamed from `from_id_source` in 0.29); clipboard via `output_mut(|o| o.copied_text = …)` (NOT `ctx.copy_text()`, which only exists from 0.31).
- clap **4** derive — the `scan` subcommand uses `target: Option<PathBuf>` (not `path`) to avoid arg-id collision with the flattened `--path/-p` option.
- pyo3 **0.22** — uses `Bound` API; `use pyo3::prelude::*` brings `PyModuleMethods` into scope.
- zip **2** — `ZipWriter`/`SimpleFileOptions`/`CompressionMethod::Stored` available without feature flags.

## Conventions

- No AI attribution in commit messages (global CLAUDE.md rule).
- All installs/new files go on `D:\` (global rule).
- Comments only when the WHY is non-obvious. No docstring blocks on obvious functions.
- Parse-only invariant: any code that reads a model file must never call anything that could execute it. If adding a new format parser, add a `can_handle` check and delegate heavy lifting to the existing `pickle::walk` or `protobuf::ProtoReader`.
