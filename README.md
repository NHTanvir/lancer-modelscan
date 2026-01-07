# lancer-modelscan

A Rust clone of [Protect AI's `modelscan`](https://github.com/protectai/modelscan) — a security scanner for serialized machine-learning model files — with a native desktop GUI on top. Part of the **Lancer** toolkit, a 2026 AI-era bug-bounty suite.

Serialized model formats such as pickle, joblib, PyTorch `.pt`/`.pth`, TensorFlow SavedModel, and Keras `.h5` can execute arbitrary code the moment they are loaded. `lancer-modelscan` parses these files **without ever loading or executing them**, walks the pickle opcode stream / protobuf graph / HDF5 tree, and flags dangerous constructs (e.g. a `REDUCE` bound to `os.system`) with a severity tier and a stable, machine-readable report.

The plain `lancer-modelscan` invocation opens a native GUI window. Pass `--cli` (or use the CLI surface directly) for headless / CI use.

> **Security note:** `lancer-modelscan` is **parse-only**. It never calls `pickle.load`, `torch.load`, `import_module`, `getattr`, or any model-defined `__reduce__`. It reads and walks bytes; it does not run model content. It is safe to point at untrusted model files.

## Supported formats

| Format | Container | Code-execution surface | Handling |
|---|---|---|---|
| pickle (proto 0–5) | raw stream | every `REDUCE`/`BUILD`/`INST`/`OBJ`/`NEWOBJ` op | full parse-only opcode walk |
| joblib | pickle stream + sklearn shim | same as pickle | strip shim, delegate to pickle walker |
| dill | extended pickle | extra opcodes | extended opcode table |
| cloudpickle | extended pickle | dynamic class/function pickling | extended opcode table |
| PyTorch `.pt` / `.pth` | ZIP of `data.pkl` + tensors | pickle inside zip | list zip members, walk `data.pkl` (never unpickled) |
| TensorFlow SavedModel | protobuf GraphDef + variables | `Lambda` / `PyFunc` custom ops | protobuf graph walk |
| HDF5 / `.h5` | hierarchical dataset tree | embedded lambda source strings | dataset traversal |
| Keras `.keras` / `.h5` | HDF5 + model-config JSON | lambda layer code | HDF5 + JSON-config parse |
| ONNX `.onnx` | protobuf ModelProto | custom-domain operators | flag non-`ai.onnx` operators |
| safetensors `.safetensors` | header JSON + raw tensors | none | header parse, emitted as safe baseline |
| GGUF (`llama.cpp`) | binary header + tensors | none (metadata only) | recognized as safe-like |

## Install / build

Requirements:

- [Rust / Cargo](https://rustup.rs)
- Windows: Visual C++ Build Tools 2019/2022 (needed by some crates)
- macOS (optional): [`cargo-bundle`](https://crates.io/crates/cargo-bundle) for a `.app` bundle

### Windows

Double-click `build.bat` or run from cmd:

```
build.bat
```

Output: `build\lancer-modelscan.exe` (double-click opens the GUI).

For a packaged dist build:

```
build-windows.bat
```

Output: `dist\lancer-modelscan-windows-x86_64\bin\lancer-modelscan.exe`, plus `LICENSE` and `README.md`, ready to zip.

### Linux

```bash
./build-linux.sh
```

Output: `build/lancer-modelscan`.

### macOS

```bash
./build-mac.sh
```

Output: `build/lancer-modelscan.app` when `cargo-bundle` is installed, otherwise the bare binary at `build/lancer-modelscan`.

## Usage

### GUI (default)

Launch with no scan arguments to open the native desktop window:

```
lancer-modelscan
```

The window follows the Lancer three-pane layout — inputs/jobs on the left, a sortable findings table in the center, and a detail pane (full record, target, remediation) on the right. Drag-and-drop a file or folder onto the window, or use **File → Open**, then press **Scan**. Results can be exported to JSON, HTML, or SARIF from the **File** menu. A local cross-tool HTTP API (`127.0.0.1:<auto>`, port written to `%TEMP%/lancer-modelscan.port`) lets the Lancer mothership import/export scans.

The GUI is an alternate frontend over the same core engine the CLI uses — every CLI capability is reachable from the GUI.

### CLI

Use the CLI surface for headless / scripting / CI by passing `--cli`:

```bash
# Scan a single file
lancer-modelscan --cli scan ./model.pkl

# Scan a directory tree
lancer-modelscan --cli scan ./models/

# JSON report to a file
lancer-modelscan --cli scan ./models/ -r json -o report.json
```

#### Upstream `modelscan` parity flags

These mirror `protectai/modelscan` verbatim and work under `--cli`:

| Flag | Meaning |
|---|---|
| `-p, --path <PATH>` | File or directory to scan (a positional `<PATH>` is also accepted) |
| `-l, --log <LEVEL>` | Log level: `CRITICAL`, `ERROR`, `WARNING`, `INFO`, `DEBUG` |
| `--settings-file <FILE>` | Path to a `modelscan-settings.toml` |
| `-r, --reporting-format <FORMAT>` | `console` (default), `json`, or `custom` |
| `-o, --output-file <FILE>` | Write the report to a file instead of stdout |
| `--show-skipped` | List files skipped (filtered out) during the scan |

The `create-settings-file` subcommand writes a default `modelscan-settings.toml` into the current directory:

```bash
lancer-modelscan --cli create-settings-file          # write modelscan-settings.toml
lancer-modelscan --cli create-settings-file --force  # overwrite an existing file
```

#### Lancer extensions

Beyond upstream parity, `lancer-modelscan` adds:

| Flag | Meaning |
|---|---|
| `--ci` | Gate mode: exit non-zero when findings meet the threshold (uses the severity-mapped exit codes below) |
| `--fail-on <critical\|high\|medium\|low>` | Severity threshold used by `--ci` |
| `--include <glob>` | Only scan paths matching the glob(s) (e.g. `"*.pkl,*.pt,*.h5"`) |
| `--exclude <glob>` | Skip paths matching the glob(s) (e.g. `"tests/**,**/fixtures/**"`) |
| `--max-depth <n>` | Recursive walk depth cap (default 10) |
| `--baseline <path>` | Compare against a known-clean baseline; only *new* findings break the build |
| `--explain` | Expand each finding into a plain-language explanation |
| `--strict-parity` | Emit byte-equivalent upstream output (omit Lancer-only LOW findings and `[lancer]` extensions) |
| `--self-test` | Run the parity matrix against a bundled reference target and print pass/fail per feature group |

Example CI gate:

```bash
lancer-modelscan --cli --ci --fail-on high scan ./models/
```

## Exit codes

In upstream parity mode (`--cli`, no `--ci`), exit codes match `protectai/modelscan` numerically:

| Code | Meaning |
|---|---|
| `0` | Scan succeeded, no issues found |
| `1` | Scan succeeded, issues found |
| `2` | Scan failed with an internal error |
| `3` | No supported files found at the path |
| `4` | Invalid CLI usage (bad flags) |

In Lancer gate mode (`--ci` / `--fail-on`), the exit code maps to the maximum finding severity:

| Code | Meaning |
|---|---|
| `0` | No issues, or all issues below the threshold |
| `1` | Low+ found |
| `2` | Medium+ found |
| `3` | High+ found |
| `4` | Critical found |

## Settings and allowlist

A `modelscan-settings.toml` file controls the scan: the walk depth, scannable extensions, the allowlist of known-safe calls, per-file overrides, disabled detectors, and reporting defaults. See [`modelscan-settings.toml.example`](modelscan-settings.toml.example) for a fully-commented sample, or generate one with `lancer-modelscan --cli create-settings-file`.

The **allowlist** is how legitimate models avoid false positives. Many safe libraries use `__reduce__` for state recovery — NumPy's `ndarray`, PyTorch tensors, sklearn trees, and friends — so the default settings ship a closed set of known-safe rebuild functions. Anything outside that set is reported. A bare module name (e.g. `"torch"`) permits any member of that module; a fully-qualified `module.name` permits one call.

```toml
[allowlist]
calls = [
    "numpy.core.multiarray._reconstruct",
    "numpy.ndarray",
    "torch._utils._rebuild_tensor_v2",
    "sklearn.tree._tree.Tree",
]
# Issue ids to suppress after manual triage.
issues = ["MS-1234-abcd"]

# Per-file overrides.
[[files]]
path = "models/legacy/*.pkl"
calls = ["custom.legacy.Loader"]

[detectors]
# Disable specific detectors by id.
exclude = ["obfuscated_module"]

[reporting]
format = "json"
include_safe = true
```

Load a settings file at scan time with `--settings-file path/to/modelscan-settings.toml`. Use `--show-skipped` to surface allowlist entries that *would* have fired but were suppressed, and `--baseline` to generate an allowlist from a known-clean scan so only future findings break the build.

## License

[MIT](LICENSE) © 2026 NHTanvir.
