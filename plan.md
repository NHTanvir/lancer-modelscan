# RESEARCH DOSSIER: ModelScan

> Part of the Lancer ecosystem. A Rust clone of Protect AI's ModelScan — serialized ML model security scanner. Build with Claude Code.
> Upstream: github.com/protectai/modelscan (Python, Apache-2.0, 0.x line — currently 0.8 → 1.0). Maintained by Protect AI / now part of Palo Alto Networks AI security stack.

## Feature Parity Mandate

**`lancer-modelscan` MUST ship with 100% feature parity to the upstream `modelscan` tool — every flag, every subcommand, every output format, every probe / detector / module / payload / mode — plus a native Rust GUI on top.** This is not a "subset clone" — this is a full reimplementation in Rust with a GUI wrapper.

### Parity contract

- **Every CLI flag** documented in upstream `modelscan --help` (and the long-form man page / docs) must work in `lancer-modelscan --cli`.
- **Every output format** the upstream tool emits (text, JSON, XML, CSV, SARIF, custom formats) must round-trip through `lancer-modelscan` byte-equivalent where the format allows.
- **Every probe / detector / module / category / payload class / built-in script** must be ported. None silently dropped.
- **Every supported target type / input format / protocol / file format / language** must work.
- **Every configuration option** (config files, env vars, registry / settings entries) must be honoured.
- **Companion binaries / sub-tools** in the upstream suite (if any) must each get their own binary in this workspace.

### GUI on top

Every feature reachable via CLI is also reachable from the GUI (see `## GUI (Lancer-standard pattern)` below). The GUI is not a subset — it is an alternate frontend over the same `core` library that the CLI uses. The `core` crate is GUI-agnostic.

### Verification

- The `## Granular feature catalog` section below enumerates everything that must be supported.
- Reference: `tests/upstream_parity/` will pin upstream flag combinations + canned outputs as parity tests. CI fails if any flag is unsupported or output diverges.
- A `lancer-modelscan --self-test` flag runs the full parity matrix against a bundled reference target and prints pass/fail per upstream feature group.

### What is allowed to diverge

- **Performance** — Rust-native, async-first; we are allowed to be faster.
- **Memory footprint** — we are allowed to be smaller.
- **GUI** — entirely new (no upstream GUI to copy except where the upstream ships its own GUI like Zenmap / Wireshark UI / Ghidra GUI / jadx-gui — in which case our GUI must cover every panel the upstream GUI has, plus the Lancer-standard layout from `## GUI` below).
- **AI augmentation** — net-new (see `## AI augmentation ideas`).

### What is NOT allowed to diverge

- Any flag silently dropped, renamed, or behavior-changed compared to upstream.
- Any output format / record schema diverging in field names, types, or semantics.
- Any built-in script / detector / module not ported (mark explicitly with `[N/A — see note]` if genuinely impossible in Rust, e.g. NSE Lua scripts requiring features not in `mlua`).

## What it actually does

ModelScan scans serialized ML model files for **unsafe code execution risks**. The core problem it solves: pickle — Python's most common serialization format — allows arbitrary code execution on `pickle.load()`. The same holds for joblib, dill, and cloudpickle, all of which sit on top of pickle. A malicious model file silently runs `os.system("rm -rf /")` or curls a reverse shell the moment a data scientist opens it. PyTorch `.pt`/`.pth` files are zipped pickles, so they inherit the same risk. TensorFlow's `Lambda` layer embeds raw Python source inside HDF5/SavedModel containers — also arbitrary code. Keras `.h5`/`.keras` files do the same.

ModelScan parses these formats **without executing them**, walks the opcode stream / proto graph / HDF5 dataset tree, identifies dangerous opcodes (`REDUCE`, `BUILD`, `INST`, `OBJ`, `NEWOBJ`, `STACK_GLOBAL`) bound to risky module/name pairs (`os.system`, `subprocess.Popen`, `__builtin__.eval`, `posix.system`, `nt.system`, `socket.socket`, `commands.getoutput`, `runpy._run_code`, `pty.spawn`, `webbrowser.open`), and flags them with a severity tier. It also enumerates HDF5-embedded lambda strings, TensorFlow custom ops sitting outside the safelist domain, and ONNX custom-domain operators.

Supported formats:
- **pickle** (protocols 0-5) — flagged when risky
- **joblib** — pickle wrapper for sklearn models
- **dill** / **cloudpickle** — extended pickle, same risk
- **PyTorch `.pt` / `.pth`** — ZIP-of-pickle (since PyTorch 1.6)
- **TensorFlow SavedModel** — protobuf GraphDef + variables; lambda nodes flagged
- **HDF5 / `.h5`** — embedded lambda layer source strings
- **Keras `.keras` / `.h5`** — same as HDF5
- **ONNX** — flagged only on custom-domain operators (metadata is code-relevant)
- **safetensors** — used as the **safe baseline reference**; never flagged

The companion tool to MLflow / Hugging Face Hub workflows: "scan-before-load." Output is JSON, HTML, or console-friendly; exit code maps to max severity, so CI gates work out of the box.

## Internal architecture

**Workspace** (`Cargo.toml`):
```
[workspace]
members = ["lancer-modelscan", "ms-core", "ms-formats", "ms-detectors", "ms-report"]
```

- **`lancer-modelscan`** — CLI binary (clap 4.x). Parses args, picks scan vs CI-gate vs interactive mode, dispatches to `ms-core`.
- **`ms-core`** — Orchestrator: file enumeration (recursive directory walk + globs), format sniffing (magic-byte + extension), allowlist merge from `modelscan.toml`, severity-to-exit-code mapping, deterministic Issue ordering.
- **`ms-formats`** — Format-specific parsers. Each implements `Parser` trait yielding a stream of suspicious-call **events**. One module per format:
  - `pickle.rs` — opcode walker (no execution, no `pickle.load`)
  - `joblib.rs` — delegates to `pickle.rs` after sklearn wrapper strip
  - `dill.rs`, `cloudpickle.rs` — same delegation with extended opcode table
  - `pytorch.rs` — ZIP extractor → pickle walker on each `.pkl` member
  - `tensorflow.rs` — protobuf GraphDef walker
  - `keras.rs` — HDF5 reader + lambda string extractor
  - `hdf5.rs` — generic HDF5 walker (dataset traversal)
  - `onnx.rs` — onnx-pb reader, flag custom domain
  - `safetensors.rs` — read-only header parse, always emits "safe"
- **`ms-detectors`** — Detector layer. Consumes the event stream from a parser, scores each event against the allowlist, produces an `Issue { severity, location, opcode, target, message }`.
- **`ms-report`** — JSON / HTML (via `tera` templates) / console emitters.

**Key modules in `ms-core/src/`:**
- `ctx.rs` — `ScanContext { allowlist, settings, results }` shared across parsers.
- `walker.rs` — Recursive directory walker (`ignore` crate), glob filters (`globset`), skip-list (`*.bin`, `*.txt`, etc.).
- `sniff.rs` — Format detection: magic bytes (`PK\x03\x04` → ZIP/PyTorch, `\x89HDF` → HDF5, `\x08\x01` proto tag → ONNX, pickle protocol header → pickle), with extension fallback.
- `allowlist.rs` — Per-issue / per-call permits, parsed from `modelscan.toml`.
- `exitcode.rs` — `Critical→4`, `High→3`, `Medium→2`, `Low→1`, `None→0`.

**Parser trait** (`ms-formats/src/lib.rs`):
```rust
pub trait Parser: Send + Sync {
    fn id(&self) -> &str;
    fn can_handle(&self, path: &Path, magic: &[u8]) -> bool;
    fn parse(&self, reader: &mut dyn Read) -> Result<Vec<Event>, ParseError>;
}

pub struct Event {
    pub opcode: Option<PickleOpcode>,
    pub target_module: Option<String>,
    pub target_name: Option<String>,
    pub raw_string: Option<String>,   // for HDF5/Keras lambda source
    pub graph_op: Option<String>,     // for TF/ONNX custom op
    pub offset: u64,
    pub stack_depth: usize,
}
```

**How detectors plug in:**
1. Each detector is a Rust struct implementing `Detector`:
```rust
pub trait Detector: Send + Sync {
    fn id(&self) -> &str;
    fn evaluate(&self, event: &Event, allowlist: &Allowlist) -> Option<Issue>;
}
```
2. Default detectors: `risky_call`, `unknown_import`, `suspicious_reduce`, `obfuscated_module`, `tf_custom_op`, `onnx_custom_domain`, `keras_lambda_layer`.
3. `define_detectors!` macro registers each one at compile time.
4. `ms-core` iterates the detector list per event (parallelized with `rayon` across files, sequential within a file to keep offsets ordered).

**Pickle opcode walker** is the heart of the project. It's a parse-only state machine that reads each opcode byte, pushes/pops the simulated stack with `Varnode`-like markers (`GLOBAL("os","system")`, `STR("rm -rf /")`, `MARK`, `TUPLE(...)`), and emits an event whenever a `REDUCE`/`BUILD`/`INST`/`OBJ`/`NEWOBJ` consumes a `GLOBAL` from the stack. No `__reduce__` is ever invoked. The walker tolerates malformed pickles (bounded depth, bounded total opcodes).

## Granular feature catalog

**Supported formats** (with risk model):

| Format | Container | Code-execution surface | ModelScan handling |
|---|---|---|---|
| pickle (proto 0-5) | raw stream | every `REDUCE`/`BUILD`/`INST`/`OBJ`/`NEWOBJ` op | full opcode walk |
| joblib | pickle stream w/ sklearn shim | same as pickle | strip shim, delegate |
| dill | extended pickle | extra opcodes (`DILL_*`) | extended table |
| cloudpickle | extended pickle | dynamic class/function pickling | extended table |
| PyTorch `.pt` / `.pth` | ZIP of `data.pkl` + tensors | pickle inside zip | unzip without unpickling, walk |
| TensorFlow SavedModel | protobuf GraphDef + variables/ | `Lambda`/`PyFunc` custom ops | proto walk via prost |
| HDF5 / `.h5` | hierarchical dataset tree | embedded lambda source strings | HDF5 dataset traversal |
| Keras `.keras` / `.h5` | HDF5 with model config JSON | lambda layer code | HDF5 + JSON-config parse |
| ONNX `.onnx` | protobuf ModelProto | custom-domain operators | onnx-pb walk, flag non-`ai.onnx` ops |
| **safetensors `.safetensors`** | header-only JSON + raw tensors | **none** | read header, emit "safe" baseline |
| GGUF (`llama.cpp`) | binary header + tensors | none (metadata only) | flagged as "safe-like" (low priority) |

**Pickle opcodes flagged** (the dangerous set, by stack effect):
- `REDUCE` (`R`) — pops `(callable, args)`, calls `callable(*args)` on load
- `BUILD` (`b`) — pops `(obj, state)`, calls `obj.__setstate__(state)` if defined
- `INST` (`i`) — `INST modname classname` — instantiate `modname.classname`
- `OBJ` (`o`) — like INST but uses MARK/stack
- `NEWOBJ` (`\x81`) — pops `(cls, args)`, calls `cls.__new__(cls, *args)`
- `NEWOBJ_EX` (`\x92`) — `NEWOBJ` with kwargs
- `STACK_GLOBAL` (`\x93`) — pops `(modname, name)` → push `getattr(import(modname), name)`
- `GLOBAL` (`c`) — `GLOBAL modname\nname\n` → push global
- `EXT1/EXT2/EXT4` — copyreg extension code lookup
- `PERSID` / `BINPERSID` — persistent ID hook (`persistent_load`)

**Risky module/name pairs** (default list, allowlist-overridable):
- `os.system`, `os.popen`, `os.execvp`, `os.spawnl`
- `subprocess.Popen`, `subprocess.run`, `subprocess.call`, `subprocess.check_output`
- `builtins.eval`, `builtins.exec`, `builtins.compile`, `builtins.__import__`, `builtins.open`
- `posix.system`, `nt.system`
- `socket.socket`, `socket.create_connection`
- `commands.getoutput`, `commands.getstatusoutput`
- `runpy._run_code`, `runpy._run_module_code`
- `pty.spawn`
- `webbrowser.open`
- `shutil.rmtree`, `shutil.copy`
- `pickle.loads`, `pickle.load`, `marshal.loads`, `marshal.load`
- `dill.loads`, `cloudpickle.loads`
- `importlib.import_module`, `importlib.__import__`
- `ctypes.CDLL`, `ctypes.WinDLL`
- `code.InteractiveInterpreter`, `code.compile_command`

**CLI flags** (`lancer-modelscan`):
- `scan <file|dir>` — primary verb
- `--reporting-format <json|html|console>` (default: `console`)
- `--show-skipped` — list files that were filtered out
- `--settings-file <path>` — load `modelscan.toml` from non-default location
- `--allow-list <path>` — append allowlist entries
- `--max-depth <n>` — recursive walk depth
- `--include <glob>`, `--exclude <glob>` — filter patterns
- `--ci` — gate mode: exit non-zero on severity threshold
- `--fail-on <critical|high|medium|low>` — threshold for CI
- `--no-color`, `--quiet`, `--verbose`
- `--output <path>` — write report to file (else stdout)

**Upstream `modelscan` parity flags** (must be supported verbatim by `lancer-modelscan --cli` / Lancer's CLI surface, mirroring `protectai/modelscan` v0.8.x exactly):
- `-h, --help` — help text
- `-v, --version` — version (also `--version-json`)
- `-p, --path <PATH>` — file or directory to scan (mirror upstream's `-p`; we also accept positional `<PATH>`)
- `-l, --log <LEVEL>` — log level: `CRITICAL`, `ERROR`, `WARNING`, `INFO`, `DEBUG` (Python `logging` levels)
- `--settings-file <FILE>` — path to `modelscan-settings.toml` (NOT `modelscan.toml` — match upstream filename exactly)
- `-r, --reporting-format <FORMAT>` — `console` (default), `json`, or `custom` (custom = use a `modelscan.reporting.*` module path from settings)
- `-o, --output-file <FILE>` — write report to file (alias of `--output`)
- `--show-skipped` — list files skipped during scan
- `create-settings-file` — **subcommand** (not a flag): writes a default `modelscan-settings.toml` into the current directory. Must be a top-level subcommand like `lancer-modelscan create-settings-file [--force]`.

**Upstream exit codes** (must mirror `protectai/modelscan` numerically — do NOT re-map to severity tiers):
- `0` — scan succeeded, no issues found
- `1` — scan succeeded, issues found
- `2` — scan failed with internal error
- `3` — no supported files found at path (path was valid but contained nothing scannable)
- `4` — invalid CLI usage (bad flags)

> **NOTE: divergence from our internal `Critical→4, High→3, Medium→2, Low→1` mapping above.** Upstream's exit codes are binary (issues / no issues) with operational error codes 2/3/4. Our `--ci` / `--fail-on` flag, which is a Lancer extension, uses our internal severity-mapped codes; in pure `--cli` parity mode we must emit the upstream 0/1/2/3/4 codes verbatim.

**Upstream Python API parity** (the `core` crate must expose an equivalent Rust API consumable from FFI / PyO3 bindings shipped as `lancer-modelscan-py`):
```python
from modelscan.modelscan import ModelScan
from modelscan.settings import DEFAULT_SETTINGS

scanner = ModelScan(settings=DEFAULT_SETTINGS)
results = scanner.scan("/path/to/model.pkl")

scanner.issues.all_issues             # list of Issue
scanner.issues.group_by_severity()    # {Severity: [Issue]}
scanner.generate_report()             # str / dict / file write per reporter
```
Rust mirror: `ms_core::ModelScan::new(settings).scan(path) -> ScanResult` with `.issues().all()`, `.issues().group_by_severity()`, `.generate_report()`.

**Exit codes**:
- `0` — no issues, or all issues below threshold
- `1` — Low+ found
- `2` — Medium+ found
- `3` — High+ found
- `4` — Critical found
- `>=10` — internal error (5: I/O, 6: parse failure, 7: config invalid)

**Severity tiers**:
- **CRITICAL** — direct call to known exec/system/eval primitives (`os.system`, `subprocess.Popen`, `builtins.eval`, `builtins.exec`)
- **HIGH** — unknown / unlisted module-name pair on a `REDUCE`/`NEWOBJ` (bypasses allowlist); custom TF op outside known-safe domains; Keras lambda layer with non-trivial body
- **MEDIUM** — suspicious `__reduce__` pattern: a class whose `__reduce__` returns a non-builtin callable, or whose target lives in `__main__`
- **LOW** — obfuscated module name (e.g., constructed via `chr(111)+chr(115)` then resolved), short ONNX custom op without metadata

**Upstream severity taxonomy (parity-required exact lists from `protectai/modelscan` v0.8.x `unsafe_globals` table):**

- **CRITICAL — globals that can execute arbitrary code at unpickle time:**
  - `exec`, `eval`, `compile`, `getattr`, `open`, `breakpoint`
  - `os` (any submember), `posix`, `nt`
  - `subprocess` (any submember)
  - `socket`
  - `pickle` (any submember — `pickle.loads`, `pickle.load`)
  - `pdb` (debugger drops to interactive prompt → arbitrary code)
  - `runpy`, `sys`
  - `asyncio` (added in 0.8.2 — `asyncio.create_subprocess_exec` etc.)
  - `_pickle` (C-accelerated alias, added in 0.8.5)
- **HIGH — globals that cannot directly execute code but can be weaponized (exfil / file I/O / network):**
  - `webbrowser`
  - `httplib`, `http.client`
  - `requests.api`
  - `aiohttp.client`
  - TensorFlow `ReadFile`, `WriteFile` ops (SavedModel side)
- **MEDIUM — globals/ops neither in the parent ML library's known-safe set nor in ModelScan's known list:**
  - Keras `Lambda` layer (any body — represents arbitrary code surface)
  - Unknown custom TF ops outside the safelist
  - Unknown ONNX custom-domain operators
- **LOW** — currently empty in upstream 0.8.x. Reserved for future low-confidence findings (obfuscated module names, dead-code suspect reductions). `lancer-modelscan` may populate LOW with our extra heuristics under a `[lancer]` extension namespace, but the upstream `--reporting-format json` output must omit LOW entries when run in strict parity mode (`--strict-parity`).

> The default `unsafe_globals` table is replicated in `ms-detectors/src/defaults.rs` and pinned by a parity test that reads upstream's `modelscan/settings.py` and asserts set-equality.

**Allowlist** (`modelscan.toml`):
```toml
[allowlist]
# permit specific calls outright
calls = [
    "numpy.core.multiarray._reconstruct",
    "numpy.ndarray",
    "collections.OrderedDict",
    "torch._utils._rebuild_tensor_v2",
    "torch._utils._rebuild_parameter",
    "torch.nn.parameter.Parameter",
    "sklearn.tree._tree.Tree",
]

# permit by issue ID (after a manual triage)
issues = ["MS-1234-abcd", "MS-1234-efgh"]

# per-file overrides
[[files]]
path = "models/legacy/*.pkl"
calls = ["custom.legacy.Loader"]

[detectors]
exclude = ["obfuscated_module"]

[reporting]
format = "json"
include_safe = true
```

**Recursive directory scanning** — by default `lancer-modelscan scan ./models/` walks the tree, applying include/exclude globs, capped at `--max-depth` (default 10). Symlinks not followed unless `--follow-symlinks`.

**Glob filters** — `--include "*.pkl,*.pt,*.h5"`, `--exclude "tests/**,**/fixtures/**"`. Powered by `globset`.

## Engineering hard parts

**1. Pickle opcode walking without execution.** The walker must simulate pickle's stack machine *exactly* — every push/pop, mark stack, memo dict, frame opcodes (proto 4+), persistent-id callbacks — without ever calling `getattr`, `import_module`, or `__reduce__`. Each `GLOBAL`/`STACK_GLOBAL` pushes a *symbolic* `Varnode::Global(mod, name)` rather than a resolved object. When `REDUCE` pops `(callable, args)`, the detector inspects the symbolic callable. The walker must handle: `PROTO`, `FRAME`, `MEMOIZE`, `PUT`/`GET` (memo), `MARK`/`POP_MARK`, `BININT*`, `BINUNICODE*`, `SHORT_BINSTRING`, `LIST`/`EMPTY_LIST`/`APPENDS`, `DICT`/`EMPTY_DICT`/`SETITEMS`, `TUPLE*`, `STOP`. Reference: CPython's `Lib/pickletools.py` `genops()` — that's the parse-only generator we mirror in Rust.

**2. Distinguishing legit vs malicious `__reduce__`.** Many legit classes use `__reduce__` for state recovery: NumPy's `ndarray.__reduce__` returns `(numpy.core.multiarray._reconstruct, ...)`, PyTorch's `Tensor.__reduce__` returns `(torch._utils._rebuild_tensor_v2, ...)`, sklearn trees return `(sklearn.tree._tree.Tree, ...)`. The default allowlist ships with the closed-set of known-safe rebuild functions across NumPy, PyTorch, TensorFlow, sklearn, scipy, pandas, xgboost, lightgbm, catboost. Anything outside that set is reported as HIGH ("unknown reduce target"). Users append project-specific entries.

**3. HDF5 lambda-string extraction without TensorFlow runtime.** Keras stores `Lambda` layer functions as marshalled Python code objects, then base64-encodes the bytes into a JSON string under `model_config['config']['layers'][i]['config']['function']`. Detection path: open HDF5 (`hdf5` crate), read `model_config` attribute on root group, parse the JSON, locate any layer with `class_name == "Lambda"`, decode `function` field, hand the marshal bytes to a marshal walker (similar shape to pickle walker — also parse-only). Flag CRITICAL if the marshal disassembly references known-bad globals.

**4. TensorFlow GraphDef walking for custom ops.** SavedModel format: top-level directory with `saved_model.pb` (protobuf), `variables/`, `assets/`. We use `prost` to deserialize `SavedModel` → `MetaGraphDef` → `GraphDef` → `NodeDef`. For each `NodeDef`, inspect `op` (the op name) and `attr["f"]` (function name). Flag any op not in the TF builtin set (`tf.keras.layers.*` + `tf.nn.*` + ~2000 stable ops), and any `PyFunc` / `EagerPyFunc` node — these embed Python tokens.

**5. ONNX custom-domain detection.** ONNX `ModelProto.graph.node[].domain` defaults to `""` (== `ai.onnx`). Anything in `com.microsoft`, `org.pytorch`, custom-anything, or arbitrary user domains can ship runtime ops a user-supplied runtime may execute. Flag MEDIUM with op name + domain.

**6. PyTorch zip format extraction without unpickling.** Since PyTorch 1.6, `torch.save(model, "x.pt")` writes a ZIP archive containing `data.pkl` (the pickle) plus `data/<id>` raw tensor binaries plus `version`. We use the `zip` crate to *list* members, then open `data.pkl` as a `Read` and hand it to the pickle walker — never to `torch.load`. Older `.pt` files (pre-1.6) are raw pickles; sniff by checking for `PK\x03\x04` magic.

**7. Reporting reproducibility.** Multi-issue files must produce stable diffs across runs (important for CI gate noise). Solutions: (a) sort `Issue` by `(file_path, byte_offset, detector_id, target)` before emission, (b) lock to UTC timestamps in JSON, (c) optionally pin `git_commit` of the scan tool in the report header. The `tera`-rendered HTML report uses a fixed iteration order.

**8. Memory-bounded pickle walking.** Adversarial pickles can blow up: `LONG_BINUNICODE` with 4GB length, `MARK` stacks of millions, infinite `PUT`/`GET` cycles. Walker enforces: max stack depth 10k, max memo entries 100k, max single-string length 16MB, max total opcodes 10M. Above any cap, emit a HIGH "bomb" finding and bail.

**9. Distinguishing TensorFlow constants from code.** GraphDef `Const` ops carry raw tensor data inside `attr["value"].tensor`. We must skip these (huge, code-irrelevant) without holding the bytes in RAM. `prost` lets us defer-read with `MessageRead` impls.

**10. Allowlist UX.** Allowlists snowball over time, drift from reality, become rubber-stamp lists. Mitigations: (a) `--show-skipped` lists every entry that *would* have fired but was suppressed, (b) `--baseline <path>` mode lets you generate an allowlist *from a known-clean scan* — only future *new* findings break the build, (c) report includes per-allowlist-entry hit count to prune dead entries.

## Rust library mapping

| Need | Crate | Notes |
|---|---|---|
| Pickle parsing (safe) | `serde-pickle` | Read-only; we use the opcode iterator, not the value deserializer |
| HDF5 reading | `hdf5` (via libhdf5 FFI) or `hdf5-metno` (pure-Rust subset) | `hdf5-metno` covers Keras model_config attribute |
| TensorFlow protobuf | `prost` + hand-vendored `.proto` files from tensorflow/core | Or `tensorflow-protos-rs` if maintained |
| ONNX protobuf | `onnx-pb` or `onnx-protobuf` | `prost`-generated; `tract-onnx` ships the schemas too |
| ZIP container (PyTorch) | `zip` | Lock to read-only path |
| safetensors header parse | `safetensors` | Read-only; only header JSON is touched |
| GGUF parse (low-priority) | `gguf-rs` (early stage) | Or hand-roll header |
| Marshal walker (Keras lambda) | hand-roll over `marshal` opcodes | ~300 LOC; mirrors `dis.dis` |
| CLI | `clap` | v4.x |
| Glob filtering | `globset`, `ignore` | Used by `ripgrep` |
| Magic-byte sniffing | `infer` | Fallback to manual prefix checks |
| Templating (HTML report) | `tera` | Or `askama` to match Aderyn |
| JSON output | `serde_json` | Standard |
| TOML config | `toml` | Standard |
| Parallelism | `rayon` | Per-file parallel scan |
| Errors | `eyre` + `thiserror` | Standard |
| Logging | `tracing` + `tracing-subscriber` | Standard |
| Async (HTTP fetch for HF models) | `tokio` + `reqwest` | Only for `--fetch-url` mode |

## Bug bounty workflows

**1. Hugging Face model supply-chain.** A target uses Hugging Face Hub models in production (`transformers`, `diffusers`, or any custom `AutoModel.from_pretrained()` call). Download the model artifact (`pytorch_model.bin`, `model.safetensors`, custom `*.pkl`), run `lancer-modelscan scan ./downloaded/`, and report any CRITICAL/HIGH pickle finding as a supply-chain risk against the target. If they pin `revision=main` (mutable), this is exploitable end-to-end via a HF account compromise.

**2. CI gate for ML projects.** Any ML project in scope (production training pipeline, MLflow registry, internal model repo): get a pre-merge job to run `lancer-modelscan --ci --fail-on high` on every PR that touches a model artifact. PRs that introduce unsafe pickle get blocked. Auditors who can introduce this gate often surface dormant unsafe pickles that count as findings.

**3. Private ML registry audit.** Targets with internal model registries (MLflow, Weights & Biases artifacts, Neptune, custom S3 buckets). Authorized scan of the registry catches: legacy `pickle.dump(model)` artifacts, third-party model imports from Kaggle / GitHub, models contributed by departing employees. Often produces a SEV-3-level "supply-chain hygiene" deliverable.

**4. Vendor safety claim verification.** Vendor markets a model as "safe to load." Scan it with `lancer-modelscan`, find unsafe `__reduce__`, ship a PoC that pops a calc on `pickle.load`. Marketing-claim mismatch is a real-world report category.

**5. Combined with §44 MCP Server Scanner.** ML-agent supply chain: an MCP server backed by an LLM that internally loads a downstream model. ModelScan the model layer; MCP-scan the agent layer. Chain becomes "MCP tool call → model load → arbitrary code → host compromise."

**6. Open-source ML repo audits.** Random Kaggle notebook ships `model.pkl` in the repo. Public, easy bounty targets for responsible disclosure to academic / hobbyist projects; harder targets are ML startups with public model zoos.

**7. Triage workflow.** Run `lancer-modelscan scan ./target --reporting-format json --output report.json`. Filter by CRITICAL/HIGH. Reproduce the unsafe load in a sandbox (`docker run --rm python:3.12 python -c "import pickle; pickle.load(open('x.pkl','rb'))"`) with `strace` to capture the actual syscall. Attach trace + PoC + remediation ("use safetensors") to bug report.

## 2024-2026 state

- **ModelScan 0.5 → 0.8 (2024).** Initial release in 2023 by Protect AI. Added joblib, dill, cloudpickle in 0.6. Added TensorFlow SavedModel + Keras in 0.7. CI exit codes formalized in 0.8.
- **ModelScan 0.8 → 1.0 (2025-2026).** Stable allowlist schema, baseline-diff mode, JSON-schema'd reports for SARIF-style ingestion. MLflow plugin integration. Hugging Face Hub server-side scanning preview (HF runs ModelScan + Picklescan + custom checks on every uploaded file).
- **safetensors adoption surge (2024-2025).** Hugging Face flipped the default for `transformers.save_pretrained` to safetensors. New models pushed to the Hub since mid-2024 default to safetensors. Legacy `pytorch_model.bin` (pickle) still everywhere in long-tail repos.
- **PyTorch `.pt` security PSA (2024).** PyTorch team published an advisory: `torch.load` is unsafe. New `weights_only=True` flag in PyTorch 2.1, default-on in 2.6 (mid-2025). Adversarial pickles still possible via allowed globals; `weights_only` provides defense-in-depth, not certainty.
- **Hugging Face's "scan-before-load" warning.** Auto-banner on Hub model cards when a file fails Protect AI's scan. Drives upstream adoption.
- **Transformers library safe-mode.** `from_pretrained(use_safetensors=True)` enforces no pickle path. 2025 mainline default.
- **GGUF format (llama.cpp).** Binary header + tensor data, no executable surface. Effectively safe-by-construction; ModelScan adds GGUF in 0.9 as a "safe-baseline" recognizer.
- **MLflow integration.** MLflow 3.x ships a `modelscan` plugin. Registered models get scanned on registration; failed scans block deployment.
- **NIST AI RMF + EU AI Act pressure.** Compliance frameworks require artifact supply-chain attestation. ModelScan output is a common SBOM-style attachment.
- **Picklescan, Fickling, ModelScan, Hugging Face Picklescan-pro — converging.** The three open-source tools (picklescan from mmaitre314, fickling from Trail of Bits, ModelScan from Protect AI) cross-pollinate detector rules. Trail of Bits' `fickling` ships a deeper symbolic interpreter; ModelScan ships better multi-format reporting; picklescan is the lightest.
- **2026 outlook.** ONNX Runtime sandboxing proposals; Hugging Face "verified models" badge; mandatory scan-on-upload at major model registries.

## AI augmentation ideas

**1. Plain-language explanations.** For each flagged event, an LLM expands "REDUCE → os.system bound at offset 0x1f2" into "This model file, when loaded, will execute the shell command stored at the GLOBAL push. The exact command isn't visible without further analysis, but the binding to `os.system` makes this almost certainly malicious." Ships as `--explain` flag in CLI.

**2. Safe-alternative suggester.** For every CRITICAL pickle finding, LLM proposes the migration: "replace `pickle.dump(model, f)` with `safetensors.torch.save_file(model.state_dict(), 'x.safetensors')`" — with the actual code patch. Format-specific: TF → `tf.saved_model.save` with explicit signature; Keras → strip lambda layers.

**3. False-positive vs true-positive classifier across batch.** Across N findings, send context (target, file metadata, allowlist neighborhood) to LLM, ask for triage label. Auto-suppress at threshold; the rest go to human reviewer. Especially useful on a 10k-file scan of a private registry.

**4. Per-project allowlist from observed-clean baseline.** Point ModelScan at a known-clean directory (`baseline/`), let LLM cluster the seen calls into safe groups ("all numpy rebuild functions", "all torch rebuilds", "all sklearn-tree rebuilds"), emit a deduplicated `modelscan.toml` allowlist. Beats hand-writing one.

**5. Risk-report summarization for security review.** Take JSON report with 200 findings across 50 files, produce a one-page exec summary: "3 files contain CRITICAL `os.system` calls (likely backdoored), 17 contain unknown `__reduce__` targets needing manual review, 30 contain dead-code remnants from a deprecated training pipeline." Plus suggested remediation order.

**6. Adversarial-test corpus generator.** Given the live allowlist, LLM proposes evasion payloads ("module name obfuscated via `chr()` chain", "double-pickle wrapper", "ONNX custom op piggyback"). Run them through ModelScan, confirm coverage gaps.

**7. Hugging Face model-card cross-check.** Given a HF model URL, LLM reads the model card claims ("safetensors-only, no pickle"), then ModelScan verifies. Mismatch → finding.

**8. Conversational triage.** Chat panel in Lancer UI: "What's in `flagged_model.pkl`?" → LLM with parser output + allowlist context responds with severity, target, suggested action.

## Implementation phases (8-week roadmap)

**Week 1 — Workspace + pickle MVP.** Cargo workspace (`lancer-modelscan`, `ms-core`, `ms-formats`, `ms-detectors`, `ms-report`). Pickle opcode table + parse-only walker (mirror `pickletools.genops`). Default risky-module table. Console report. Test against known-good (numpy ndarray) + known-bad (eval payload from picklescan test fixtures).

**Week 2 — joblib + dill + cloudpickle.** Extended opcode tables, sklearn wrapper strip for joblib. Test fixtures from each upstream project.

**Week 3 — PyTorch zip + sniffing.** ZIP-container handling, magic-byte sniffer, file enumeration via `ignore` walker, glob filters. Test against torchvision pretrained ResNet50 (`.pth`).

**Week 4 — HDF5 + Keras lambda extraction.** Wire `hdf5-metno`, model_config JSON parser, marshal-bytecode walker for lambda functions. Test against `MobileNetV2.h5`.

**Week 5 — TensorFlow SavedModel.** Vendor `.proto` files from tensorflow/core, prost compile, GraphDef walk, custom op detection. Test against `efficientnet/saved_model.pb`.

**Week 6 — ONNX + safetensors baseline.** `onnx-pb` integration, custom-domain detector, safetensors header parse. Comparison report mode ("this file is safe").

**Week 7 — CI gate + allowlist + reports.** `--ci`, `--fail-on`, exit-code mapping. `modelscan.toml` parser. JSON + HTML report (Tera). Deterministic ordering tests.

**Week 8 — Allowlist editor / baseline mode + polish.** `--baseline` mode generates allowlist from clean scan. `--explain` flag with LLM client (optional). MLflow plugin shim. Packaging via `build.bat` / `build-linux.sh`.

---

## GUI (Lancer-standard pattern)

`lancer-modelscan` ships as a **native GUI application** by default. The CLI surface listed in `## Granular feature catalog` is still available behind a `--cli` flag (or via the `lancer-modelscan-cli` companion binary), but the **plain `lancer-modelscan` invocation opens a native desktop window**, matching every other tool in the Lancer ecosystem. No terminal-only mode.

### Framework

Pure-Rust GUI stack — no JavaScript, no Node, single static binary:

| Crate | Role |
|-------|------|
| `eframe` | Cross-platform window + event loop wrapper around `egui` |
| `egui` | Immediate-mode UI widgets (panels, tables, forms, menus, drag-and-drop) |
| `egui_extras` | Sortable tables, image loaders, syntax highlighting, date pickers |
| `egui_plot` | Charts, graphs, timelines (histograms, activity meters, progress) |
| `rfd` | Native file/folder pickers (open file, save dialog) |
| `directories` | Per-OS config dir (`~/.config/lancer-modelscan/`, `%APPDATA%\lancer-modelscan\`, etc.) |
| `image` | Screenshot / preview rendering inside egui |
| `arboard` | Clipboard read/write for "copy result" actions |
| `muda` | Native menu bar (Linux / macOS / Windows) |
| `egui-notify` | Toast notifications |

Optional dark/light theme persisted to `lancer-modelscan-config.json` via `serde_json`.

### Window layout

Three-pane layout matching the Lancer mothership GUI:

```
┌─────────────────────────────────────────────────────────────────────┐
│  File   Tools   Settings   Help                              [≡]    │
├──────────┬────────────────────────────────────────┬─────────────────┤
│          │                                        │                 │
│  Inputs  │           Main view                    │  Detail pane    │
│  / jobs  │  (table of results / source tree /     │  (full record / │
│  / scope │   findings list / packet list / etc.)  │   bytes / src / │
│          │                                        │   remediation)  │
│          │                                        │                 │
├──────────┴────────────────────────────────────────┴─────────────────┤
│  Status: idle           Items: 0          [Open]  [Run]  [Export]   │
└─────────────────────────────────────────────────────────────────────┘
```

- **Left sidebar (200-300px)** — inputs / queued jobs / scope / target list. Drag-and-drop accepted.
- **Center pane (flexible)** — primary result view appropriate to the tool (table for findings, tree for hierarchical data, code editor for source).
- **Right pane (300-400px, collapsible)** — full detail of the currently-selected item.
- **Top menu bar** — File (Open / Save / Export / Recent / Quit), Tools (per-tool actions), Settings (theme, fonts, integrations), Help (About / Docs).
- **Bottom status bar** — current activity, item counts, primary action buttons.

### Cross-tool integration with Lancer + the other 29 clones

Every Lancer-clone GUI exposes a small local HTTP server on a port auto-allocated at launch (`127.0.0.1:<port>`, written to `%TEMP%/lancer-modelscan.port`):

- The main Lancer GUI discovers running tools by scanning `%TEMP%/lancer-*.port` and lists them in its sidebar.
- Right-clicking any item in any tool can "Send to <other Lancer tool>" — the receiving tool fetches the payload via its own HTTP endpoint.
- A future "Lancer Hub" tray shell can launch / focus any of the 30 GUIs from one menu.
- HTTP endpoints exposed:
  - `GET  /v1/state` — current jobs / progress
  - `POST /v1/import` — accept a target / file / record from another Lancer tool
  - `GET  /v1/export?format=json|csv|sarif|markdown` — pull the current result set in a portable format

### Async work + responsiveness

- Long-running scans run on a Tokio task pool; the GUI thread only renders.
- Progress propagates via `crossbeam::channel` from worker → UI.
- A `Stop` button cancels in-flight work via a `CancellationToken`.
- All file I/O / network I/O / subprocess work goes through async channels — the egui thread never blocks.

### Build output

The existing `build.bat` / `build-windows.bat` / `build-linux.sh` already produce a single binary. With `eframe` linked, the same binary is the GUI app.

- Windows: `build\lancer-modelscan.exe` (double-click opens the GUI window).
- Linux: `build/lancer-modelscan` (also installable as a `.desktop` entry via `build-linux.sh --install`).
- macOS: `build/lancer-modelscan` (bundled into `lancer-modelscan.app` via `cargo-bundle` in the `build-mac.sh` companion).

For CI / headless / scripting, pass `--cli` to fall through to the CLI surface from `## Granular feature catalog`.

## Build Setup (Lancer-standard pattern)

This clone follows the same build pattern as the main Lancer project — single `.exe` output via `build.bat` on Windows, `.so/elf` via `build-linux.sh` on Linux.

### Project layout

```
lancer-modelscan/
├── Cargo.toml              # single-crate Rust project
├── Cargo.lock              # committed (binary, not library)
├── src/
│   └── main.rs             # entry point (scaffold)
├── build.bat               # Windows build → build/lancer-modelscan.exe
├── build-windows.bat       # Windows packaged dist build → dist/lancer-modelscan-windows-x86_64/
├── build-linux.sh          # Linux build → build/lancer-modelscan
├── .gitignore              # plan.md (local-only) + target/ + build/ + dist/
├── README.md               # public-facing (pushed to GitHub)
└── plan.md                 # this file (gitignored — local blueprint, never pushed)
```

### Build commands

**Windows (double-click `build.bat`):**
```
build.bat
```
Produces `build\lancer-modelscan.exe`. Pauses at end so the window stays open.

**Windows (packaged dist):**
```
build-windows.bat
```
Produces `dist\lancer-modelscan-windows-x86_64\bin\lancer-modelscan.exe` plus LICENSE/README — ready to zip.

**Linux / macOS:**
```bash
./build-linux.sh
```
Produces `build/lancer-modelscan`.

### Requirements
- Rust toolchain (https://rustup.rs)
- Windows: Visual C++ Build Tools 2019/2022 (needed by some crates)

### CI

The build pattern is intentionally identical across Lancer and all 19 clones, so a single Jenkins/GitHub Actions matrix can build everything by calling `build-windows.bat` or `build-linux.sh` per repo.
