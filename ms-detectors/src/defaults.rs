//! Default detection data: the upstream-parity `unsafe_globals` table, the
//! known-safe rebuild-function set (used to seed the default allowlist), and
//! the TensorFlow / ONNX builtin-op references.
//!
//! Pinned by `tests/upstream_parity` against `protectai/modelscan`'s
//! `settings.py`. See plan §"Upstream severity taxonomy".

use crate::Severity;

/// One row of the unsafe-globals table. `name == "*"` matches any attribute of
/// the module.
#[derive(Debug, Clone, Copy)]
pub struct GlobalRule {
    pub module: &'static str,
    pub name: &'static str,
    pub severity: Severity,
}

const C: Severity = Severity::Critical;
const H: Severity = Severity::High;

/// Builtins names that execute / escalate at unpickle time (CRITICAL).
/// Applied to both `builtins` (py3) and `__builtin__` (py2).
pub const BUILTIN_CRITICAL_NAMES: &[&str] = &[
    "eval",
    "exec",
    "execfile",
    "compile",
    "getattr",
    "open",
    "breakpoint",
    "__import__",
    "apply",
    "input",
    "globals",
    "locals",
    "vars",
    "memoryview",
];

/// The unsafe-globals table. Modules with `"*"` flag *any* member.
///
/// CRITICAL = arbitrary code execution at unpickle time.
/// HIGH     = cannot directly exec but can exfiltrate / do file or network I/O.
pub const UNSAFE_GLOBALS: &[GlobalRule] = &[
    // ---- CRITICAL: direct code execution ----
    GlobalRule { module: "os", name: "*", severity: C },
    GlobalRule { module: "posix", name: "*", severity: C },
    GlobalRule { module: "nt", name: "*", severity: C },
    GlobalRule { module: "subprocess", name: "*", severity: C },
    GlobalRule { module: "socket", name: "*", severity: C },
    GlobalRule { module: "pickle", name: "*", severity: C },
    GlobalRule { module: "_pickle", name: "*", severity: C },
    GlobalRule { module: "cPickle", name: "*", severity: C },
    GlobalRule { module: "marshal", name: "*", severity: C },
    GlobalRule { module: "runpy", name: "*", severity: C },
    GlobalRule { module: "sys", name: "*", severity: C },
    GlobalRule { module: "asyncio", name: "*", severity: C },
    GlobalRule { module: "pty", name: "*", severity: C },
    GlobalRule { module: "commands", name: "*", severity: C },
    GlobalRule { module: "pdb", name: "*", severity: C },
    GlobalRule { module: "bdb", name: "*", severity: C },
    GlobalRule { module: "code", name: "*", severity: C },
    GlobalRule { module: "codeop", name: "*", severity: C },
    GlobalRule { module: "importlib", name: "*", severity: C },
    GlobalRule { module: "operator", name: "attrgetter", severity: C },
    GlobalRule { module: "operator", name: "methodcaller", severity: C },
    GlobalRule { module: "operator", name: "itemgetter", severity: H },
    GlobalRule { module: "functools", name: "reduce", severity: H },
    GlobalRule { module: "timeit", name: "*", severity: C },
    GlobalRule { module: "torch", name: "load", severity: C },
    GlobalRule { module: "torch.serialization", name: "load", severity: C },

    // ---- HIGH: exfiltration / network / file I/O ----
    GlobalRule { module: "webbrowser", name: "*", severity: H },
    GlobalRule { module: "httplib", name: "*", severity: H },
    GlobalRule { module: "http", name: "*", severity: H },
    GlobalRule { module: "http.client", name: "*", severity: H },
    GlobalRule { module: "urllib", name: "*", severity: H },
    GlobalRule { module: "urllib.request", name: "*", severity: H },
    GlobalRule { module: "urllib2", name: "*", severity: H },
    GlobalRule { module: "ftplib", name: "*", severity: H },
    GlobalRule { module: "telnetlib", name: "*", severity: H },
    GlobalRule { module: "smtplib", name: "*", severity: H },
    GlobalRule { module: "requests", name: "*", severity: H },
    GlobalRule { module: "requests.api", name: "*", severity: H },
    GlobalRule { module: "aiohttp", name: "*", severity: H },
    GlobalRule { module: "aiohttp.client", name: "*", severity: H },
    GlobalRule { module: "shutil", name: "*", severity: H },
    GlobalRule { module: "ctypes", name: "*", severity: H },
    GlobalRule { module: "cffi", name: "*", severity: H },
    GlobalRule { module: "tempfile", name: "*", severity: H },
    GlobalRule { module: "pathlib", name: "*", severity: H },
    GlobalRule { module: "glob", name: "*", severity: H },
    GlobalRule { module: "shelve", name: "*", severity: H },
    GlobalRule { module: "dbm", name: "*", severity: H },
];

/// Severity for a `module.name` global, or `None` if not in the unsafe table.
pub fn severity_for(module: &str, name: &str) -> Option<Severity> {
    // builtins names
    if module == "builtins" || module == "__builtin__" {
        if BUILTIN_CRITICAL_NAMES.contains(&name) {
            return Some(Severity::Critical);
        }
    }
    let mut best: Option<Severity> = None;
    for rule in UNSAFE_GLOBALS {
        if rule.module == module && (rule.name == "*" || rule.name == name) {
            best = Some(match best {
                Some(b) if b >= rule.severity => b,
                _ => rule.severity,
            });
        }
    }
    best
}

/// Known-safe rebuild / reconstruct functions across the major ML libraries.
/// These seed the default allowlist; anything *outside* this set bound to a
/// REDUCE/NEWOBJ is reported HIGH ("unknown reduce target"). See plan §2.
pub const SAFE_REBUILD_CALLS: &[&str] = &[
    // numpy
    "numpy.core.multiarray._reconstruct",
    "numpy.core.multiarray.scalar",
    "numpy._core.multiarray._reconstruct",
    "numpy._core.multiarray.scalar",
    "numpy.ndarray",
    "numpy.dtype",
    "numpy.core.numeric._frombuffer",
    "numpy.random._pickle.__randomstate_ctor",
    "numpy.random._pickle.__bit_generator_ctor",
    "numpy.random._pickle.__generator_ctor",
    // python stdlib containers commonly seen in legit pickles
    "collections.OrderedDict",
    "collections.defaultdict",
    "collections.Counter",
    "collections.deque",
    "_codecs.encode",
    // torch
    "torch._utils._rebuild_tensor",
    "torch._utils._rebuild_tensor_v2",
    "torch._utils._rebuild_tensor_v3",
    "torch._utils._rebuild_parameter",
    "torch._utils._rebuild_parameter_with_state",
    "torch._utils._rebuild_sparse_tensor",
    "torch._utils._rebuild_meta_tensor_no_storage",
    "torch._utils._rebuild_qtensor",
    "torch._utils._rebuild_device_tensor_from_numpy",
    "torch.nn.parameter.Parameter",
    "torch.storage._load_from_bytes",
    "torch.FloatStorage",
    "torch.DoubleStorage",
    "torch.HalfStorage",
    "torch.LongStorage",
    "torch.IntStorage",
    "torch.ShortStorage",
    "torch.CharStorage",
    "torch.ByteStorage",
    "torch.BoolStorage",
    "torch.BFloat16Storage",
    "torch.storage.TypedStorage",
    "torch.storage.UntypedStorage",
    "torch.device",
    // sklearn
    "sklearn.tree._tree.Tree",
    "sklearn.linear_model._base.LinearRegression",
    "sklearn.preprocessing._data.StandardScaler",
    // scipy
    "scipy.sparse._csr.csr_matrix",
    "scipy.sparse.csr.csr_matrix",
    "scipy.sparse._csc.csc_matrix",
    // pandas
    "pandas.core.frame.DataFrame",
    "pandas.core.series.Series",
    "pandas.core.internals.blocks.new_block",
    "pandas._libs.internals._unpickle_block",
    // gradient-boosted trees
    "xgboost.core.Booster",
    "xgboost.sklearn.XGBClassifier",
    "xgboost.sklearn.XGBRegressor",
    "lightgbm.basic.Booster",
    "lightgbm.sklearn.LGBMClassifier",
    "lightgbm.sklearn.LGBMRegressor",
    "catboost.core.CatBoost",
    "catboost.core.CatBoostClassifier",
    "catboost.core.CatBoostRegressor",
];

/// ONNX domains that are *builtin* (not custom). Anything else is flagged.
pub const ONNX_BUILTIN_DOMAINS: &[&str] = &[
    "",
    "ai.onnx",
    "ai.onnx.ml",
    "ai.onnx.training",
    "ai.onnx.preview.training",
];

/// Is this ONNX domain a builtin (safe) domain?
pub fn is_onnx_builtin_domain(domain: &str) -> bool {
    ONNX_BUILTIN_DOMAINS.contains(&domain)
}

/// Severity for a TensorFlow `NodeDef.op`. `PyFunc`/`EagerPyFunc` embed Python
/// → CRITICAL; `ReadFile`/`WriteFile` are file I/O → HIGH. Everything else is
/// treated as safe here (unknown custom-op heuristics live in the detector).
pub fn tf_op_severity(op: &str) -> Option<Severity> {
    match op {
        "PyFunc" | "PyFuncStateless" | "EagerPyFunc" => Some(Severity::Critical),
        "ReadFile" | "WriteFile" | "MatchingFiles" => Some(Severity::High),
        _ => None,
    }
}

/// A conservative set of well-known safe TF op prefixes/names. Used by the
/// `tf_custom_op` detector to decide whether an op is "known". This is not the
/// full ~2000-op stable set; the detector flags MEDIUM for anything that is
/// neither here nor explicitly dangerous, matching upstream's "unknown op"
/// behavior.
pub fn is_tf_known_op(op: &str) -> bool {
    const KNOWN: &[&str] = &[
        "Const", "Placeholder", "Identity", "VariableV2", "VarHandleOp",
        "ReadVariableOp", "AssignVariableOp", "MatMul", "BiasAdd", "Add", "AddV2",
        "Sub", "Mul", "Div", "RealDiv", "Relu", "Relu6", "Sigmoid", "Tanh",
        "Softmax", "Conv2D", "DepthwiseConv2dNative", "MaxPool", "AvgPool",
        "Reshape", "Squeeze", "ExpandDims", "Pad", "Mean", "Sum", "Max", "Min",
        "Cast", "Shape", "StridedSlice", "ConcatV2", "Pack", "Unpack", "Fill",
        "Range", "Transpose", "BatchMatMulV2", "FusedBatchNormV3", "NoOp",
        "Merge", "Switch", "Enter", "Exit", "NextIteration", "LoopCond",
        "StatefulPartitionedCall", "PartitionedCall", "Func", "Select", "Where",
    ];
    KNOWN.contains(&op) || op.starts_with("_")
}
