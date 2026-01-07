//! Command-line surface.
//!
//! Mirrors upstream `modelscan` flags verbatim (`-p/--path`, `-l/--log`,
//! `--settings-file`, `-r/--reporting-format`, `-o/--output-file`,
//! `--show-skipped`, the `create-settings-file` subcommand, upstream exit codes
//! 0/1/2/3/4) and adds Lancer extensions (`--ci`, `--fail-on`, `--include`,
//! `--exclude`, `--max-depth`, `--follow-symlinks`, `--baseline`, `--explain`,
//! `--strict-parity`, `--self-test`, `--allow-list`, html/sarif formats).

use clap::{Args, Parser, Subcommand};
use ms_core::{exitcode, ModelScan, ReportFormat, ScanOptions, Settings, Severity};
use std::io::{IsTerminal, Write};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "lancer-modelscan",
    version,
    about = "Scan serialized ML model files for unsafe code-execution risks (Rust clone of Protect AI modelscan).",
    long_about = "lancer-modelscan scans pickle / joblib / dill / cloudpickle / PyTorch / \
TensorFlow / Keras / HDF5 / ONNX files for unsafe code-execution risks, without ever \
executing them. Plain invocation opens the native GUI; pass --cli, a scan path, or a \
subcommand to use the command line."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    #[command(flatten)]
    args: ScanArgs,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Scan a file or directory for unsafe serialized-model code.
    Scan {
        /// File or directory to scan (positional). Named `target` to avoid a
        /// clap arg-id clash with the flattened `--path/-p` option below.
        target: Option<PathBuf>,
        #[command(flatten)]
        args: ScanArgs,
    },
    /// Write a default modelscan-settings.toml into the current directory.
    CreateSettingsFile {
        /// Overwrite an existing settings file.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Args, Debug, Clone, Default)]
struct ScanArgs {
    /// File or directory to scan (upstream -p/--path).
    #[arg(short = 'p', long = "path", value_name = "PATH")]
    path: Option<PathBuf>,

    /// Log level: CRITICAL, ERROR, WARNING, INFO, DEBUG.
    #[arg(short = 'l', long = "log", value_name = "LEVEL")]
    log: Option<String>,

    /// Path to a modelscan-settings.toml.
    #[arg(long = "settings-file", value_name = "FILE")]
    settings_file: Option<PathBuf>,

    /// Reporting format: console (default), json, html, sarif, custom.
    #[arg(short = 'r', long = "reporting-format", value_name = "FORMAT")]
    reporting_format: Option<String>,

    /// Write the report to FILE instead of stdout.
    #[arg(short = 'o', long = "output-file", visible_alias = "output", value_name = "FILE")]
    output_file: Option<PathBuf>,

    /// List files skipped during the scan.
    #[arg(long = "show-skipped")]
    show_skipped: bool,

    /// Append allowlist entries from a TOML file.
    #[arg(long = "allow-list", value_name = "FILE")]
    allow_list: Option<PathBuf>,

    /// Include glob(s), comma-separated (e.g. "*.pkl,*.pt").
    #[arg(long = "include", value_name = "GLOBS")]
    include: Option<String>,

    /// Exclude glob(s), comma-separated (e.g. "tests/**").
    #[arg(long = "exclude", value_name = "GLOBS")]
    exclude: Option<String>,

    /// Maximum recursive walk depth (default 10).
    #[arg(long = "max-depth", value_name = "N")]
    max_depth: Option<usize>,

    /// Follow symlinks during the walk.
    #[arg(long = "follow-symlinks")]
    follow_symlinks: bool,

    /// CI gate mode: exit non-zero (severity-mapped) on findings at/above --fail-on.
    #[arg(long = "ci")]
    ci: bool,

    /// Severity threshold for --ci: critical, high, medium, low (default: low).
    #[arg(long = "fail-on", value_name = "SEVERITY")]
    fail_on: Option<String>,

    /// Generate the allowlist from a known-clean baseline tree before scanning.
    #[arg(long = "baseline", value_name = "PATH")]
    baseline: Option<PathBuf>,

    /// Strict upstream-parity output: omit Lancer-only LOW findings.
    #[arg(long = "strict-parity")]
    strict_parity: bool,

    /// Append an LLM plain-language explanation to the report (requires the
    /// `net` feature + an API key). No-op if unavailable.
    #[arg(long = "explain")]
    explain: bool,

    /// Disable colored console output.
    #[arg(long = "no-color")]
    no_color: bool,

    /// Suppress informational logging.
    #[arg(long = "quiet")]
    quiet: bool,

    /// Verbose (DEBUG) logging.
    #[arg(long = "verbose")]
    verbose: bool,

    /// Force CLI mode (do not open the GUI).
    #[arg(long = "cli")]
    cli: bool,

    /// Run the built-in parity self-test matrix and exit.
    #[arg(long = "self-test")]
    self_test: bool,

    /// Print version as JSON and exit.
    #[arg(long = "version-json")]
    version_json: bool,
}

/// Entry point. Returns the process exit code.
pub fn run() -> i32 {
    let cli = Cli::parse();

    // Resolve the effective scan args + path across the top-level vs `scan` verb.
    let (path, args, is_create, force) = match cli.command {
        Some(Command::CreateSettingsFile { force }) => (None, cli.args, true, force),
        Some(Command::Scan { target, args }) => {
            let p = target.or_else(|| args.path.clone());
            (p, args, false, false)
        }
        None => (cli.args.path.clone(), cli.args, false, false),
    };

    init_logging(&args);

    if args.version_json {
        println!(
            "{{\"name\":\"lancer-modelscan\",\"version\":\"{}\"}}",
            env!("CARGO_PKG_VERSION")
        );
        return exitcode::OK;
    }

    if is_create {
        return create_settings_file(force);
    }

    if args.self_test {
        return self_test(&args);
    }

    // No path + not forced to CLI → open the GUI (if compiled in).
    if path.is_none() && !args.cli {
        #[cfg(feature = "gui")]
        {
            return match crate::gui::launch(None) {
                Ok(()) => exitcode::OK,
                Err(e) => {
                    eprintln!("error: GUI failed to start: {e}");
                    exitcode::INTERNAL_ERROR
                }
            };
        }
        #[cfg(not(feature = "gui"))]
        {
            eprintln!(
                "error: no PATH given. This build has no GUI; pass -p <PATH> or `scan <PATH>`."
            );
            return exitcode::INVALID_USAGE;
        }
    }

    let path = match path {
        Some(p) => p,
        None => {
            eprintln!("error: no PATH to scan. Use -p <PATH> or `scan <PATH>`.");
            return exitcode::INVALID_USAGE;
        }
    };

    run_scan(&path, &args)
}

fn init_logging(args: &ScanArgs) {
    use tracing::Level;
    let level = if args.quiet {
        Level::ERROR
    } else if args.verbose {
        Level::DEBUG
    } else {
        match args.log.as_deref().map(|s| s.to_ascii_uppercase()) {
            Some(ref l) if l == "CRITICAL" || l == "ERROR" => Level::ERROR,
            Some(ref l) if l == "WARNING" || l == "WARN" => Level::WARN,
            Some(ref l) if l == "DEBUG" => Level::DEBUG,
            Some(ref l) if l == "INFO" => Level::INFO,
            _ => Level::WARN,
        }
    };
    let _ = tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(std::io::stderr)
        .with_target(false)
        .try_init();
}

fn load_settings(args: &ScanArgs) -> Result<Settings, i32> {
    let mut settings = match &args.settings_file {
        Some(p) => match Settings::from_file(p) {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                eprintln!("error: invalid settings file {}: {e}", p.display());
                return Err(6);
            }
            Err(e) => {
                eprintln!("error: cannot read settings file {}: {e}", p.display());
                return Err(5);
            }
        },
        None => Settings::default(),
    };
    if let Some(p) = &args.allow_list {
        match std::fs::read_to_string(p) {
            Ok(text) => {
                if let Err(e) = settings.merge_allowlist_toml(&text) {
                    eprintln!("error: invalid allow-list file {}: {e}", p.display());
                    return Err(6);
                }
            }
            Err(e) => {
                eprintln!("error: cannot read allow-list {}: {e}", p.display());
                return Err(5);
            }
        }
    }
    Ok(settings)
}

fn build_options(args: &ScanArgs) -> ScanOptions {
    let split = |s: &Option<String>| -> Vec<String> {
        s.as_deref()
            .map(|v| {
                v.split(',')
                    .map(|x| x.trim().to_string())
                    .filter(|x| !x.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    };
    ScanOptions {
        include: split(&args.include),
        exclude: split(&args.exclude),
        max_depth: args.max_depth,
        follow_symlinks: args.follow_symlinks,
        strict_parity: args.strict_parity,
        baseline: args.baseline.clone(),
        show_skipped: args.show_skipped,
    }
}

fn run_scan(path: &std::path::Path, args: &ScanArgs) -> i32 {
    let settings = match load_settings(args) {
        Ok(s) => s,
        Err(code) => return code,
    };

    // Resolve report format: -r flag wins, else settings default.
    let format = ReportFormat::parse(
        args.reporting_format
            .as_deref()
            .unwrap_or(&settings.reporting.format),
    );

    let mut scanner = ModelScan::new(settings);
    scanner.set_options(build_options(args));

    let result = match scanner.scan(path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: scan failed: {e}");
            return e.exit_code();
        }
    };

    let max_sev = result.max_severity();
    let has_issues = result.has_issues();
    let found_supported = result.found_supported;

    // Render.
    let color = !args.no_color
        && matches!(format, ReportFormat::Console)
        && args.output_file.is_none()
        && std::io::stdout().is_terminal();

    let mut report = match scanner.generate_report(&format, color) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: report generation failed: {e}");
            return exitcode::INTERNAL_ERROR;
        }
    };

    if args.explain {
        report = append_explanation(&scanner, report);
    }

    if let Err(e) = emit(&report, &args.output_file) {
        eprintln!("error: failed to write report: {e}");
        return 5;
    }

    // Exit code.
    if args.ci || args.fail_on.is_some() {
        let fail_on = args
            .fail_on
            .as_deref()
            .and_then(Severity::parse)
            .unwrap_or(Severity::Low);
        exitcode::ci_code(max_sev, fail_on)
    } else {
        exitcode::upstream_code(found_supported, has_issues)
    }
}

#[cfg(feature = "net")]
fn append_explanation(scanner: &ModelScan, mut report: String) -> String {
    if let Some(result) = scanner.result() {
        match crate::explain::explain_result(result) {
            Ok(text) if !text.trim().is_empty() => {
                report.push_str("\n\n");
                report.push_str(&text);
            }
            Ok(_) => {}
            Err(e) => eprintln!("warning: --explain unavailable: {e}"),
        }
    }
    report
}

#[cfg(not(feature = "net"))]
fn append_explanation(_scanner: &ModelScan, report: String) -> String {
    eprintln!("warning: --explain requires a build with the `net` feature; ignoring.");
    report
}

fn emit(report: &str, output: &Option<PathBuf>) -> std::io::Result<()> {
    match output {
        Some(p) => std::fs::write(p, report),
        None => {
            let stdout = std::io::stdout();
            let mut lock = stdout.lock();
            lock.write_all(report.as_bytes())?;
            if !report.ends_with('\n') {
                lock.write_all(b"\n")?;
            }
            Ok(())
        }
    }
}

fn create_settings_file(force: bool) -> i32 {
    let path = std::path::Path::new("modelscan-settings.toml");
    if path.exists() && !force {
        eprintln!(
            "error: {} already exists (use --force to overwrite)",
            path.display()
        );
        return exitcode::INVALID_USAGE;
    }
    match std::fs::write(path, ms_core::DEFAULT_SETTINGS_TOML) {
        Ok(()) => {
            println!("Wrote default settings to {}", path.display());
            exitcode::OK
        }
        Err(e) => {
            eprintln!("error: failed to write {}: {e}", path.display());
            5
        }
    }
}

/// Built-in parity self-test: craft canonical fixtures and verify detection.
fn self_test(args: &ScanArgs) -> i32 {
    use std::fs;
    let dir = std::env::temp_dir().join(format!("lancer-modelscan-selftest-{}", std::process::id()));
    let _ = fs::create_dir_all(&dir);

    let mut pass = 0usize;
    let mut fail = 0usize;
    let color = !args.no_color && std::io::stdout().is_terminal();
    let ok = |c: bool| if !color {
        if c { "PASS" } else { "FAIL" }.to_string()
    } else if c {
        "\x1b[32mPASS\x1b[0m".to_string()
    } else {
        "\x1b[31mFAIL\x1b[0m".to_string()
    };

    // Fixture 1: malicious os.system pickle → expect CRITICAL.
    let mal = dir.join("malicious.pkl");
    let _ = fs::write(&mal, os_system_pickle());
    let mut s = ModelScan::with_defaults();
    let crit = s
        .scan(&mal)
        .map(|r| {
            r.all_issues()
                .iter()
                .any(|i| i.module.as_deref() == Some("os") && i.severity == Severity::Critical)
        })
        .unwrap_or(false);
    println!("{}  pickle: os.system → CRITICAL", ok(crit));
    if crit { pass += 1 } else { fail += 1 }

    // Fixture 2: numpy rebuild pickle → expect no findings (allowlisted).
    let safe = dir.join("numpy.pkl");
    let _ = fs::write(&safe, numpy_pickle());
    let mut s = ModelScan::with_defaults();
    let clean = s.scan(&safe).map(|r| !r.has_issues()).unwrap_or(false);
    println!("{}  pickle: numpy rebuild → allowlisted (no findings)", ok(clean));
    if clean { pass += 1 } else { fail += 1 }

    // Fixture 3: safetensors header → expect supported + no findings.
    let st = dir.join("model.safetensors");
    let _ = fs::write(&st, safetensors_file());
    let mut s = ModelScan::with_defaults();
    let st_ok = s
        .scan(&st)
        .map(|r| r.found_supported && !r.has_issues())
        .unwrap_or(false);
    println!("{}  safetensors: header validated → safe baseline", ok(st_ok));
    if st_ok { pass += 1 } else { fail += 1 }

    // Exit-code mapping sanity.
    let codes_ok = exitcode::upstream_code(true, false) == 0
        && exitcode::upstream_code(true, true) == 1
        && exitcode::upstream_code(false, false) == 3
        && exitcode::ci_code(Severity::Critical, Severity::High) == 4;
    println!("{}  exit-code mapping (upstream 0/1/3 + CI severity)", ok(codes_ok));
    if codes_ok { pass += 1 } else { fail += 1 }

    let _ = fs::remove_dir_all(&dir);
    println!("\nself-test: {pass} passed, {fail} failed");
    if fail == 0 { exitcode::OK } else { 1 }
}

/// Protocol-2 pickle: GLOBAL os system, TUPLE1, REDUCE, STOP.
fn os_system_pickle() -> Vec<u8> {
    let mut p = vec![0x80, 0x02];
    p.extend_from_slice(b"cos\nsystem\n");
    p.extend_from_slice(&[b'q', 0x00]);
    let arg = b"echo lancer";
    p.push(b'X');
    p.extend_from_slice(&(arg.len() as u32).to_le_bytes());
    p.extend_from_slice(arg);
    p.push(0x85); // TUPLE1
    p.push(b'R'); // REDUCE
    p.push(b'.'); // STOP
    p
}

/// Protocol-2 pickle: GLOBAL numpy.core.multiarray _reconstruct (allowlisted).
fn numpy_pickle() -> Vec<u8> {
    let mut p = vec![0x80, 0x02];
    p.extend_from_slice(b"cnumpy.core.multiarray\n_reconstruct\n");
    p.push(b'.');
    p
}

/// Minimal valid safetensors file: 8-byte LE header length + JSON object.
fn safetensors_file() -> Vec<u8> {
    let header = br#"{"__metadata__":{"format":"pt"}}"#;
    let mut out = Vec::new();
    out.extend_from_slice(&(header.len() as u64).to_le_bytes());
    out.extend_from_slice(header);
    out
}
