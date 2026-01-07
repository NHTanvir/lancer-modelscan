//! lancer-modelscan — Rust clone of Protect AI's modelscan, with a native GUI.
//!
//! Plain invocation opens the GUI (see [`gui`]); `--cli` (or any scan path /
//! subcommand) falls through to the CLI surface in [`cli`], which mirrors the
//! upstream `modelscan` flags plus Lancer extensions.

mod cli;

#[cfg(feature = "gui")]
mod config;
#[cfg(feature = "gui")]
mod gui;
#[cfg(feature = "gui")]
mod server;

#[cfg(feature = "net")]
mod explain;

fn main() {
    let code = cli::run();
    std::process::exit(code);
}
