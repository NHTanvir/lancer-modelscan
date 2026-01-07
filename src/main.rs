//! lancer-modelscan
//! Rust clone of modelscan. See plan.md (local, gitignored) for the spec.

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "lancer-modelscan", version, about = "Rust clone of modelscan")]
struct Cli {}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let _cli = Cli::parse();
    println!("lancer-modelscan - scaffold ready. Implement per plan.md.");
    Ok(())
}
