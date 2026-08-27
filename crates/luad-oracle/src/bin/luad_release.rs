//! Maintainer CLI for a local, non-promoting release packaging dry run.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use luad_oracle::release_package::package_clean_workspace;

#[derive(Debug, Parser)]
#[command(
    name = "luad-release",
    about = "Assemble and verify a local non-promoting luad release archive",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Build, package, verify, extract, and smoke one host-platform archive.
    Package {
        /// Clean luad repository revision to package.
        #[arg(long)]
        repository: PathBuf,

        /// Exact release platform: linux-x86_64 or macos-aarch64.
        #[arg(long)]
        platform: String,

        /// New or empty output directory for archive sidecars.
        #[arg(long = "output-dir")]
        output_dir: PathBuf,
    },
}

fn run() -> Result<(), String> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Package {
            repository,
            platform,
            output_dir,
        } => {
            let result = package_clean_workspace(&repository, &platform, &output_dir)?;
            let json = serde_json::to_string_pretty(&result)
                .map_err(|error| format!("serialize package result: {error}"))?;
            println!("{json}");
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("luad-release: {error}");
            ExitCode::FAILURE
        }
    }
}
