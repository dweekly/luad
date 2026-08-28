//! Maintainer CLI for a local, non-promoting release packaging dry run.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use luad_oracle::release_bundle::{assemble_release_bundle, verify_release_bundle};
use luad_oracle::release_package::package_clean_workspace;
use luad_oracle::release_sbom::generate_release_sbom;

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

    /// Generate and independently verify the deterministic release SBOM.
    Sbom {
        /// Clean luad repository revision to describe.
        #[arg(long)]
        repository: PathBuf,

        /// Exact cargo-cyclonedx 0.5.9 executable.
        #[arg(long = "cargo-cyclonedx")]
        cargo_cyclonedx: PathBuf,

        /// New or empty output directory for the one SBOM document.
        #[arg(long = "output-dir")]
        output_dir: PathBuf,
    },

    /// Assemble and verify the five-file non-promoting release bundle.
    Bundle {
        /// Clean luad repository revision described by every input.
        #[arg(long)]
        repository: PathBuf,

        /// Exact seven-file output from the hosted release-archive aggregator.
        #[arg(long = "archive-dir")]
        archive_dir: PathBuf,

        /// Canonical release SBOM from the accepted SBOM boundary.
        #[arg(long)]
        sbom: PathBuf,

        /// Canonical prerequisite-result reference document.
        #[arg(long)]
        prerequisites: PathBuf,

        /// New or empty output directory for the five bundle files.
        #[arg(long = "output-dir")]
        output_dir: PathBuf,
    },

    /// Verify an assembled five-file non-promoting release bundle.
    VerifyBundle {
        /// Clean luad repository revision described by the bundle.
        #[arg(long)]
        repository: PathBuf,

        /// Directory containing exactly the five release bundle files.
        #[arg(long = "bundle-dir")]
        bundle_dir: PathBuf,
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
        Commands::Sbom {
            repository,
            cargo_cyclonedx,
            output_dir,
        } => {
            let result = generate_release_sbom(&repository, &cargo_cyclonedx, &output_dir)?;
            let json = serde_json::to_string_pretty(&result)
                .map_err(|error| format!("serialize SBOM result: {error}"))?;
            println!("{json}");
        }
        Commands::Bundle {
            repository,
            archive_dir,
            sbom,
            prerequisites,
            output_dir,
        } => {
            let result = assemble_release_bundle(
                &repository,
                &archive_dir,
                &sbom,
                &prerequisites,
                &output_dir,
            )?;
            let json = serde_json::to_string_pretty(&result)
                .map_err(|error| format!("serialize release bundle result: {error}"))?;
            println!("{json}");
        }
        Commands::VerifyBundle {
            repository,
            bundle_dir,
        } => {
            let result = verify_release_bundle(&repository, &bundle_dir)?;
            let json = serde_json::to_string_pretty(&result)
                .map_err(|error| format!("serialize release bundle result: {error}"))?;
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
