//! Command-line interface for candidate qualification and verification.
//!
//! Subcommands:
//! - pack: produce deterministic candidate release archive and ledger
//! - verify-platform: verify candidate platform attestation sidecar against spec and archive
//! - assemble-index: assemble two-platform candidate evidence index
//! - verify-index: verify two-platform candidate evidence index against spec and artifacts
//! - resolve-bin: resolve candidate test binary fail-closed
//! - transcript: execute and record checked analysis transcript on redistributable fixture

use std::path::PathBuf;
use std::process::exit;

use clap::{Parser, Subcommand};
use luad_oracle::candidate::{
    assemble_evidence_index, execute_checked_transcript, pack_candidate, resolve_test_binary,
    verify_evidence_index, verify_platform_attestation, BinaryResolutionDoc,
};

#[derive(Parser, Debug)]
#[command(
    name = "luad-candidate",
    about = "Reproducible Lua 5.1 LNUM32 candidate qualification and packaging tool",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Pack a deterministic release archive and member ledger.
    Pack {
        /// Path to candidate specification JSON.
        #[arg(long)]
        spec: PathBuf,

        /// Path to compiled luad binary.
        #[arg(long)]
        binary: PathBuf,

        /// Path to repository LICENSE file.
        #[arg(long)]
        license: PathBuf,

        /// Path to VERSION.json metadata file.
        #[arg(long = "version-info")]
        version_info: PathBuf,

        /// Output path for deterministic tar.gz archive.
        #[arg(long = "out-archive")]
        out_archive: PathBuf,

        /// Output path for member ledger JSON.
        #[arg(long = "out-ledger")]
        out_ledger: PathBuf,
    },

    /// Verify a platform attestation against candidate spec and archive.
    VerifyPlatform {
        /// Path to candidate specification JSON.
        #[arg(long)]
        spec: PathBuf,

        /// Path to platform attestation JSON sidecar.
        #[arg(long)]
        attestation: PathBuf,

        /// Path to packed platform tar.gz archive.
        #[arg(long)]
        archive: PathBuf,
    },

    /// Assemble a multi-platform candidate evidence index.
    AssembleIndex {
        /// Path to candidate specification JSON.
        #[arg(long)]
        spec: PathBuf,

        /// Root directory containing platform archives and sidecars.
        #[arg(long = "artifact-root")]
        artifact_root: PathBuf,

        /// Path to platform attestation JSON (repeat for each platform).
        #[arg(long = "attestation", action = clap::ArgAction::Append)]
        attestation: Vec<PathBuf>,

        /// Output path for assembled candidate-index.json.
        #[arg(long)]
        out: PathBuf,
    },

    /// Verify a multi-platform candidate evidence index.
    VerifyIndex {
        /// Path to candidate specification JSON.
        #[arg(long)]
        spec: PathBuf,

        /// Root directory containing platform archives and sidecars.
        #[arg(long = "artifact-root")]
        artifact_root: PathBuf,

        /// Path to candidate-index.json to verify.
        #[arg(long)]
        index: PathBuf,
    },

    /// Resolve candidate test binary fail-closed.
    ResolveBin {
        /// Path to candidate specification JSON.
        #[arg(long)]
        spec: PathBuf,
    },

    /// Run and record checked analysis transcript on redistributable fixture.
    Transcript {
        /// Path to candidate specification JSON.
        #[arg(long)]
        spec: PathBuf,

        /// Path to redistributable authority bytecode fixture.
        #[arg(long)]
        fixture: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Pack {
            spec,
            binary,
            license,
            version_info,
            out_archive,
            out_ledger,
        } => {
            if let Err(e) = pack_candidate(
                &spec,
                &binary,
                &license,
                &version_info,
                &out_archive,
                &out_ledger,
            ) {
                eprintln!("Error packing candidate archive: {e}");
                exit(1);
            }
        }

        Commands::VerifyPlatform {
            spec,
            attestation,
            archive,
        } => {
            if let Err(e) = verify_platform_attestation(&spec, &attestation, &archive) {
                eprintln!("Error verifying platform attestation: {e}");
                exit(1);
            }
        }

        Commands::AssembleIndex {
            spec,
            artifact_root,
            attestation,
            out,
        } => {
            if let Err(e) = assemble_evidence_index(&spec, &artifact_root, &attestation, &out) {
                eprintln!("Error assembling candidate index: {e}");
                exit(1);
            }
        }

        Commands::VerifyIndex {
            spec,
            artifact_root,
            index,
        } => {
            if let Err(e) = verify_evidence_index(&spec, &artifact_root, &index) {
                eprintln!("Error verifying candidate index: {e}");
                exit(1);
            }
        }

        Commands::ResolveBin { spec: _ } => {
            let override_active = std::env::var_os("LUAD_CANDIDATE_BIN").is_some();
            match resolve_test_binary() {
                Ok(path) => {
                    let doc = BinaryResolutionDoc {
                        selected_binary_path: path.to_string_lossy().to_string(),
                        override_active,
                    };
                    println!("{}", serde_json::to_string_pretty(&doc).unwrap());
                }
                Err(e) => {
                    eprintln!("Error: LUAD_CANDIDATE_BIN resolution failed: {e}");
                    exit(1);
                }
            }
        }

        Commands::Transcript { spec, fixture } => {
            match execute_checked_transcript(&spec, &fixture) {
                Ok(doc) => {
                    println!("{}", serde_json::to_string_pretty(&doc).unwrap());
                }
                Err(e) => {
                    eprintln!("Error executing checked transcript: {e}");
                    exit(1);
                }
            }
        }
    }
}
