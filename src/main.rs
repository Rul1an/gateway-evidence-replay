use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use gateway_evidence_replay::pack::replay_pack_dir;
use gateway_evidence_replay::schema::PROFILE;
use gateway_evidence_replay::{verify_json_str, ReplayResult};

#[derive(Debug, Parser)]
#[command(name = "gateway-evidence-replay")]
#[command(about = "Verify gateway-path evidence bundles offline")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Verify one gateway-path evidence bundle.
    Verify {
        /// Evidence bundle JSON file.
        evidence: PathBuf,
        /// Evidence profile to verify.
        #[arg(long, default_value = PROFILE)]
        format: String,
        /// Emit a JSON verdict.
        #[arg(long)]
        json: bool,
    },
    /// Replay a digest-pinned demo pack and compare every verdict.
    ReplayPack {
        /// Directory containing manifest.json, manifest-sha256.txt, expected.json, and fixtures.
        directory: PathBuf,
        /// Emit a JSON replay report.
        #[arg(long)]
        json: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Verify {
            evidence,
            format,
            json,
        } => verify_command(evidence, &format, json),
        Commands::ReplayPack { directory, json } => replay_pack_command(directory, json),
    }
}

fn verify_command(evidence: PathBuf, format: &str, json: bool) -> Result<()> {
    let result = if format == PROFILE {
        let contents = fs::read_to_string(&evidence)
            .with_context(|| format!("failed to read evidence file {}", evidence.display()))?;
        verify_json_str(&contents)
    } else {
        ReplayResult::invalid()
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!(
            "{} ceiling={}",
            serde_json::to_string(&result.status)?,
            result
                .ceiling
                .map(|ceiling| serde_json::to_string(&ceiling).unwrap_or_default())
                .unwrap_or_else(|| "null".to_string())
        );
    }

    Ok(())
}

fn replay_pack_command(directory: PathBuf, json: bool) -> Result<()> {
    let report = replay_pack_dir(&directory)
        .with_context(|| format!("failed to replay pack {}", directory.display()))?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "passed cases={}/{} manifest={}",
            report.cases_passed, report.cases_total, report.manifest_sha256
        );
    }

    Ok(())
}
