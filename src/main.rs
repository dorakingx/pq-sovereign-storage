use clap::{Parser, Subcommand};
use dotenv::dotenv;
use pqsp_core::{
    CommitmentSubmission, MockOnChainVerifier, OnChainVerifier, VerificationReceipt, VerifierInput,
};
use pqsp_crypto::{
    EncryptionKey, MockZkProver, Shake256Committer, XChaCha20Poly1305Encryptor,
};
use pqsp_storage_client::{
    StorageClient, UploadPayloadSummary, UploadReceipt, ZeroGStorageConfig, ZeroGStorageService,
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::{
    env,
    error::Error,
    fs,
    io::{self, ErrorKind},
    path::{Path, PathBuf},
};

const DEFAULT_AAD: &str = "app=pqsp-cli;purpose=judge-demo";
const DEFAULT_NETWORK: &str = "galileo-testnet";

#[derive(Debug, Parser)]
#[command(
    name = "pq-sovereign-storage",
    version,
    about = "Judge-friendly CLI for post-quantum sovereign privacy storage."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Encrypt, commit, and upload a file to 0G Storage.
    Upload {
        /// Path to the file that should be uploaded.
        file_path: PathBuf,
        /// Optional output path for the saved verification artifact JSON.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Additional authenticated data bound into the commitment/proof transcript.
        #[arg(long, default_value = DEFAULT_AAD)]
        aad: String,
        /// Application identifier embedded into the commitment submission.
        #[arg(long, default_value = "pqsp-cli")]
        application_id: String,
        /// Optional submitter identifier recorded in the saved artifact.
        #[arg(long)]
        submitter: Option<String>,
        /// Optional memo recorded in the saved artifact.
        #[arg(long)]
        memo: Option<String>,
        /// Human-readable network label used in the storage receipt.
        #[arg(long, default_value = DEFAULT_NETWORK)]
        network: String,
    },
    /// Verify a previously saved upload artifact using the mock verifier.
    Verify {
        /// Path to the saved JSON artifact produced by `upload`.
        storage_receipt_json: PathBuf,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct VerificationArtifact {
    /// Schema version for the CLI artifact format.
    version: u8,
    /// Original file path used for the upload command.
    source_file: String,
    /// Whether the upload used `dry_run` or `live_with_nodes`.
    storage_mode: String,
    /// Compact payload metadata for quick inspection.
    payload_summary: UploadPayloadSummary,
    /// Upload receipt returned by the storage layer.
    upload_receipt: UploadReceipt,
    /// Complete verifier submission required for later verification.
    commitment_submission: CommitmentSubmission,
}

#[derive(Debug, Serialize)]
struct UploadCommandOutput {
    artifact_path: String,
    artifact: VerificationArtifact,
}

#[derive(Debug, Serialize)]
struct VerifyCommandOutput {
    artifact_path: String,
    payload_summary: UploadPayloadSummary,
    upload_receipt: UploadReceipt,
    verification_receipt: VerificationReceipt,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenv().ok();

    let cli = Cli::parse();
    match cli.command {
        Commands::Upload {
            file_path,
            out,
            aad,
            application_id,
            submitter,
            memo,
            network,
        } => {
            run_upload(
                &file_path,
                out.as_deref(),
                &aad,
                &application_id,
                submitter,
                memo,
                &network,
            )
            .await?;
        }
        Commands::Verify {
            storage_receipt_json,
        } => {
            run_verify(&storage_receipt_json).await?;
        }
    }

    Ok(())
}

async fn run_upload(
    file_path: &Path,
    out_path: Option<&Path>,
    aad: &str,
    application_id: &str,
    submitter: Option<String>,
    memo: Option<String>,
    network: &str,
) -> Result<(), Box<dyn Error>> {
    let plaintext = fs::read(file_path)?;
    let (config, storage_mode) = build_storage_config(network);

    let encryption_key = EncryptionKey::generate(&mut OsRng);
    let encryptor = XChaCha20Poly1305Encryptor::new(encryption_key);
    let committer = Shake256Committer::default();
    let prover = MockZkProver;
    let storage = ZeroGStorageService::new(config, committer, encryptor);

    let (prepared, upload_receipt) = storage.store(&plaintext, aad.as_bytes(), &prover).await?;
    let payload_summary = prepared.upload_payload.summary();

    let submission = CommitmentSubmission {
        application_id: application_id.to_string(),
        verifier_input: VerifierInput {
            proof_statement: prepared.proof_statement,
            proof: prepared.proof,
            storage: upload_receipt.storage.clone(),
        },
        submitter,
        memo,
    };

    let artifact = VerificationArtifact {
        version: 1,
        source_file: file_path.display().to_string(),
        storage_mode,
        payload_summary,
        upload_receipt,
        commitment_submission: submission,
    };

    let artifact_path = out_path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| default_artifact_path(file_path));
    write_json_file(&artifact_path, &artifact)?;

    let output = UploadCommandOutput {
        artifact_path: artifact_path.display().to_string(),
        artifact,
    };

    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

async fn run_verify(storage_receipt_json: &Path) -> Result<(), Box<dyn Error>> {
    let artifact_bytes = fs::read(storage_receipt_json)?;
    let artifact: VerificationArtifact = serde_json::from_slice(&artifact_bytes)?;
    validate_artifact(&artifact)?;

    let verifier = MockOnChainVerifier::default();
    let verification_receipt = verifier.submit(&artifact.commitment_submission).await?;

    let output = VerifyCommandOutput {
        artifact_path: storage_receipt_json.display().to_string(),
        payload_summary: artifact.payload_summary,
        upload_receipt: artifact.upload_receipt,
        verification_receipt,
    };

    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn build_storage_config(network: &str) -> (ZeroGStorageConfig, String) {
    let chain_rpc_url = env::var("0G_CHAIN_RPC_URL").ok().filter(|v| !v.trim().is_empty());
    let private_key = env::var("0G_PRIVATE_KEY").ok().filter(|v| !v.trim().is_empty());
    let node_url_env = env::var("0G_STORAGE_NODE_URL")
        .ok()
        .filter(|v| !v.trim().is_empty());

    if let (Some(chain_rpc_url), Some(private_key), Some(node_url_env)) =
        (chain_rpc_url, private_key, node_url_env)
    {
        let node_urls = parse_node_urls(&node_url_env);
        if !node_urls.is_empty() {
            return (
                ZeroGStorageConfig::live_with_nodes(
                    network.to_string(),
                    chain_rpc_url,
                    private_key,
                    node_urls,
                ),
                "live_with_nodes".to_string(),
            );
        }
    }

    (
        ZeroGStorageConfig::dry_run(network.to_string()),
        "dry_run".to_string(),
    )
}

fn parse_node_urls(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn default_artifact_path(file_path: &Path) -> PathBuf {
    let file_name = file_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("upload");
    file_path.with_file_name(format!("{file_name}.pqsp-receipt.json"))
}

fn write_json_file<T: Serialize>(path: &Path, value: &T) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    let json = serde_json::to_vec_pretty(value)?;
    fs::write(path, json)?;
    Ok(())
}

fn validate_artifact(artifact: &VerificationArtifact) -> Result<(), Box<dyn Error>> {
    if artifact.version != 1 {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("unsupported artifact version: {}", artifact.version),
        )
        .into());
    }

    if artifact.upload_receipt.state_commitment
        != artifact
            .commitment_submission
            .verifier_input
            .state_commitment()
    {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "artifact commitment mismatch between receipt and verifier input",
        )
        .into());
    }

    Ok(())
}
