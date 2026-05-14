use clap::{Parser, Subcommand};
use colored::Colorize;
use dotenv::dotenv;
use indicatif::{ProgressBar, ProgressStyle};
use pqsp_core::{
    CommitmentSubmission, EvmOnChainVerifier, MockOnChainVerifier, OnChainVerifier,
    VerificationReceipt, VerifierInput,
};
use pqsp_crypto::{
    EncryptedPayload, EncryptionKey, MockZkProver, PayloadEncryptor, Shake256Committer,
    XChaCha20Poly1305Encryptor,
};
use pqsp_storage_client::{
    download_with_indexer, StorageClient, UploadPayload, UploadPayloadSummary, UploadReceipt,
    ZeroGStorageConfig, ZeroGStorageService,
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::{
    env,
    error::Error,
    fs,
    io::{self, ErrorKind},
    path::{Path, PathBuf},
    time::Duration,
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
    /// Verify a saved artifact using the EVM verifier when configured, otherwise local mock mode.
    Verify {
        /// Path to the saved JSON artifact produced by `upload`.
        storage_receipt_json: PathBuf,
    },
    /// Decrypt a downloaded 0G payload or raw encrypted payload envelope.
    Decrypt {
        /// Path to the downloaded payload file.
        encrypted_file_path: PathBuf,
        /// Hex-encoded encryption key printed during upload.
        key_hex: String,
        /// Additional authenticated data used during upload.
        #[arg(long, default_value = DEFAULT_AAD)]
        aad: String,
        /// Optional output path for recovered plaintext.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Download an encrypted payload from a 0G storage node by Merkle root.
    Download {
        /// 0G Storage Merkle root to download.
        merkle_root: String,
        /// Optional output path for the downloaded payload.
        #[arg(long)]
        out: Option<PathBuf>,
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
    verifier_mode: String,
    payload_summary: UploadPayloadSummary,
    upload_receipt: UploadReceipt,
    verification_receipt: VerificationReceipt,
}

#[derive(Debug, Serialize)]
struct DecryptCommandOutput {
    input_path: String,
    output_path: String,
    plaintext_bytes: usize,
    input_format: String,
}

#[derive(Debug, Serialize)]
struct DownloadCommandOutput {
    merkle_root: String,
    request_url: String,
    output_path: String,
    downloaded_bytes: usize,
}

fn spinner(message: impl Into<String>) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::with_template("{spinner:.green} {msg}")
            .expect("valid spinner template")
            .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ "),
    );
    pb.enable_steady_tick(Duration::from_millis(100));
    pb.set_message(message.into());
    pb
}

/// Apply `.env` entries whose keys start with a decimal digit.
///
/// The `dotenv` crate (0.15) only accepts keys that start with an ASCII letter or `_`
/// (`parse_key` rejects digit-leading names). This project uses `0G_*` variables by
/// convention, so we merge those entries after `dotenv()` so live mode and downloads work.
fn patch_env_from_dotfile() -> Result<(), io::Error> {
    let path = Path::new(".env");
    if !path.is_file() {
        return Ok(());
    }
    let contents = fs::read_to_string(path)?;
    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = if let Some(rest) = line.strip_prefix("export ") {
            rest.trim_start()
        } else {
            line
        };
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        let first = key.chars().next();
        if !first.is_some_and(|c| c.is_ascii_digit()) {
            continue;
        }
        let value = value.trim().trim_matches('"').trim_matches('\'');
        env::set_var(key, value);
    }
    Ok(())
}

fn print_banner() {
    let logo = [
        "██████╗  ██████╗ ███████╗██████╗ ",
        "██╔══██╗██╔═══██╗██╔════╝██╔══██╗",
        "██████╔╝██║   ██║███████╗██████╔╝",
        "██╔═══╝ ██║▄▄ ██║╚════██║██╔═══╝ ",
        "██║     ╚██████╔╝███████║██║     ",
        "╚═╝      ╚══▀▀═╝ ╚══════╝╚═╝     ",
    ];

    eprintln!();
    for (index, line) in logo.iter().enumerate() {
        let styled = match index {
            0 | 1 => line.bright_cyan(),
            2 | 3 => line.bright_magenta(),
            _ => line.bright_blue(),
        };
        eprintln!("{}", styled.bold());
    }
    eprintln!(
        "{}",
        "Post-Quantum Sovereign Privacy Storage"
            .bright_white()
            .bold()
    );
    eprintln!(
        "{}",
        "0G APAC Hackathon | Track 5: Privacy & Sovereign Infrastructure"
            .bright_green()
            .bold()
    );
    eprintln!();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenv().ok();
    patch_env_from_dotfile()?;
    print_banner();

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
        Commands::Decrypt {
            encrypted_file_path,
            key_hex,
            aad,
            out,
        } => {
            run_decrypt(&encrypted_file_path, &key_hex, &aad, out.as_deref()).await?;
        }
        Commands::Download { merkle_root, out } => {
            run_download(&merkle_root, out.as_deref()).await?;
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
    let encryption_key_hex = encryption_key.to_hex();
    eprintln!();
    eprintln!(
        "{}",
        "IMPORTANT: Save this encryption key to decrypt your data:"
            .bold()
            .yellow()
    );
    eprintln!("{}", encryption_key_hex.bold().red());
    eprintln!();

    let encryptor = XChaCha20Poly1305Encryptor::new(encryption_key);
    let committer = Shake256Committer::default();
    let prover = MockZkProver;
    let storage = ZeroGStorageService::new(config, committer, encryptor);

    let pb = spinner("Encrypting payload and uploading to 0G Storage...");
    let (prepared, upload_receipt) = storage.store(&plaintext, aad.as_bytes(), &prover).await?;
    pb.finish_with_message("Upload complete!".green().to_string());
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

    let pb = spinner("Submitting proof and commitment to 0G Chain...");
    let (verification_receipt, verifier_mode) =
        submit_with_configured_verifier(&artifact.commitment_submission).await?;
    pb.finish_with_message("Verification complete!".green().to_string());

    if verification_receipt.accepted {
        eprintln!("{}", "Commitment accepted by verifier.".green());
        if let Some(tx_hash) = &verification_receipt.verifier_tx_hash {
            eprintln!("{} {}", "Transaction hash:".green(), tx_hash.green());
        }
    }

    let output = VerifyCommandOutput {
        artifact_path: storage_receipt_json.display().to_string(),
        verifier_mode,
        payload_summary: artifact.payload_summary,
        upload_receipt: artifact.upload_receipt,
        verification_receipt,
    };

    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

async fn run_decrypt(
    encrypted_file_path: &Path,
    key_hex: &str,
    aad: &str,
    out_path: Option<&Path>,
) -> Result<(), Box<dyn Error>> {
    let encrypted_bytes = fs::read(encrypted_file_path)?;
    let (encrypted_payload, input_format) = parse_encrypted_payload(&encrypted_bytes)?;
    let encryption_key = EncryptionKey::from_hex(key_hex)?;
    let encryptor = XChaCha20Poly1305Encryptor::new(encryption_key);
    let pb = spinner("Decrypting sovereign payload...");
    let plaintext = encryptor.decrypt(&encrypted_payload, aad.as_bytes())?;
    let output_path = out_path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| default_decrypt_path(encrypted_file_path));

    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(&output_path, &plaintext)?;
    pb.finish_with_message("Plaintext successfully recovered!".bold().green().to_string());

    let output = DecryptCommandOutput {
        input_path: encrypted_file_path.display().to_string(),
        output_path: output_path.display().to_string(),
        plaintext_bytes: plaintext.len(),
        input_format,
    };

    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

async fn run_download(merkle_root: &str, out_path: Option<&Path>) -> Result<(), Box<dyn Error>> {
    let output_path = out_path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| default_download_path(merkle_root));

    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    let request_url = if let Some(indexer_url) = first_storage_indexer_url() {
        let pb = spinner("Fetching payload from 0G Storage indexer...");
        download_with_indexer(&indexer_url, merkle_root, &output_path).await?;
        pb.finish_with_message("Download complete!".green().to_string());
        format!("{}/file/{}", indexer_url.trim_end_matches('/'), merkle_root)
    } else {
        let node_url = first_storage_node_url().ok_or_else(|| {
            io::Error::new(
                ErrorKind::NotFound,
                "Configure 0G_STORAGE_INDEXER_URL or 0G_STORAGE_NODE_URL before running download.",
            )
        })?;
        let request_url = format!(
            "{}/file/{}",
            node_url.trim_end_matches('/'),
            merkle_root.trim_start_matches('/')
        );
        let pb = spinner("Fetching payload from 0G Storage network...");
        let response = reqwest::get(&request_url).await?.error_for_status()?;
        let downloaded_bytes = response.bytes().await?;
        fs::write(&output_path, &downloaded_bytes)?;
        pb.finish_with_message("Download complete!".green().to_string());
        request_url
    };
    let downloaded_bytes = usize::try_from(fs::metadata(&output_path)?.len())?;

    let output = DownloadCommandOutput {
        merkle_root: merkle_root.to_string(),
        request_url,
        output_path: output_path.display().to_string(),
        downloaded_bytes,
    };

    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

async fn submit_with_configured_verifier(
    submission: &CommitmentSubmission,
) -> Result<(VerificationReceipt, String), Box<dyn Error>> {
    let chain_rpc_url = env::var("0G_CHAIN_RPC_URL")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let private_key = env::var("0G_PRIVATE_KEY")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let contract_address = env::var("PQSP_VERIFIER_CONTRACT_ADDRESS")
        .ok()
        .filter(|value| !value.trim().is_empty());

    if let (Some(chain_rpc_url), Some(private_key), Some(contract_address)) =
        (chain_rpc_url, private_key, contract_address)
    {
        let verifier = EvmOnChainVerifier::new(chain_rpc_url, private_key, contract_address).await?;
        let receipt = verifier.submit(submission).await?;
        return Ok((receipt, "evm".to_string()));
    }

    eprintln!("Running in Local Mock Mode...");
    let verifier = MockOnChainVerifier::default();
    let receipt = verifier.submit(submission).await?;
    Ok((receipt, "local_mock".to_string()))
}

fn build_storage_config(network: &str) -> (ZeroGStorageConfig, String) {
    let chain_rpc_url = env::var("0G_CHAIN_RPC_URL").ok().filter(|v| !v.trim().is_empty());
    let private_key = env::var("0G_PRIVATE_KEY").ok().filter(|v| !v.trim().is_empty());
    let indexer_url_env = env::var("0G_STORAGE_INDEXER_URL")
        .ok()
        .filter(|v| !v.trim().is_empty());
    let node_url_env = env::var("0G_STORAGE_NODE_URL")
        .ok()
        .filter(|v| !v.trim().is_empty());

    if let (Some(chain_rpc_url), Some(private_key), Some(indexer_url_env)) =
        (&chain_rpc_url, &private_key, indexer_url_env)
    {
        return (
            ZeroGStorageConfig::live_with_indexer(
                network.to_string(),
                chain_rpc_url.to_string(),
                private_key.to_string(),
                indexer_url_env,
            ),
            "live_with_indexer".to_string(),
        );
    }

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

fn first_storage_indexer_url() -> Option<String> {
    env::var("0G_STORAGE_INDEXER_URL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn first_storage_node_url() -> Option<String> {
    env::var("0G_STORAGE_NODE_URL")
        .ok()
        .and_then(|raw| parse_node_urls(&raw).into_iter().next())
}

fn default_artifact_path(file_path: &Path) -> PathBuf {
    let file_name = file_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("upload");
    file_path.with_file_name(format!("{file_name}.pqsp-receipt.json"))
}

fn default_decrypt_path(encrypted_file_path: &Path) -> PathBuf {
    let file_name = encrypted_file_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("payload");
    encrypted_file_path.with_file_name(format!("{file_name}.decrypted"))
}

fn default_download_path(merkle_root: &str) -> PathBuf {
    let file_name = merkle_root
        .strip_prefix("0x")
        .unwrap_or(merkle_root)
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    PathBuf::from(format!("{file_name}.json"))
}

fn parse_encrypted_payload(bytes: &[u8]) -> Result<(EncryptedPayload, String), Box<dyn Error>> {
    if let Ok(upload_payload) = serde_json::from_slice::<UploadPayload>(bytes) {
        return Ok((
            EncryptedPayload::from_bytes(upload_payload.encrypted_blob.as_ref())?,
            "upload_payload_json".to_string(),
        ));
    }

    Ok((
        EncryptedPayload::from_bytes(bytes)?,
        "raw_encrypted_payload".to_string(),
    ))
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
