use async_trait::async_trait;
use ethers::types::{H256, U256};
use pqsp_core::StorageReceiptRef;
use pqsp_crypto::{
    PayloadEncryptor, ProofStatement, ProofWitness, StateCommitter, ZkProver,
};
use std::{io::Write, path::Path, sync::Arc};
use tempfile::NamedTempFile;
use zg_storage_client::{
    cmd::upload::{FinalityRequirement, UploadOption},
    common::blockchain::rpc::new_web3,
    core::file::File as ZgFile,
    indexer::client::IndexerClient,
    node::client_zgs::ZgsClient,
    transfer::uploader::Uploader,
};

use crate::{
    error::StorageClientError,
    payload::{PayloadMetadata, PreparedUpload, UploadPayload, UploadReceipt},
};

/// Upload execution mode.
#[derive(Clone, Copy, Debug, Default)]
pub enum UploadMode {
    /// Do not contact 0G. Produce a deterministic local receipt instead.
    #[default]
    DryRun,
    /// Stage a real payload and upload it via the official 0G Rust SDK.
    Live,
}

/// Finality level requested from the 0G upload path.
#[derive(Clone, Copy, Debug, Default)]
pub enum UploadFinality {
    /// Wait until the file is finalized on storage nodes.
    FileFinalized,
    /// Wait until the transaction is packed on chain.
    #[default]
    TransactionPacked,
    /// Return immediately after dispatch.
    WaitNothing,
}

impl UploadFinality {
    fn into_sdk(self) -> FinalityRequirement {
        match self {
            Self::FileFinalized => FinalityRequirement::FileFinalized,
            Self::TransactionPacked => FinalityRequirement::TransactionPacked,
            Self::WaitNothing => FinalityRequirement::WaitNothing,
        }
    }
}

/// Live-upload configuration for the 0G adapter.
#[derive(Clone, Debug)]
pub struct ZeroGStorageConfig {
    /// Human-readable network label.
    pub network_label: String,
    /// Whether the service performs a real upload or returns a deterministic stub.
    pub mode: UploadMode,
    /// 0G Chain RPC endpoint used when `mode` is `Live`.
    pub chain_rpc_url: Option<String>,
    /// Hex-encoded private key used by the SDK to sign upload transactions.
    pub private_key_hex: Option<String>,
    /// Optional indexer endpoint. When present it takes precedence over `node_urls`.
    pub indexer_url: Option<String>,
    /// Explicit node URLs used when no indexer endpoint is supplied.
    pub node_urls: Vec<String>,
    /// Desired replica count for the storage upload.
    pub expected_replica: u64,
    /// Number of segments submitted in each upload task.
    pub task_size: u64,
    /// Skip the chain transaction if the SDK detects the file already exists.
    pub skip_tx: bool,
    /// Upload fee in wei-equivalent base units.
    pub fee_wei: u128,
    /// Requested upload finality.
    pub finality: UploadFinality,
}

impl ZeroGStorageConfig {
    /// Build a dry-run configuration suitable for local demos and tests.
    pub fn dry_run(network_label: impl Into<String>) -> Self {
        Self {
            network_label: network_label.into(),
            mode: UploadMode::DryRun,
            chain_rpc_url: None,
            private_key_hex: None,
            indexer_url: None,
            node_urls: Vec::new(),
            expected_replica: 1,
            task_size: 10,
            skip_tx: true,
            fee_wei: 0,
            finality: UploadFinality::TransactionPacked,
        }
    }

    /// Build a live config that resolves storage nodes through an indexer.
    pub fn live_with_indexer(
        network_label: impl Into<String>,
        chain_rpc_url: impl Into<String>,
        private_key_hex: impl Into<String>,
        indexer_url: impl Into<String>,
    ) -> Self {
        Self {
            network_label: network_label.into(),
            mode: UploadMode::Live,
            chain_rpc_url: Some(chain_rpc_url.into()),
            private_key_hex: Some(private_key_hex.into()),
            indexer_url: Some(indexer_url.into()),
            node_urls: Vec::new(),
            expected_replica: 1,
            task_size: 10,
            skip_tx: true,
            fee_wei: 0,
            finality: UploadFinality::TransactionPacked,
        }
    }

    /// Build a live config that targets explicit storage nodes.
    pub fn live_with_nodes(
        network_label: impl Into<String>,
        chain_rpc_url: impl Into<String>,
        private_key_hex: impl Into<String>,
        node_urls: Vec<String>,
    ) -> Self {
        Self {
            network_label: network_label.into(),
            mode: UploadMode::Live,
            chain_rpc_url: Some(chain_rpc_url.into()),
            private_key_hex: Some(private_key_hex.into()),
            indexer_url: None,
            node_urls,
            expected_replica: 1,
            task_size: 10,
            skip_tx: true,
            fee_wei: 0,
            finality: UploadFinality::TransactionPacked,
        }
    }
}

/// Trait implemented by services capable of staging and uploading protocol payloads.
#[async_trait]
pub trait StorageClient: Send + Sync {
    /// Encrypt data, commit to the resulting ciphertext envelope, and generate a proof.
    async fn prepare_upload(
        &self,
        plaintext: &[u8],
        aad: &[u8],
        prover: &dyn ZkProver,
    ) -> Result<PreparedUpload, StorageClientError>;

    /// Upload a previously prepared payload to 0G Storage.
    async fn upload_prepared(
        &self,
        prepared: &PreparedUpload,
    ) -> Result<UploadReceipt, StorageClientError>;

    /// Convenience helper for the full encrypt -> prove -> upload pipeline.
    async fn store(
        &self,
        plaintext: &[u8],
        aad: &[u8],
        prover: &dyn ZkProver,
    ) -> Result<(PreparedUpload, UploadReceipt), StorageClientError> {
        let prepared = self.prepare_upload(plaintext, aad, prover).await?;
        let receipt = self.upload_prepared(&prepared).await?;
        Ok((prepared, receipt))
    }
}

/// Reference implementation of the sovereign upload pipeline.
pub struct ZeroGStorageService<C, E> {
    config: ZeroGStorageConfig,
    committer: C,
    encryptor: E,
}

impl<C, E> ZeroGStorageService<C, E> {
    /// Create a new service from caller-supplied crypto primitives and config.
    pub fn new(config: ZeroGStorageConfig, committer: C, encryptor: E) -> Self {
        Self {
            config,
            committer,
            encryptor,
        }
    }
}

#[async_trait]
impl<C, E> StorageClient for ZeroGStorageService<C, E>
where
    C: StateCommitter + Send + Sync,
    E: PayloadEncryptor + Send + Sync,
{
    async fn prepare_upload(
        &self,
        plaintext: &[u8],
        aad: &[u8],
        prover: &dyn ZkProver,
    ) -> Result<PreparedUpload, StorageClientError> {
        // Commit to the ciphertext envelope so the public state reflects the
        // exact bytes persisted into the sovereign storage layer.
        let envelope = self.encryptor.encrypt(plaintext, aad)?;
        let envelope_bytes = envelope.to_bytes();
        let state_commitment = self.committer.commit(&envelope_bytes, aad);

        let proof_statement = ProofStatement {
            state_commitment,
            context: aad.to_vec(),
            public_inputs: vec![
                format!("state_commitment={}", state_commitment),
                format!("ciphertext_bytes={}", envelope.ciphertext_len()),
            ],
        };

        let witness = ProofWitness::new(plaintext);
        let proof = prover.prove(&proof_statement, &witness)?;

        let upload_payload = UploadPayload {
            version: 1,
            encrypted_blob: envelope_bytes.clone().into(),
            state_commitment,
            proof_statement: proof_statement.clone(),
            proof: proof.clone(),
            metadata: PayloadMetadata {
                protocol_version: 1,
                content_type: "application/json".to_string(),
                encryption_scheme: "XChaCha20Poly1305".to_string(),
                commitment_scheme: "SHAKE256-256".to_string(),
                proof_system: format!("{}@{}", proof.system.name, proof.system.version),
            },
        };

        let encoded_payload = upload_payload.encode()?;

        Ok(PreparedUpload {
            envelope,
            proof_statement,
            proof,
            state_commitment,
            upload_payload,
            encoded_payload: encoded_payload.into(),
        })
    }

    async fn upload_prepared(
        &self,
        prepared: &PreparedUpload,
    ) -> Result<UploadReceipt, StorageClientError> {
        let storage = match self.config.mode {
            UploadMode::DryRun => StorageReceiptRef {
                network: self.config.network_label.clone(),
                merkle_root: self
                    .committer
                    .commit(
                        prepared.encoded_payload.as_ref(),
                        b"pqsp:v1:dry-run-storage-root",
                    )
                    .to_hex(),
                tx_hash: None,
            },
            UploadMode::Live => self
                .upload_live_bytes(prepared.encoded_payload.as_ref())
                .await?,
        };

        Ok(UploadReceipt {
            storage,
            state_commitment: prepared.state_commitment,
            payload_bytes: prepared.encoded_payload.len(),
        })
    }
}

/// Download an uploaded payload by Merkle root through the 0G storage indexer.
pub async fn download_with_indexer(
    indexer_url: &str,
    merkle_root: &str,
    output_path: &Path,
) -> Result<(), StorageClientError> {
    let root = merkle_root
        .parse::<H256>()
        .map_err(|err| StorageClientError::ZeroGSdk(err.to_string()))?;
    let indexer = IndexerClient::new(indexer_url)
        .await
        .map_err(|err| StorageClientError::ZeroGSdk(err.to_string()))?;

    indexer
        .download(root, &output_path.to_path_buf(), false)
        .await
        .map_err(|err| StorageClientError::ZeroGSdk(err.to_string()))
}

impl<C, E> ZeroGStorageService<C, E>
where
    C: StateCommitter + Send + Sync,
    E: PayloadEncryptor + Send + Sync,
{
    async fn upload_live_bytes(
        &self,
        payload_bytes: &[u8],
    ) -> Result<StorageReceiptRef, StorageClientError> {
        let chain_rpc_url = self
            .config
            .chain_rpc_url
            .as_deref()
            .ok_or(StorageClientError::MissingChainCredentials)?;
        let private_key_hex = self
            .config
            .private_key_hex
            .as_deref()
            .ok_or(StorageClientError::MissingChainCredentials)?;

        if self.config.indexer_url.is_none() && self.config.node_urls.is_empty() {
            return Err(StorageClientError::MissingUploadTarget);
        }

        let mut staged_file = NamedTempFile::new()?;
        staged_file.write_all(payload_bytes)?;
        staged_file.flush()?;

        let file_root = ZgFile::merkle_root(staged_file.path())
            .await
            .map_err(|err| StorageClientError::ZeroGSdk(err.to_string()))?;
        let file = Arc::new(
            ZgFile::open(staged_file.path())
                .map_err(|err| StorageClientError::ZeroGSdk(err.to_string()))?,
        );
        let web3_client = new_web3(chain_rpc_url, private_key_hex)
            .await
            .map_err(|err| StorageClientError::ZeroGSdk(err.to_string()))?;
        let upload_option = UploadOption {
            tags: Vec::new(),
            finality_required: self.config.finality.into_sdk(),
            task_size: self.config.task_size,
            expected_replica: self.config.expected_replica,
            skip_tx: self.config.skip_tx,
            fee: U256::from(self.config.fee_wei),
            nonce: U256::zero(),
        };

        let tx_hash = if let Some(indexer_url) = &self.config.indexer_url {
            let indexer = IndexerClient::new(indexer_url)
                .await
                .map_err(|err| StorageClientError::ZeroGSdk(err.to_string()))?;
            indexer
                .upload(web3_client, file, &upload_option, None, None)
                .await
                .map_err(|err| StorageClientError::ZeroGSdk(err.to_string()))?
        } else {
            let mut clients = Vec::with_capacity(self.config.node_urls.len());
            for node_url in &self.config.node_urls {
                clients.push(
                    ZgsClient::new(node_url)
                        .await
                        .map_err(|err| StorageClientError::ZeroGSdk(err.to_string()))?,
                );
            }

            let uploader = Uploader::new_with_addresses(web3_client, clients, None, None)
                .await
                .map_err(|err| StorageClientError::ZeroGSdk(err.to_string()))?;
            uploader
                .upload(file, &upload_option)
                .await
                .map_err(|err| StorageClientError::ZeroGSdk(err.to_string()))?
        };

        Ok(StorageReceiptRef {
            network: self.config.network_label.clone(),
            merkle_root: format!("0x{}", hex::encode(file_root.as_bytes())),
            tx_hash: Some(format!("0x{}", hex::encode(tx_hash.as_bytes()))),
        })
    }
}
