use pqsp_crypto::{EncryptionError, ProofSystemError};
use thiserror::Error;

/// Errors returned by the sovereign storage pipeline.
#[derive(Debug, Error)]
pub enum StorageClientError {
    /// Ciphertext envelope creation failed.
    #[error("payload encryption failed: {0}")]
    Encryption(#[from] EncryptionError),
    /// Proof generation failed.
    #[error("proof generation failed: {0}")]
    Proof(#[from] ProofSystemError),
    /// Payload serialization failed.
    #[error("payload serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    /// Local filesystem staging failed.
    #[error("local staging failed: {0}")]
    Io(#[from] std::io::Error),
    /// A live upload requires at least one storage target.
    #[error("configure either an indexer URL or one or more storage node URLs")]
    MissingUploadTarget,
    /// Live upload requires chain credentials.
    #[error("live uploads require both a chain RPC URL and a private key")]
    MissingChainCredentials,
    /// The official 0G SDK reported an error.
    #[error("0G SDK error: {0}")]
    ZeroGSdk(String),
}
