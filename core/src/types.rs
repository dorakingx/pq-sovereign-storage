use pqsp_crypto::{ProofBundle, ProofStatement, StateCommitment};
use serde::{Deserialize, Serialize};

/// Reference to a payload committed into the 0G Storage network.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageReceiptRef {
    /// Human-readable network identifier such as `galileo-testnet`.
    pub network: String,
    /// Merkle root returned by the storage layer for the uploaded payload.
    pub merkle_root: String,
    /// Optional transaction hash if the upload emitted an on-chain transaction.
    pub tx_hash: Option<String>,
}

/// Compact metadata derived from a proof bundle.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofMetadata {
    /// Proof system name, for example `mock-zk` during bootstrap.
    pub system_name: String,
    /// Proof system version.
    pub system_version: String,
    /// Encoded proof size in bytes.
    pub proof_size_bytes: usize,
}

impl ProofMetadata {
    /// Build metadata from a proof bundle.
    pub fn from_bundle(bundle: &ProofBundle) -> Self {
        Self {
            system_name: bundle.system.name.clone(),
            system_version: bundle.system.version.clone(),
            proof_size_bytes: bundle.proof_bytes.len(),
        }
    }
}

/// Complete verifier-facing public input.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifierInput {
    /// The proof statement the verifier is expected to validate.
    pub proof_statement: ProofStatement,
    /// The proof bundle proving the statement.
    pub proof: ProofBundle,
    /// Storage-layer receipt proving where the ciphertext envelope lives.
    pub storage: StorageReceiptRef,
}

impl VerifierInput {
    /// Convenience accessor for the state commitment inside the proof statement.
    pub fn state_commitment(&self) -> StateCommitment {
        self.proof_statement.state_commitment
    }

    /// Extract proof metadata without copying proof bytes.
    pub fn proof_metadata(&self) -> ProofMetadata {
        ProofMetadata::from_bundle(&self.proof)
    }
}

/// Submission object destined for a future on-chain verifier contract.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitmentSubmission {
    /// Application-level identifier for the submission.
    pub application_id: String,
    /// Proof plus storage receipt to validate on chain.
    pub verifier_input: VerifierInput,
    /// Optional submitter identity or address.
    pub submitter: Option<String>,
    /// Optional operator memo for indexing or debugging.
    pub memo: Option<String>,
}

/// Result returned by an on-chain verifier adapter.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerificationReceipt {
    /// Whether the verifier accepted the submission.
    pub accepted: bool,
    /// Transaction hash for the verifier transaction if available.
    pub verifier_tx_hash: Option<String>,
    /// Human-readable explanation of the outcome.
    pub reason: Option<String>,
}
