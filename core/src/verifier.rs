use async_trait::async_trait;
use pqsp_crypto::{MockZkVerifier, ProofSystemError, ZkVerifier};
use thiserror::Error;

use crate::{CommitmentSubmission, VerificationReceipt, VerifierInput};

/// Errors surfaced by an on-chain verifier adapter.
#[derive(Debug, Error)]
pub enum VerifierError {
    /// Storage-layer receipt is malformed.
    #[error("storage receipt is missing a 0x-prefixed merkle root")]
    InvalidStorageRoot,
    /// The proof could not be verified.
    #[error("proof validation failed: {0}")]
    InvalidProof(#[from] ProofSystemError),
    /// A chain client or remote verifier call failed.
    #[error("verifier transport error: {0}")]
    Transport(String),
}

/// Verifier abstraction intended for future 0G Chain integration.
#[async_trait]
pub trait OnChainVerifier: Send + Sync {
    /// Validate the verifier input before an on-chain submission is attempted.
    async fn validate(&self, input: &VerifierInput) -> Result<(), VerifierError>;

    /// Submit a verifier payload and return the result receipt.
    async fn submit(
        &self,
        submission: &CommitmentSubmission,
    ) -> Result<VerificationReceipt, VerifierError>;
}

/// Mock verifier that validates proof structure locally.
#[derive(Debug, Default)]
pub struct MockOnChainVerifier {
    zk_verifier: MockZkVerifier,
}

#[async_trait]
impl OnChainVerifier for MockOnChainVerifier {
    async fn validate(&self, input: &VerifierInput) -> Result<(), VerifierError> {
        if !input.storage.merkle_root.starts_with("0x") {
            return Err(VerifierError::InvalidStorageRoot);
        }

        self.zk_verifier
            .verify(&input.proof_statement, &input.proof)
            .map_err(VerifierError::from)
    }

    async fn submit(
        &self,
        submission: &CommitmentSubmission,
    ) -> Result<VerificationReceipt, VerifierError> {
        self.validate(&submission.verifier_input).await?;

        let synthetic_tx_hash =
            format!("0x{}", hex::encode(submission.verifier_input.state_commitment().as_bytes()));

        Ok(VerificationReceipt {
            accepted: true,
            verifier_tx_hash: Some(synthetic_tx_hash),
            reason: Some("mock verifier accepted the commitment and proof".to_string()),
        })
    }
}
