use async_trait::async_trait;
use ethers::{
    abi::AbiParser,
    contract::Contract,
    core::types::{Address, Bytes as EvmBytes, H256, U64},
    middleware::SignerMiddleware,
    providers::{Http, Middleware, Provider},
    signers::{LocalWallet, Signer},
};
use pqsp_crypto::{MockZkVerifier, ProofSystemError, ZkVerifier};
use std::{str::FromStr, sync::Arc};
use thiserror::Error;

use crate::{CommitmentSubmission, VerificationReceipt, VerifierInput};

type EvmClient = SignerMiddleware<Provider<Http>, LocalWallet>;

/// Errors surfaced by an on-chain verifier adapter.
#[derive(Debug, Error)]
pub enum VerifierError {
    /// State commitment is malformed.
    #[error("state commitment cannot be zero")]
    InvalidCommitment,
    /// Storage-layer receipt is malformed.
    #[error("storage receipt must contain a valid nonzero 32-byte hex merkle root")]
    InvalidStorageRoot,
    /// The proof could not be verified.
    #[error("proof validation failed: {0}")]
    InvalidProof(#[from] ProofSystemError),
    /// The configured verifier contract address is malformed.
    #[error("invalid verifier contract address: {0}")]
    InvalidContractAddress(String),
    /// The configured signer private key is malformed.
    #[error("invalid verifier private key: {0}")]
    InvalidPrivateKey(String),
    /// The verifier transaction was dropped before a receipt was produced.
    #[error("verifier transaction was dropped before a receipt was produced")]
    TransactionDropped,
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

/// EVM-backed verifier that submits commitments to a deployed `PqspVerifier`.
///
/// This adapter performs local structural/mock-proof validation before it sends
/// the transaction. The Solidity contract currently mocks its proof check, but
/// this type still provides real on-chain activity by signing and broadcasting
/// `submitCommitment(bytes32,bytes32,bytes)` to 0G Chain.
pub struct EvmOnChainVerifier {
    contract: Contract<EvmClient>,
    zk_verifier: MockZkVerifier,
}

impl EvmOnChainVerifier {
    /// Create a verifier from chain RPC URL, signer private key, and contract address.
    pub async fn new(
        rpc_url: impl AsRef<str>,
        private_key: impl AsRef<str>,
        contract_address: impl AsRef<str>,
    ) -> Result<Self, VerifierError> {
        let provider = Provider::<Http>::try_from(rpc_url.as_ref())
            .map_err(|err| VerifierError::Transport(err.to_string()))?;
        let chain_id = provider
            .get_chainid()
            .await
            .map_err(|err| VerifierError::Transport(err.to_string()))?
            .as_u64();

        let wallet = LocalWallet::from_str(private_key.as_ref())
            .map_err(|err| VerifierError::InvalidPrivateKey(err.to_string()))?
            .with_chain_id(chain_id);

        let address = Address::from_str(contract_address.as_ref())
            .map_err(|err| VerifierError::InvalidContractAddress(err.to_string()))?;
        let client = Arc::new(SignerMiddleware::new(provider, wallet));
        let abi = AbiParser::default()
            .parse(&[
                "function submitCommitment(bytes32 stateCommitment, bytes32 storageMerkleRoot, bytes proofContext) external",
                "function verifiedState(bytes32 stateCommitment) external view returns (bool)",
            ])
            .map_err(|err| VerifierError::Transport(err.to_string()))?;

        Ok(Self {
            contract: Contract::new(address, abi, client),
            zk_verifier: MockZkVerifier,
        })
    }

    fn encode_submission(
        &self,
        submission: &CommitmentSubmission,
    ) -> Result<(H256, H256, EvmBytes), VerifierError> {
        let input = &submission.verifier_input;
        let state_commitment = H256::from(*input.state_commitment().as_bytes());
        if state_commitment.is_zero() {
            return Err(VerifierError::InvalidCommitment);
        }

        let storage_merkle_root = parse_bytes32_hex(&input.storage.merkle_root)?;
        let proof_context = EvmBytes::from(input.proof.proof_bytes.to_vec());

        Ok((state_commitment, storage_merkle_root, proof_context))
    }
}

#[async_trait]
impl OnChainVerifier for EvmOnChainVerifier {
    async fn validate(&self, input: &VerifierInput) -> Result<(), VerifierError> {
        let state_commitment = H256::from(*input.state_commitment().as_bytes());
        if state_commitment.is_zero() {
            return Err(VerifierError::InvalidCommitment);
        }

        parse_bytes32_hex(&input.storage.merkle_root)?;
        self.zk_verifier
            .verify(&input.proof_statement, &input.proof)
            .map_err(VerifierError::from)
    }

    async fn submit(
        &self,
        submission: &CommitmentSubmission,
    ) -> Result<VerificationReceipt, VerifierError> {
        self.validate(&submission.verifier_input).await?;

        let (state_commitment, storage_merkle_root, proof_context) =
            self.encode_submission(submission)?;
        let call = self
            .contract
            .method::<_, ()>(
                "submitCommitment",
                (state_commitment, storage_merkle_root, proof_context),
            )
            .map_err(|err| VerifierError::Transport(err.to_string()))?;
        let pending_tx = call
            .send()
            .await
            .map_err(|err| VerifierError::Transport(err.to_string()))?;
        let receipt = pending_tx
            .await
            .map_err(|err| VerifierError::Transport(err.to_string()))?
            .ok_or(VerifierError::TransactionDropped)?;
        let accepted = receipt.status == Some(U64::from(1u64));

        Ok(VerificationReceipt {
            accepted,
            verifier_tx_hash: Some(format!("{:#x}", receipt.transaction_hash)),
            reason: Some(if accepted {
                "EVM verifier contract accepted the commitment".to_string()
            } else {
                "EVM verifier transaction was mined but not successful".to_string()
            }),
        })
    }
}

fn parse_bytes32_hex(value: &str) -> Result<H256, VerifierError> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    let decoded = hex::decode(value).map_err(|_| VerifierError::InvalidStorageRoot)?;

    if decoded.len() != 32 || decoded.iter().all(|byte| *byte == 0) {
        return Err(VerifierError::InvalidStorageRoot);
    }

    Ok(H256::from_slice(&decoded))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_bytes32_hex_root() {
        let root = format!("0x{}", "11".repeat(32));

        assert!(parse_bytes32_hex(&root).is_ok());
    }

    #[test]
    fn rejects_malformed_bytes32_hex_root() {
        assert!(parse_bytes32_hex("0x1234").is_err());
        assert!(parse_bytes32_hex("not-hex").is_err());
    }

    #[test]
    fn rejects_zero_bytes32_hex_root() {
        let zero_root = format!("0x{}", "00".repeat(32));

        assert!(parse_bytes32_hex(&zero_root).is_err());
    }
}
