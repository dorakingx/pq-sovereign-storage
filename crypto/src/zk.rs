use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::StateCommitment;

const MOCK_PROOF_DOMAIN: &[u8] = b"pqsp:v1:mock-proof";

/// Public statement supplied to a proving system.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofStatement {
    /// State commitment being proven about.
    pub state_commitment: StateCommitment,
    /// Domain or tenant-specific context bound into the proof transcript.
    pub context: Vec<u8>,
    /// Public inputs as human-readable key/value style strings for prototyping.
    pub public_inputs: Vec<String>,
}

/// Private proving witness.
///
/// The witness is intentionally opaque in the scaffold and is zeroized on drop
/// so it cannot be logged or accidentally retained in memory.
pub struct ProofWitness {
    private_input: Zeroizing<Vec<u8>>,
}

impl ProofWitness {
    /// Construct a new private witness from raw bytes.
    pub fn new(private_input: impl Into<Vec<u8>>) -> Self {
        Self {
            private_input: Zeroizing::new(private_input.into()),
        }
    }

    /// Return the witness length in bytes.
    pub fn len(&self) -> usize {
        self.private_input.len()
    }

    /// Check whether the witness is empty.
    pub fn is_empty(&self) -> bool {
        self.private_input.is_empty()
    }
}

/// Descriptor of the proving backend used to create a proof bundle.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofSystemDescriptor {
    /// Human-readable proving backend name.
    pub name: String,
    /// Version string for the proving backend or protocol.
    pub version: String,
}

impl ProofSystemDescriptor {
    /// Descriptor used by the scaffold's deterministic mock proving backend.
    pub fn mock() -> Self {
        Self {
            name: "mock-zk".to_string(),
            version: "0.1.0".to_string(),
        }
    }
}

/// Serialized proof output plus metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofBundle {
    /// Proving system information for the verifier boundary.
    pub system: ProofSystemDescriptor,
    /// Encoded proof bytes.
    pub proof_bytes: Bytes,
    /// Public inputs duplicated here to ease transport into verifier clients.
    pub public_inputs: Vec<String>,
}

/// Errors produced by the proving scaffold.
#[derive(Debug, Error)]
pub enum ProofSystemError {
    /// Canonical statement serialization failed.
    #[error("failed to serialize proof statement: {0}")]
    StatementEncoding(#[from] serde_json::Error),
    /// The proof bundle failed deterministic mock verification.
    #[error("mock proof verification failed")]
    InvalidMockProof,
}

/// Abstract proof generation interface.
pub trait ZkProver: Send + Sync {
    /// Generate a proof for a public statement and private witness.
    fn prove(
        &self,
        statement: &ProofStatement,
        witness: &ProofWitness,
    ) -> Result<ProofBundle, ProofSystemError>;
}

/// Abstract proof verification interface.
pub trait ZkVerifier: Send + Sync {
    /// Verify a proof bundle against the supplied public statement.
    fn verify(
        &self,
        statement: &ProofStatement,
        proof: &ProofBundle,
    ) -> Result<(), ProofSystemError>;
}

/// Deterministic development prover.
///
/// This is intentionally not a real zero-knowledge system. It gives the rest
/// of the protocol a stable interface while production engineers choose a real
/// backend later.
#[derive(Debug, Default)]
pub struct MockZkProver;

impl ZkProver for MockZkProver {
    fn prove(
        &self,
        statement: &ProofStatement,
        _witness: &ProofWitness,
    ) -> Result<ProofBundle, ProofSystemError> {
        let proof_bytes = mock_proof_bytes(statement)?;

        Ok(ProofBundle {
            system: ProofSystemDescriptor::mock(),
            proof_bytes: Bytes::from(proof_bytes),
            public_inputs: statement.public_inputs.clone(),
        })
    }
}

/// Deterministic development verifier corresponding to [`MockZkProver`].
#[derive(Debug, Default)]
pub struct MockZkVerifier;

impl ZkVerifier for MockZkVerifier {
    fn verify(
        &self,
        statement: &ProofStatement,
        proof: &ProofBundle,
    ) -> Result<(), ProofSystemError> {
        let expected = mock_proof_bytes(statement)?;

        if proof.system.name != "mock-zk"
            || proof.proof_bytes.as_ref() != expected.as_slice()
            || proof.public_inputs != statement.public_inputs
        {
            return Err(ProofSystemError::InvalidMockProof);
        }

        Ok(())
    }
}

fn mock_proof_bytes(statement: &ProofStatement) -> Result<Vec<u8>, ProofSystemError> {
    let mut hasher = Shake256::default();
    let canonical_statement = serde_json::to_vec(statement)?;

    hasher.update(&(MOCK_PROOF_DOMAIN.len() as u64).to_le_bytes());
    hasher.update(MOCK_PROOF_DOMAIN);
    hasher.update(&(canonical_statement.len() as u64).to_le_bytes());
    hasher.update(&canonical_statement);

    let mut reader = hasher.finalize_xof();
    let mut output = vec![0u8; 64];
    reader.read(&mut output);
    Ok(output)
}
