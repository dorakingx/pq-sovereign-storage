use serde::{Deserialize, Serialize};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use std::fmt;

/// Domain separator used for protocol state commitments.
pub const DEFAULT_COMMITMENT_DOMAIN: &[u8] = b"pqsp:v1:state-commitment";

/// Fixed-size state commitment derived from a post-quantum-resistant hash.
///
/// SHAKE256 is selected because it is standardized in FIPS 202, conservative,
/// and retains the standard post-quantum security profile expected from
/// sponge-based hash commitments.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StateCommitment([u8; 32]);

impl StateCommitment {
    /// Number of bytes emitted by the commitment.
    pub const BYTE_LEN: usize = 32;

    /// Create a new commitment from raw bytes.
    pub fn new(bytes: [u8; Self::BYTE_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the inner commitment bytes.
    pub fn as_bytes(&self) -> &[u8; Self::BYTE_LEN] {
        &self.0
    }

    /// Render the commitment as a hexadecimal string with `0x` prefix.
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }
}

impl fmt::Debug for StateCommitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("StateCommitment").field(&self.to_hex()).finish()
    }
}

impl fmt::Display for StateCommitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Abstraction over state-commitment primitives.
pub trait StateCommitter: Send + Sync {
    /// Commit to a message under a caller-specified context.
    fn commit(&self, message: &[u8], context: &[u8]) -> StateCommitment;
}

/// SHAKE256-based state committer with explicit domain separation.
#[derive(Clone, Debug)]
pub struct Shake256Committer {
    domain_separator: Vec<u8>,
}

impl Shake256Committer {
    /// Create a committer with a custom domain separator.
    pub fn new(domain_separator: impl Into<Vec<u8>>) -> Self {
        Self {
            domain_separator: domain_separator.into(),
        }
    }
}

impl Default for Shake256Committer {
    fn default() -> Self {
        Self::new(DEFAULT_COMMITMENT_DOMAIN)
    }
}

impl StateCommitter for Shake256Committer {
    fn commit(&self, message: &[u8], context: &[u8]) -> StateCommitment {
        let mut hasher = Shake256::default();

        // Length-prefix each field so the transcript is unambiguous even when
        // contexts or messages are attacker-controlled byte strings.
        hasher.update(&(self.domain_separator.len() as u64).to_le_bytes());
        hasher.update(&self.domain_separator);
        hasher.update(&(context.len() as u64).to_le_bytes());
        hasher.update(context);
        hasher.update(&(message.len() as u64).to_le_bytes());
        hasher.update(message);

        let mut reader = hasher.finalize_xof();
        let mut output = [0u8; StateCommitment::BYTE_LEN];
        reader.read(&mut output);

        StateCommitment::new(output)
    }
}
