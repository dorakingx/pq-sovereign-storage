//! Post-quantum-oriented cryptographic building blocks for sovereign storage.
//!
//! The current scaffold uses standardized hash-based commitments via SHAKE256,
//! authenticated encryption via XChaCha20-Poly1305, and trait-based proof
//! interfaces so a production proving system can be introduced later without
//! rewriting upstream protocol crates.

pub mod commitment;
pub mod encryption;
pub mod zk;

pub use commitment::{
    Shake256Committer, StateCommitment, StateCommitter, DEFAULT_COMMITMENT_DOMAIN,
};
pub use encryption::{
    EncryptedPayload, EncryptionError, EncryptionKey, PayloadEncryptor,
    XChaCha20Poly1305Encryptor, PAYLOAD_ENVELOPE_VERSION,
};
pub use zk::{
    MockZkProver, MockZkVerifier, ProofBundle, ProofStatement, ProofSystemDescriptor,
    ProofSystemError, ProofWitness, ZkProver, ZkVerifier,
};
