//! Core protocol types for the on-chain verifier boundary.
//!
//! The crate defines submission payloads and verifier traits, plus both a local
//! mock verifier and an ethers-rs EVM adapter for the deployed `PqspVerifier`.

pub mod types;
pub mod verifier;

pub use types::{
    CommitmentSubmission, ProofMetadata, StorageReceiptRef, VerificationReceipt, VerifierInput,
};
pub use verifier::{EvmOnChainVerifier, MockOnChainVerifier, OnChainVerifier, VerifierError};
