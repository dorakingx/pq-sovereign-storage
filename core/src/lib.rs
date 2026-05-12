//! Core protocol types for the on-chain verifier boundary.
//!
//! This crate intentionally avoids committing to a concrete 0G Chain client.
//! Instead it defines submission payloads and verifier traits that can later be
//! implemented by an EVM/0G adapter without changing upstream application code.

pub mod types;
pub mod verifier;

pub use types::{
    CommitmentSubmission, ProofMetadata, StorageReceiptRef, VerificationReceipt, VerifierInput,
};
pub use verifier::{MockOnChainVerifier, OnChainVerifier, VerifierError};
