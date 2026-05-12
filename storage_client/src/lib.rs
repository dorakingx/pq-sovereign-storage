//! 0G Storage client integration and upload-pipeline assembly.
//!
//! The service in this crate owns the protocol's data flow:
//! encrypt plaintext, derive a post-quantum state commitment, build a proof
//! statement, serialize the final upload payload, and submit it to 0G Storage.

pub mod client;
pub mod error;
pub mod payload;

pub use client::{
    StorageClient, UploadFinality, UploadMode, ZeroGStorageConfig, ZeroGStorageService,
};
pub use error::StorageClientError;
pub use payload::{
    PayloadMetadata, PreparedUpload, UploadPayload, UploadPayloadSummary, UploadReceipt,
};
