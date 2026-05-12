use bytes::Bytes;
use pqsp_core::StorageReceiptRef;
use pqsp_crypto::{EncryptedPayload, ProofBundle, ProofStatement, StateCommitment};
use serde::{Deserialize, Serialize};

/// Descriptive metadata attached to an upload payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PayloadMetadata {
    /// Version of the outer protocol payload schema.
    pub protocol_version: u8,
    /// Content type emitted to 0G Storage.
    pub content_type: String,
    /// Encryption scheme applied to the raw plaintext.
    pub encryption_scheme: String,
    /// Commitment scheme used to derive the state commitment.
    pub commitment_scheme: String,
    /// Proof system identifier used for `proof`.
    pub proof_system: String,
}

/// Final upload payload serialized and stored on 0G Storage.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UploadPayload {
    /// Schema version of the upload payload.
    pub version: u8,
    /// Encrypted bytes encoded as `version || nonce || ciphertext`.
    pub encrypted_blob: Bytes,
    /// Post-quantum state commitment over the encrypted envelope.
    pub state_commitment: StateCommitment,
    /// Public statement for proof verification.
    pub proof_statement: ProofStatement,
    /// Proof material that can later be submitted to an on-chain verifier.
    pub proof: ProofBundle,
    /// Human-readable metadata about the outer payload.
    pub metadata: PayloadMetadata,
}

impl UploadPayload {
    /// Encode the outer payload into upload-ready JSON bytes.
    pub fn encode(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec_pretty(self)
    }

    /// Return a compact summary useful for logging and demos.
    pub fn summary(&self) -> UploadPayloadSummary {
        UploadPayloadSummary {
            version: self.version,
            encrypted_blob_bytes: self.encrypted_blob.len(),
            state_commitment_hex: self.state_commitment.to_hex(),
            proof_system: format!(
                "{}@{}",
                self.proof.system.name, self.proof.system.version
            ),
        }
    }
}

/// Prepared upload bundle emitted before 0G submission.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreparedUpload {
    /// Parsed encrypted envelope before outer serialization.
    pub envelope: EncryptedPayload,
    /// Public proof statement paired with the commitment.
    pub proof_statement: ProofStatement,
    /// Proof bundle generated for the statement.
    pub proof: ProofBundle,
    /// State commitment over the encrypted envelope.
    pub state_commitment: StateCommitment,
    /// Final structured payload to store on 0G.
    pub upload_payload: UploadPayload,
    /// Serialized bytes that will be sent to 0G Storage.
    pub encoded_payload: Bytes,
}

/// Compact printable view of an upload payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UploadPayloadSummary {
    /// Payload schema version.
    pub version: u8,
    /// Length of the encrypted blob in bytes.
    pub encrypted_blob_bytes: usize,
    /// Hex rendering of the state commitment.
    pub state_commitment_hex: String,
    /// Proof system identifier in `name@version` form.
    pub proof_system: String,
}

/// Result returned after staging or uploading a payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UploadReceipt {
    /// 0G storage receipt produced by the uploader.
    pub storage: StorageReceiptRef,
    /// State commitment paired with the uploaded payload.
    pub state_commitment: StateCommitment,
    /// Number of payload bytes staged or uploaded.
    pub payload_bytes: usize,
}
