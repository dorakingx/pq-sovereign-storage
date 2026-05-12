use bytes::Bytes;
use chacha20poly1305::{
    aead::{Aead, AeadCore, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use rand_core::{CryptoRng, RngCore};
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// Version byte encoded into the upload envelope.
pub const PAYLOAD_ENVELOPE_VERSION: u8 = 1;

const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 24;

/// Symmetric encryption key stored in zeroizing memory.
pub struct EncryptionKey(SecretBox<[u8; KEY_BYTES]>);

impl EncryptionKey {
    /// Generate a fresh random key using the caller's RNG.
    pub fn generate(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let mut key = [0u8; KEY_BYTES];
        rng.fill_bytes(&mut key);
        Self(SecretBox::new(Box::new(key)))
    }

    /// Construct a key from pre-existing key material.
    pub fn from_bytes(bytes: [u8; KEY_BYTES]) -> Self {
        Self(SecretBox::new(Box::new(bytes)))
    }

    fn expose(&self) -> &[u8; KEY_BYTES] {
        self.0.expose_secret()
    }
}

impl fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EncryptionKey([REDACTED])")
    }
}

/// Versioned encrypted payload envelope.
///
/// The envelope format is `version || nonce || ciphertext`, where the
/// ciphertext includes the AEAD authentication tag.
#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedPayload {
    version: u8,
    nonce: [u8; NONCE_BYTES],
    ciphertext: Bytes,
}

impl EncryptedPayload {
    /// Create a new payload from its structured components.
    pub fn new(version: u8, nonce: [u8; NONCE_BYTES], ciphertext: Vec<u8>) -> Self {
        Self {
            version,
            nonce,
            ciphertext: Bytes::from(ciphertext),
        }
    }

    /// Access the ciphertext bytes.
    pub fn ciphertext(&self) -> &[u8] {
        self.ciphertext.as_ref()
    }

    /// Access the nonce bytes.
    pub fn nonce(&self) -> &[u8; NONCE_BYTES] {
        &self.nonce
    }

    /// Return the envelope version.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Return the ciphertext length.
    pub fn ciphertext_len(&self) -> usize {
        self.ciphertext.len()
    }

    /// Serialize the envelope into upload-ready bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(1 + NONCE_BYTES + self.ciphertext.len());
        encoded.push(self.version);
        encoded.extend_from_slice(&self.nonce);
        encoded.extend_from_slice(self.ciphertext());
        encoded
    }

    /// Deserialize an envelope from upload-ready bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EncryptionError> {
        if bytes.len() < 1 + NONCE_BYTES {
            return Err(EncryptionError::MalformedEnvelope);
        }

        let version = bytes[0];
        if version != PAYLOAD_ENVELOPE_VERSION {
            return Err(EncryptionError::UnsupportedVersion(version));
        }

        let mut nonce = [0u8; NONCE_BYTES];
        nonce.copy_from_slice(&bytes[1..1 + NONCE_BYTES]);

        Ok(Self::new(
            version,
            nonce,
            bytes[1 + NONCE_BYTES..].to_vec(),
        ))
    }
}

impl fmt::Debug for EncryptedPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedPayload")
            .field("version", &self.version)
            .field("nonce", &hex::encode(self.nonce))
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

/// Errors returned by payload encryption and decryption.
#[derive(Debug, Error)]
pub enum EncryptionError {
    /// The payload envelope could not be parsed safely.
    #[error("payload envelope is malformed")]
    MalformedEnvelope,
    /// The envelope version is unsupported by this crate version.
    #[error("unsupported payload envelope version: {0}")]
    UnsupportedVersion(u8),
    /// AEAD encryption or authentication failed.
    #[error("authenticated encryption failed")]
    AeadFailure,
}

/// Abstraction over authenticated-encryption backends.
pub trait PayloadEncryptor: Send + Sync {
    /// Encrypt plaintext with additional authenticated data.
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<EncryptedPayload, EncryptionError>;

    /// Decrypt and authenticate a versioned payload envelope.
    fn decrypt(&self, payload: &EncryptedPayload, aad: &[u8]) -> Result<Vec<u8>, EncryptionError>;
}

/// XChaCha20-Poly1305 encryptor for storage payloads.
///
/// XChaCha20-Poly1305 is chosen because it offers misuse-resistant nonce space
/// in practice, is widely deployed, and cleanly supports large randomized
/// envelopes without forcing nonce reuse coordination.
pub struct XChaCha20Poly1305Encryptor {
    key: EncryptionKey,
}

impl XChaCha20Poly1305Encryptor {
    /// Create a new encryptor from key material managed by the caller.
    pub fn new(key: EncryptionKey) -> Self {
        Self { key }
    }
}

impl fmt::Debug for XChaCha20Poly1305Encryptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("XChaCha20Poly1305Encryptor([REDACTED KEY])")
    }
}

impl PayloadEncryptor for XChaCha20Poly1305Encryptor {
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<EncryptedPayload, EncryptionError> {
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.expose())
            .map_err(|_| EncryptionError::AeadFailure)?;
        let nonce = XChaCha20Poly1305::generate_nonce(&mut rand_core::OsRng);
        let mut nonce_bytes = [0u8; NONCE_BYTES];
        nonce_bytes.copy_from_slice(&nonce);

        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| EncryptionError::AeadFailure)?;

        Ok(EncryptedPayload::new(
            PAYLOAD_ENVELOPE_VERSION,
            nonce_bytes,
            ciphertext,
        ))
    }

    fn decrypt(&self, payload: &EncryptedPayload, aad: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if payload.version() != PAYLOAD_ENVELOPE_VERSION {
            return Err(EncryptionError::UnsupportedVersion(payload.version()));
        }

        let cipher = XChaCha20Poly1305::new_from_slice(self.key.expose())
            .map_err(|_| EncryptionError::AeadFailure)?;

        cipher
            .decrypt(
                XNonce::from_slice(payload.nonce()),
                Payload {
                    msg: payload.ciphertext(),
                    aad,
                },
            )
            .map_err(|_| EncryptionError::AeadFailure)
    }
}
