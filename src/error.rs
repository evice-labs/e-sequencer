use cipher::InvalidLength;
use scrypt::errors::{InvalidOutputLen, InvalidParams};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SequencerError {
    #[error("P2P communication error: {0}")]
    P2pError(String),
    #[error("Consensus threshold not met: expected {expected}, got {actual}")]
    QuorumNotMet { expected: usize, actual: usize },
    #[error("Cryptographic signature verification failed")]
    InvalidSignature,
    #[error("Invalid batch format or structure")]
    InvalidBatch,
    #[error("Peer not found or unknown in address book: {0}")]
    UnknownPeer(String),
}

#[derive(Error, Debug)]
pub enum KeystoreError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("Hex decoding error: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("Scrypt params error: {0}")]
    ScryptParams(#[from] InvalidParams),
    #[error("Scrypt output length error: {0}")]
    ScryptOutputLen(#[from] InvalidOutputLen),
    #[error("Cipher error: {0}")]
    Cipher(#[from] InvalidLength),
    #[error("Padding error during decryption")]
    PaddingError,
    #[error("Invalid password or corrupted keystore")]
    InvalidPassword,
    #[error("Decrypted key has invalid length")]
    InvalidKeyLength,
    #[error("Unsupported keystore version: {0}")]
    UnsupportedVersion(u8),
    #[error("AEAD encryption/decryption error")]
    AeadError,
}

impl From<chacha20poly1305::Error> for KeystoreError {
    fn from(_: chacha20poly1305::Error) -> Self {
        KeystoreError::AeadError
    }
}
