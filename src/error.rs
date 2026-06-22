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
