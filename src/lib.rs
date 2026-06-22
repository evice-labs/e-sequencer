use bincode::{Decode, Encode};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::convert::AsRef;

use crate::crypto::{ADDRESS_SIZE, PUBLIC_KEY_SIZE};

pub type Signature = Vec<u8>;

pub mod consensus;
pub mod crypto;
pub mod error;
pub mod genesis;
pub mod keystore;
pub mod p2p;

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    PartialOrd,
    Ord,
)]
pub struct Address(pub [u8; ADDRESS_SIZE]);

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 20]> for Address {
    fn from(bytes: [u8; 20]) -> Self {
        Address(bytes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct FullPublicKey(#[serde(with = "serde_bytes")] pub [u8; PUBLIC_KEY_SIZE]);

impl BorshSerialize for FullPublicKey {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.0)?;
        Ok(())
    }
}

impl BorshDeserialize for FullPublicKey {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut bytes = [0u8; PUBLIC_KEY_SIZE];
        reader.read_exact(&mut bytes)?;
        Ok(FullPublicKey(bytes))
    }
}

impl AsRef<[u8]> for FullPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Default for FullPublicKey {
    fn default() -> Self {
        Self([0u8; PUBLIC_KEY_SIZE])
    }
}

#[derive(
    BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone, Eq, Encode, Decode,
)]
pub struct AppPayload(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl PartialEq for AppPayload {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl std::hash::Hash for AppPayload {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl AppPayload {
    pub fn message_hash(&self) -> Vec<u8> {
        let mut hasher = sha2::Sha256::new();
        hasher.update(&self.0);
        hasher.finalize().to_vec()
    }
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct BatchHeader {
    pub index: u64,
    #[serde(with = "serde_bytes")]
    pub prev_hash: Vec<u8>,
    pub timestamp: u64,
    #[serde(with = "serde_bytes")]
    pub payloads_root: Vec<u8>,
    pub authority: Address,
    #[serde(with = "serde_bytes")]
    pub vrf_output: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub vrf_proof: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub signature: Signature,
}

impl BatchHeader {
    pub fn calculate_hash(&self) -> Vec<u8> {
        let mut hasher = sha2::Sha256::new();
        hasher.update(&self.index.to_be_bytes());
        hasher.update(&self.prev_hash);
        hasher.update(&self.timestamp.to_be_bytes());
        hasher.update(&self.payloads_root);
        hasher.update(self.authority.as_ref());
        hasher.update(&self.vrf_output);
        hasher.update(&self.vrf_proof);
        hasher.update(&self.signature);
        hasher.finalize().to_vec()
    }

    pub fn canonical_bytes_for_signing(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.index.to_be_bytes());
        data.extend_from_slice(&self.prev_hash);
        data.extend_from_slice(&self.timestamp.to_be_bytes());
        data.extend_from_slice(&self.payloads_root);
        data.extend_from_slice(self.authority.as_ref());
        data.extend_from_slice(&self.vrf_output);
        data.extend_from_slice(&self.vrf_proof);
        data
    }
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone)]
pub struct PayloadBatch {
    pub header: BatchHeader,
    pub payloads: Vec<AppPayload>,
    pub justify: crate::consensus::QuorumCertificate,
    pub round: u64,
}

impl PayloadBatch {
    pub fn calculate_payloads_root(payloads: &[AppPayload]) -> Vec<u8> {
        let mut hasher = sha2::Sha256::new();
        for payload in payloads {
            hasher.update(payload.message_hash());
        }
        hasher.finalize().to_vec()
    }
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone)]
pub enum ChainMessage {
    NewPayload(AppPayload),
    NewConsensusMessage(crate::consensus::ConsensusMessage),
}
