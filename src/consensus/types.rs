use bincode::{Decode, Encode};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes};
use sha2::{Digest, Sha256};

use crate::{crypto::KeyPair, Address, BatchHeader, PayloadBatch, Signature};

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone)]
pub struct PendingBatch {
    pub header: BatchHeader,
    pub payloads: Vec<crate::AppPayload>,
    pub parent_qc: QuorumCertificate,
    pub round: u64,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone)]
pub struct VelocityVote {
    pub round_id: u64,
    pub batch_hash: Vec<u8>,
    pub voter_address: Address,
    #[serde(with = "serde_bytes")]
    pub signature: Signature,
}

impl VelocityVote {
    pub fn sign(mut self, keypair: &KeyPair) -> Self {
        let data_to_sign = self.canonical_bytes(&keypair.public_key_bytes());
        self.signature = keypair.sign(&data_to_sign).to_vec();
        self
    }

    pub fn canonical_bytes(&self, voter_public_key: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.round_id.to_be_bytes());
        data.extend_from_slice(&self.batch_hash);
        data.extend_from_slice(voter_public_key);
        data
    }
}

#[serde_as]
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone)]
pub struct OptimisticConfirmation {
    pub header: BatchHeader,
    #[serde_as(as = "Vec<Bytes>")]
    pub payload_hashes: Vec<Vec<u8>>,
    pub parent_qc: QuorumCertificate,
    pub round: u64,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone)]
pub enum ConsensusMessage {
    IntentBatchProposal(Box<PayloadBatch>),
    VelocityVoteMsg(VelocityVote),
    NewQuorumCertificate(QuorumCertificate),
}

impl ConsensusMessage {
    pub fn hash(&self) -> [u8; 32] {
        borsh::to_vec(self)
            .map(|encoded| Sha256::digest(&encoded).into())
            .unwrap_or_default()
    }
}

#[serde_as]
#[derive(
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Decode,
    Encode,
)]
pub struct QuorumCertificate {
    pub batch_hash: Vec<u8>,
    pub view_number: u64,
    #[serde_as(as = "Vec<(_, Bytes)>")]
    pub signatures: Vec<(Address, Signature)>,
}

impl QuorumCertificate {
    pub fn genesis_qc() -> Self {
        Self {
            batch_hash: vec![0; 32],
            view_number: 0,
            signatures: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{KeyPair, PUBLIC_KEY_SIZE};

    #[test]
    fn test_velocity_vote_signing_and_canonical_bytes() {
        let keypair = KeyPair::new();
        let batch_hash = vec![1, 2, 3, 4];
        let voter_address = crate::Address([0u8; 20]);

        let vote = VelocityVote {
            round_id: 1,
            batch_hash: batch_hash.clone(),
            voter_address,
            signature: vec![],
        };

        let pk_bytes = keypair.public_key_bytes();
        let canonical = vote.canonical_bytes(&pk_bytes);

        assert_eq!(canonical.len(), 8 + 4 + PUBLIC_KEY_SIZE);

        let signed_vote = vote.sign(&keypair);
        assert!(!signed_vote.signature.is_empty());
    }

    #[test]
    fn test_quorum_certificate_genesis() {
        let qc = QuorumCertificate::genesis_qc();
        assert_eq!(qc.view_number, 0);
        assert_eq!(qc.batch_hash, vec![0; 32]);
        assert!(qc.signatures.is_empty());
    }
}
