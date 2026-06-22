use borsh::{BorshDeserialize, BorshSerialize};
use libp2p::{
    gossipsub, identify, kad, request_response, swarm::NetworkBehaviour, Multiaddr, PeerId,
};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;
use tokio::sync::oneshot;

use crate::{
    consensus::{ConsensusMessage, OptimisticConfirmation, PendingBatch, VelocityVote},
    Address, AppPayload,
};

pub const INITIAL_PEER_SCORE: i32 = 0;
pub const MAX_PEER_SCORE: i32 = 100;
pub const BAN_THRESHOLD: i32 = -50;
pub const PENALTY_DESERIALIZATION_ERROR: i32 = -5;
pub const REWARD_VALID_MESSAGE: i32 = 2;
pub const BAN_DURATION: std::time::Duration = std::time::Duration::from_secs(1800);
pub const NETWORK_STABILITY_WINDOW: std::time::Duration = std::time::Duration::from_secs(3);

#[derive(Debug)]
pub struct PeerInfo {
    pub score: i32,
    pub is_banned: bool,
    pub ban_until: Option<Instant>,
}

impl PeerInfo {
    pub fn new() -> Self {
        Self {
            score: INITIAL_PEER_SCORE,
            is_banned: false,
            ban_until: None,
        }
    }

    pub fn apply_penalty(&mut self, penalty: i32) {
        self.score = (self.score + penalty).max(BAN_THRESHOLD - 1);
        if self.score <= BAN_THRESHOLD {
            self.is_banned = true;
            self.ban_until = Some(Instant::now() + BAN_DURATION);
            warn!(
                "Peer banned because score reached {}. Blocked until {:?}.",
                self.score, self.ban_until
            );
        }
    }

    pub fn apply_reward(&mut self, reward: i32) {
        self.score = (self.score + reward).min(MAX_PEER_SCORE);
    }
}

#[derive(Debug)]
pub struct PendingResponse {
    pub channel: request_response::ResponseChannel<SyncResponse>,
    pub response: SyncResponse,
}

#[derive(NetworkBehaviour)]
pub struct AppBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub identify: identify::Behaviour,
    pub sync: request_response::Behaviour<
        request_response::cbor::codec::Codec<SyncRequest, SyncResponse>,
    >,
}

#[derive(Debug)]
pub enum P2pCommand {
    BroadcastConsensusMessage(ConsensusMessage),
    SendDirectRequest {
        destination: PeerId,
        request: SyncRequest,
    },
    ApplyPenalty {
        peer_id: PeerId,
        penalty: i32,
    },
    DialAddress(Multiaddr),
    GetConnectedPeers(oneshot::Sender<Vec<PeerId>>),
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, Serialize, Deserialize)]
pub enum SyncRequest {
    InformAboutPeers(Vec<String>),
    ConsensusRequest(Box<ConsensusMessage>),
    GetFullProposal(Vec<u8>),
    FullProposalForCommittee {
        confirmation: Box<OptimisticConfirmation>,
        payloads: Vec<AppPayload>,
    },
    SubmitVote(Box<VelocityVote>),
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, Serialize, Deserialize)]
pub enum SyncResponse {
    Peers(Vec<String>),
    ConsensusResponse(Option<Box<ConsensusMessage>>),
    FullProposal(Option<Box<PendingBatch>>),
    FullProposalReceivedAck,
    VoteAck,
    PeersReceivedAck,
}

#[derive(Clone, Debug)]
pub struct PeerIdentityInfo {
    pub peer_id: PeerId,
    pub multiaddr: Multiaddr,
    pub public_key: Option<Vec<u8>>,
    pub vrf_public_key: Option<Vec<u8>>,
    pub version: u64,
}

#[derive(Default, Clone)]
pub struct AddressBook {
    pub address_to_identity: HashMap<Address, PeerIdentityInfo>,
}

impl AddressBook {
    pub fn update_from_genesis(&mut self, genesis: &crate::genesis::Genesis) {
        let previous_size = self.address_to_identity.len();

        for (addr_str, account) in &genesis.accounts {
            if let Some(multiaddr_str) = &account.network_identity {
                if let Ok(addr_bytes) = hex::decode(addr_str.trim_start_matches("0x")) {
                    if addr_bytes.len() == 20 {
                        let mut validator_addr = [0u8; 20];
                        validator_addr.copy_from_slice(&addr_bytes);

                        if let Ok(multiaddr) = multiaddr_str.parse::<libp2p::Multiaddr>() {
                            if let Some(peer_id) = multiaddr.iter().find_map(|p| {
                                if let libp2p::multiaddr::Protocol::P2p(peer_id) = p {
                                    Some(peer_id)
                                } else {
                                    None
                                }
                            }) {
                                let pub_key_bytes =
                                    hex::decode(account.public_key.trim_start_matches("0x")).ok();
                                
                                let vrf_pub_key_bytes = account.vrf_public_key.as_ref().and_then(|k| hex::decode(k.trim_start_matches("0x")).ok());

                                let current_info = self
                                    .address_to_identity
                                    .entry(validator_addr.into())
                                    .or_insert_with(|| PeerIdentityInfo {
                                        peer_id,
                                        multiaddr: multiaddr.clone(),
                                        public_key: pub_key_bytes,
                                        vrf_public_key: vrf_pub_key_bytes,
                                        version: 0,
                                    });

                                if current_info.multiaddr != multiaddr {
                                    current_info.multiaddr = multiaddr;
                                    current_info.version += 1;
                                    info!(
                                        "[P2P] Peer info updated for validator: {:?}",
                                        validator_addr
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        let new_size = self.address_to_identity.len();
        if new_size > previous_size {
            info!(
                "[P2P] {} new validator peers found in Genesis.",
                new_size - previous_size
            );
        }
    }

    pub fn get_peer_id(&self, address: &Address) -> Option<PeerId> {
        self.address_to_identity
            .get(address)
            .map(|info| info.peer_id)
    }

    pub fn get_address(&self, peer_id_to_find: &PeerId) -> Option<Address> {
        for (addr, info) in &self.address_to_identity {
            if &info.peer_id == peer_id_to_find {
                return Some(*addr);
            }
        }
        None
    }

    pub fn get_all_peer_ids(&self) -> Vec<PeerId> {
        self.address_to_identity
            .values()
            .map(|info| info.peer_id)
            .collect()
    }
}
