use libp2p::PeerId;
use lru::LruCache;
use std::{
    collections::{HashMap, HashSet},
    num::NonZeroUsize,
    sync::Arc,
    time::Instant,
};
use tokio::sync::{oneshot, RwLock};

use super::types::{ConsensusMessage, PendingBatch, QuorumCertificate, VelocityVote};
use crate::{p2p::SyncResponse, PayloadBatch};

/// Maximum number of confirmed batches to retain in memory before pruning.
const MAX_CONFIRMED_BATCHES: usize = 256;

pub type ConsensusMsgTuple = (
    ConsensusMessage,
    PeerId,
    Option<oneshot::Sender<SyncResponse>>,
);

#[derive(Clone)]
pub struct ConsensusState {
    pub core_state: Arc<RwLock<CoreConsensusState>>,
    pub pending_proposals: Arc<RwLock<HashMap<Vec<u8>, PendingBatch>>>,
    pub proposal_queues: Arc<RwLock<ProposalQueues>>,
    pub recently_processed_hashes: Arc<RwLock<LruCache<[u8; 32], ()>>>,
}

pub struct CoreConsensusState {
    pub current_round: u64,
    pub current_step: u64,
    pub step_start_time: Instant,
    pub highest_seen_qc: QuorumCertificate,
    pub velocity_votes: HashMap<Vec<u8>, Vec<VelocityVote>>,
    pub processed_optimistic_batches: HashSet<Vec<u8>>,
    pub optimistically_confirmed_batches: Vec<PayloadBatch>,
}

impl CoreConsensusState {
    /// Prune stale data to prevent unbounded memory growth.
    /// Removes votes for already-processed batches and trims
    /// the confirmed batch history to `MAX_CONFIRMED_BATCHES`.
    pub fn prune_stale_data(&mut self) {
        // MEM-2: Remove votes for batches that have already reached quorum
        self.velocity_votes
            .retain(|hash, _| !self.processed_optimistic_batches.contains(hash));

        // MEM-1: Keep only the most recent confirmed batches
        if self.optimistically_confirmed_batches.len() > MAX_CONFIRMED_BATCHES {
            let drain_count = self.optimistically_confirmed_batches.len() - MAX_CONFIRMED_BATCHES;
            self.optimistically_confirmed_batches.drain(..drain_count);
        }
    }
}

pub struct ProposalQueues {
    pub premature_proposals: HashMap<u64, Vec<ConsensusMsgTuple>>,
    pub stale_qc_request: HashMap<Vec<u8>, (u64, Instant)>,
}

impl ConsensusState {
    pub fn new(initial_qc: QuorumCertificate) -> Self {
        Self {
            core_state: Arc::new(RwLock::new(CoreConsensusState {
                current_round: 0,
                current_step: 0,
                step_start_time: Instant::now(),
                highest_seen_qc: initial_qc.clone(),
                velocity_votes: HashMap::new(),
                processed_optimistic_batches: HashSet::new(),
                optimistically_confirmed_batches: Vec::new(),
            })),
            pending_proposals: Arc::new(RwLock::new(HashMap::new())),
            proposal_queues: Arc::new(RwLock::new(ProposalQueues {
                premature_proposals: HashMap::new(),
                stale_qc_request: HashMap::new(),
            })),
            recently_processed_hashes: Arc::new(RwLock::new(LruCache::new(
                NonZeroUsize::new(1000).unwrap(),
            ))),
        }
    }

    /// Prune pending proposals that have already been confirmed.
    /// Call this periodically or after each batch confirmation.
    pub async fn prune_confirmed_proposals(&self) {
        let confirmed_hashes: HashSet<Vec<u8>> = {
            let core = self.core_state.read().await;
            core.processed_optimistic_batches.clone()
        };
        let mut proposals = self.pending_proposals.write().await;
        proposals.retain(|hash, _| !confirmed_hashes.contains(hash));
    }
}
