use async_recursion::async_recursion;
use libp2p::PeerId;
use log::{debug, error, info, warn};
use rand::{seq::SliceRandom, SeedableRng};
use sha2::Digest;
use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    sync::{mpsc, oneshot, Mutex, RwLock},
    time::interval,
};

use crate::{
    crypto::{self, ValidatorKeys},
    p2p::{AddressBook, P2pCommand, SyncRequest, SyncResponse},
    Address, AppPayload, BatchHeader, ChainMessage, PayloadBatch,
};

use super::{
    state::{ConsensusMsgTuple, ConsensusState},
    types::{ConsensusMessage, PendingBatch, QuorumCertificate, VelocityVote},
};


/// The `ConsensusEngine` handles the PBFT-style sequencer consensus mechanism.
/// It works alongside the networking layer to order batches of intents and produce Quorum Certificates (QC).
#[derive(Clone)]
pub struct ConsensusEngine {
    pub my_address: Address,
    pub validator_keys: Arc<ValidatorKeys>,
    pub p2p_cmd_tx: mpsc::Sender<P2pCommand>,
    pub state: ConsensusState,
    pub consensus_ready: Arc<AtomicBool>,
    pub address_book: Arc<Mutex<AddressBook>>,
    pub pending_tx_requests: Arc<RwLock<HashMap<u64, oneshot::Sender<Vec<AppPayload>>>>>,
    pub tx_gossip: mpsc::Sender<ChainMessage>,
    pub mempool: Arc<RwLock<Vec<AppPayload>>>,
    pub chain_id: String,
    pub genesis_params: crate::genesis::GenesisParameters,
}

/// Starts the consensus loop. This loop listens for signals, orchestrates sub-committee elections,
/// triggers block proposals when chosen as a leader, and processes incoming consensus messages.
impl ConsensusEngine {
    pub async fn run(
        self,
        mut p2p_msg_rx: mpsc::Receiver<ConsensusMsgTuple>,
        _txs_response_from_p2p_rx: mpsc::Receiver<SyncResponse>,
    ) {
        info!("[CONSENSUS] Consensus engine started, waiting for ConsensusReady signal...");
        loop {
            if self.consensus_ready.load(Ordering::SeqCst) {
                info!("[CONSENSUS] ConsensusReady signal received. Starting consensus protocol.");
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        let message_handler_engine = self.clone();
        tokio::spawn(async move {
            while let Some((msg, source_peer, payloads_opt)) = p2p_msg_rx.recv().await {
                let engine_clone = message_handler_engine.clone();
                tokio::spawn(async move {
                    engine_clone
                        .handle_consensus_message(msg, source_peer, payloads_opt)
                        .await;
                });
            }
        });

        let mut pacesetter_ticker = interval(Duration::from_millis(500));
        let mut current_step_task: Option<tokio::task::JoinHandle<()>> = None;

        loop {
            tokio::select! {
                _ = pacesetter_ticker.tick() => {},
            }
            if !self.consensus_ready.load(Ordering::SeqCst) {
                continue;
            }

            let (highest_qc_view, _highest_qc_hash, current_round, current_step, step_start_time) = {
                let core = self.state.core_state.read().await;
                (
                    core.highest_seen_qc.view_number,
                    core.highest_seen_qc.batch_hash.clone(),
                    core.current_round,
                    core.current_step,
                    core.step_start_time,
                )
            };

            // Proceed with consensus without checking L1 state tree

            let mut start_new_task = false;
            let mut next_round = current_round;
            let mut next_step = current_step;

            if highest_qc_view >= current_round {
                next_round = highest_qc_view + 1;
                next_step = 0;
                info!("[CONSENSUS DRIVER] QC#{} received. Advancing to Round #{}, Step #0.", highest_qc_view, next_round);
                start_new_task = true;
            } else if step_start_time.elapsed() > Duration::from_millis(self.genesis_params.proposer_timeout_ms) {
                next_step = current_step + 1;
                warn!("[CONSENSUS DRIVER] Proposer for Round #{}, Step #{} timeout. Advancing to Step #{}.", current_round, current_step, next_step);
                start_new_task = true;

                if next_step >= self.genesis_params.sub_committee_size as u64 {
                    warn!("[CONSENSUS DRIVER] All proposers failed for Round #{}. Forcing advance to next round.", current_round);
                    next_round = current_round + 1;
                    next_step = 0;
                }
            }

            if start_new_task {
                if let Some(task) = current_step_task.take() {
                    task.abort();
                }

                {
                    let mut core = self.state.core_state.write().await;
                    core.current_round = next_round;
                    core.current_step = next_step;
                    core.step_start_time = Instant::now();
                }

                let premature_proposals_for_round = self
                    .state
                    .proposal_queues
                    .write()
                    .await
                    .premature_proposals
                    .remove(&next_round);

                if let Some(proposals) = premature_proposals_for_round {
                    info!("[CONSENSUS DRIVER] Reprocessing {} premature proposals queued for Round #{}", proposals.len(), next_round);
                    for (msg, source_peer, payloads) in proposals {
                        let engine_clone = self.clone();
                        tokio::spawn(async move {
                            engine_clone
                                .handle_consensus_message(msg, source_peer, payloads)
                                .await;
                        });
                    }
                }

                current_step_task = Some(tokio::spawn(
                    self.clone().handle_round_step(next_round, next_step),
                ));
            }
        }
    }

    async fn handle_round_step(self, round: u64, step: u64) {
        let (current_round, current_step, seed_hash) = {
            let core = self.state.core_state.read().await;
            if core.current_round != round || core.current_step != step {
                info!("[CONSENSUS] Aborting stale task for Round #{}, Step #{}.", round, step);
                return;
            }
            let seed = core
                .optimistically_confirmed_batches
                .iter()
                .rev()
                .find(|b| b.header.calculate_hash() == core.highest_seen_qc.batch_hash)
                .map(|b| b.header.vrf_output.clone())
                .unwrap_or_else(|| core.highest_seen_qc.batch_hash.clone());

            (
                core.current_round,
                core.current_step,
                seed,
            )
        };

        info!("[CONSENSUS] Running task for Round #{}, Step #{}", current_round, current_step);

        let sub_committee = self.determine_sub_committee(round, &seed_hash).await;
        if sub_committee.is_empty() {
            return;
        }

        let proposer_address = match sub_committee.get(step as usize) {
            Some(addr) => addr,
            None => {
                warn!("[CONSENSUS] Step #{} out of bounds for Round #{} sub-committee.", step, round);
                return;
            }
        };

        if self.my_address == *proposer_address {
            info!("[CONSENSUS PROPOSER] I am the leader for Round #{}, Step #{}.", round, step);
            self.run_proposer_flow(round).await;
        }
    }

    async fn run_proposer_flow(&self, round: u64) {
        info!("[CONSENSUS PROPOSER] Starting proposer workflow for Round #{}.", round);

        let parent_qc = {
            let core = self.state.core_state.read().await;
            core.highest_seen_qc.clone()
        };

        let valid_payloads: Vec<AppPayload> = {
            let mut pool = self.mempool.write().await;
            let max_payloads = 100;
            let drain_count = std::cmp::min(pool.len(), max_payloads);
            pool.drain(..drain_count).collect()
        };

        let (prev_index, prev_hash) = {
            let core = self.state.core_state.read().await;
            if let Some(latest_batch) = core.optimistically_confirmed_batches.last() {
                (
                    latest_batch.header.index,
                    latest_batch.header.calculate_hash(),
                )
            } else {
                (0, vec![0u8; 32])
            }
        };

        let mut batch_proposal = PayloadBatch {
            header: BatchHeader {
                index: prev_index + 1,
                prev_hash,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
                payloads_root: PayloadBatch::calculate_payloads_root(&valid_payloads),
                authority: self.my_address,
                vrf_output: vec![],
                vrf_proof: vec![],
                signature: vec![],
            },
            payloads: valid_payloads.clone(),
            justify: parent_qc.clone(),
            round,
        };

        let ctx = schnorrkel::signing_context(b"evice-vrf");
        let (io, proof, _) = self.validator_keys.vrf_keys.vrf_sign(ctx.bytes(&batch_proposal.header.prev_hash));
        batch_proposal.header.vrf_output = io.to_preout().to_bytes().to_vec();
        batch_proposal.header.vrf_proof = proof.to_bytes().to_vec();

        let data_to_sign = batch_proposal.header.canonical_bytes_for_signing();
        batch_proposal.header.signature = self
            .validator_keys
            .signing_keys
            .sign(&data_to_sign)
            .to_vec();

        let batch_hash = batch_proposal.header.calculate_hash();
        info!(
            "[CONSENSUS PROPOSER] Proposing new batch #{} (hash: 0x{}) with {} payloads.",
            batch_proposal.header.index,
            hex::encode(&batch_hash[..4]),
            valid_payloads.len()
        );

        let pending_batch = PendingBatch {
            header: batch_proposal.header.clone(),
            payloads: valid_payloads.clone(),
            parent_qc,
            round,
        };
        self.state
            .pending_proposals
            .write()
            .await
            .insert(batch_hash.clone(), pending_batch);

        if self
            .p2p_cmd_tx
            .send(P2pCommand::BroadcastConsensusMessage(
                ConsensusMessage::IntentBatchProposal(Box::new(batch_proposal.clone())),
            ))
            .await
            .is_err()
        {
            error!("[CONSENSUS PROPOSER] Failed to broadcast batch proposal to P2P.");
        }

        let self_vote = {
            let vote = VelocityVote {
                round_id: round,
                batch_hash: batch_hash.clone(),
                voter_address: self.my_address,
                signature: [0; crypto::SIGNATURE_SIZE].to_vec(),
            };
            vote.sign(&self.validator_keys.signing_keys)
        };

        self.state
            .core_state
            .write()
            .await
            .velocity_votes
            .entry(batch_hash.clone())
            .or_default()
            .push(self_vote);

        self.process_votes_for_batch(&batch_hash).await;
    }

    #[async_recursion]
    async fn handle_consensus_message(
        &self,
        msg: ConsensusMessage,
        source_peer: PeerId,
        _response_channel: Option<tokio::sync::oneshot::Sender<SyncResponse>>,
    ) {
        let message_hash = msg.hash();

        if self
            .state
            .recently_processed_hashes
            .read()
            .await
            .contains(&message_hash)
        {
            return;
        }

        {
            let mut cache = self.state.recently_processed_hashes.write().await;
            if cache.contains(&message_hash) {
                return;
            }
            cache.put(message_hash, ());
        }

        match msg {
            ConsensusMessage::IntentBatchProposal(batch) => {
                self.handle_batch_proposal(*batch, source_peer).await;
            }
            ConsensusMessage::VelocityVoteMsg(vote) => {
                self.handle_velocity_vote(vote).await;
            }
            ConsensusMessage::NewQuorumCertificate(qc) => {
                self.handle_new_quorum_certificate(qc, source_peer).await;
            }
        }
    }

    async fn handle_batch_proposal(&self, batch: PayloadBatch, source_peer: PeerId) {
        info!("[CONSENSUS] Processing batch proposal #{} for Round #{} from {}", batch.header.index, batch.round, source_peer);

        let batch_hash = batch.header.calculate_hash();

        let proposer_address = batch.header.authority;

        let is_valid_proposer = {
            let ab = self.address_book.lock().await;
            Self::verify_batch_signature(&ab, &batch.header)
        };

        if !is_valid_proposer {
            warn!("[CONSENSUS] Rejecting batch from proposer 0x{}: invalid or missing signature.", hex::encode(proposer_address.as_ref()));
            return;
        }

        let expected_root = PayloadBatch::calculate_payloads_root(&batch.payloads);
        if batch.header.payloads_root != expected_root {
            warn!("[CONSENSUS] Rejecting batch: payloads_root mismatch.");
            return;
        }

        let current_round = self.state.core_state.read().await.current_round;
        if batch.round > current_round + 10 {
            warn!("[CONSENSUS] Rejecting batch: round {} too far in the future (current: {}).", batch.round, current_round);
            return;
        }
        if current_round > 5 && batch.round < current_round.saturating_sub(5) {
            warn!("[CONSENSUS] Rejecting batch: round {} too far in the past (current: {}).", batch.round, current_round);
            return;
        }

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let max_drift_ms = 30_000; 
        if batch.header.timestamp > now_ms + max_drift_ms {
            warn!("[CONSENSUS] Rejecting batch: timestamp too far in the future.");
            return;
        }
        if batch.header.timestamp < now_ms.saturating_sub(max_drift_ms) {
            warn!("[CONSENSUS] Rejecting batch: timestamp too far in the past.");
            return;
        }

        {
            let core = self.state.core_state.read().await;
            let expected_index = if let Some(latest) = core.optimistically_confirmed_batches.last() {
                latest.header.index + 1
            } else {
                1
            };
            if batch.header.index != expected_index {
                // Allow slightly ahead batches (may arrive before their predecessor is confirmed)
                if batch.header.index > expected_index + 5 || batch.header.index < expected_index {
                    warn!(
                        "[CONSENSUS] Rejecting batch: index {} is not sequential (expected: {}).",
                        batch.header.index, expected_index
                    );
                    return;
                }
            }
        }

        // Derive seed_hash from the justify QC (parent batch), mirroring handle_round_step logic.
        let seed_hash = {
            let core = self.state.core_state.read().await;
            core.optimistically_confirmed_batches
                .iter()
                .rev()
                .find(|b| b.header.calculate_hash() == batch.justify.batch_hash)
                .map(|b| b.header.vrf_output.clone())
                .unwrap_or_else(|| batch.justify.batch_hash.clone())
        };

        let sub_committee = self.determine_sub_committee(batch.round, &seed_hash).await;
        if !sub_committee.contains(&batch.header.authority) {
            warn!("[CONSENSUS] Rejecting batch: proposer 0x{} not in sub-committee for round {}.",
                hex::encode(proposer_address.as_ref()), batch.round);
            return;
        }

        // All validations passed, accept proposal
        let pending = PendingBatch {
            header: batch.header.clone(),
            payloads: batch.payloads.clone(),
            parent_qc: batch.justify.clone(),
            round: batch.round,
        };

        {
            let mut proposals = self.state.pending_proposals.write().await;
            if proposals.contains_key(&batch_hash) {
                return;
            }
            proposals.insert(batch_hash.clone(), pending);
        }

        info!(
            "[CONSENSUS] Proposal #{} (0x{}) is valid, casting vote.",
            batch.header.index,
            hex::encode(&batch_hash[..4])
        );

        let my_vote = {
            let vote = VelocityVote {
                round_id: batch.round,
                batch_hash: batch_hash.clone(),
                voter_address: self.my_address,
                signature: [0; crate::crypto::SIGNATURE_SIZE].to_vec(),
            };
            vote.sign(&self.validator_keys.signing_keys)
        };

        {
            let mut core = self.state.core_state.write().await;
            core.velocity_votes
                .entry(batch_hash.clone())
                .or_default()
                .push(my_vote.clone());
        }

        if self
            .p2p_cmd_tx
            .send(P2pCommand::BroadcastConsensusMessage(
                ConsensusMessage::VelocityVoteMsg(my_vote),
            ))
            .await
            .is_err()
        {
            error!("[CONSENSUS] Failed to broadcast vote to P2P.");
        }

        self.process_votes_for_batch(&batch_hash).await;
    }

    async fn process_votes_for_batch(&self, batch_hash: &[u8]) {
        let required_quorum = {
            let ab = self.address_book.lock().await;
            let total = ab.address_to_identity.len();
            let req = (total * 2 / 3) + 1;
            // Provide sensible fallback for local dev
            if total == 0 {
                1
            } else {
                req
            }
        };

        let mut core = self.state.core_state.write().await;

        if core.processed_optimistic_batches.contains(batch_hash) {
            return;
        }

        if let Some(votes) = core.velocity_votes.get(batch_hash) {
            let vote_count = votes.len();

            if vote_count >= required_quorum {
                info!(
                    "[CONSENSUS QUORUM] Batch 0x{} achieved quorum ({}/{}). Constructing QC.",
                    hex::encode(&batch_hash[..4]),
                    vote_count,
                    required_quorum
                );

                let pending_batch = {
                    let proposals = self.state.pending_proposals.read().await;
                    proposals.get(batch_hash).cloned()
                };

                if let Some(batch) = pending_batch {
                    let signatures: Vec<(Address, Vec<u8>)> = votes
                        .iter()
                        .map(|v| (v.voter_address, v.signature.clone()))
                        .collect();

                    let qc = QuorumCertificate {
                        batch_hash: batch_hash.to_vec(),
                        view_number: batch.round,
                        signatures,
                    };

                    let payload_batch = PayloadBatch {
                        header: batch.header.clone(),
                        payloads: batch.payloads.clone(),
                        justify: batch.parent_qc.clone(),
                        round: batch.round,
                    };

                    core.processed_optimistic_batches
                        .insert(batch_hash.to_vec());
                    core.optimistically_confirmed_batches.push(payload_batch);

                    if qc.view_number > core.highest_seen_qc.view_number {
                        core.highest_seen_qc = qc.clone();
                    }

                    let qc_msg = ConsensusMessage::NewQuorumCertificate(qc);
                    if self
                        .p2p_cmd_tx
                        .send(P2pCommand::BroadcastConsensusMessage(qc_msg))
                        .await
                        .is_err()
                    {
                        error!("[CONSENSUS] Failed to broadcast new QC.");
                    }

                    core.prune_stale_data();
                    drop(core);
                    self.state.prune_confirmed_proposals().await;
                } else {
                    warn!(
                        "[CONSENSUS] Quorum reached for 0x{} but full batch data is missing.",
                        hex::encode(&batch_hash[..4])
                    );
                }
            }
        }
    }

    async fn handle_velocity_vote(&self, vote: VelocityVote) {
        let batch_hash = vote.batch_hash.clone();

        if self
            .state
            .core_state
            .read()
            .await
            .processed_optimistic_batches
            .contains(&batch_hash)
        {
            return;
        }

        let is_valid = {
            let ab = self.address_book.lock().await;
            Self::verify_vote_signature(
                &ab,
                &vote.voter_address,
                vote.round_id,
                &vote.batch_hash,
                &vote.signature,
            )
        };

        if !is_valid {
            warn!(
                "[CONSENSUS] Rejecting vote with invalid signature from 0x{}",
                hex::encode(vote.voter_address.as_ref())
            );
            return;
        }

        {
            let mut core = self.state.core_state.write().await;
            let votes_for_batch = core.velocity_votes.entry(batch_hash.clone()).or_default();
            if !votes_for_batch
                .iter()
                .any(|v| v.voter_address == vote.voter_address)
            {
                votes_for_batch.push(vote);
            }
        }

        self.process_votes_for_batch(&batch_hash).await;
    }

    async fn handle_new_quorum_certificate(&self, qc: QuorumCertificate, source_peer: PeerId) {
        let is_fully_valid = {
            let ab = self.address_book.lock().await;
            let mut valid_count = 0;
            let mut unique_voters = HashSet::new();

            for (voter_addr, signature) in &qc.signatures {
                if unique_voters.insert(*voter_addr) {
                    if Self::verify_vote_signature(
                        &ab,
                        voter_addr,
                        qc.view_number,
                        &qc.batch_hash,
                        signature,
                    ) {
                        valid_count += 1;
                    }
                }
            }

            let total = ab.address_to_identity.len();
            let req = if total == 0 { 1 } else { (total * 2 / 3) + 1 };
            valid_count >= req
        };
        if !is_fully_valid {
            warn!(
                "[CONSENSUS] Received QC with INVALID SIGNATURE from peer {}. Applying penalty.",
                source_peer
            );
            let _ = self
                .p2p_cmd_tx
                .send(P2pCommand::ApplyPenalty {
                    peer_id: source_peer,
                    penalty: -50,
                })
                .await;
            return;
        }

        let new_batch_hash = qc.batch_hash.clone();
        let parent_exists_locally;

        {
            let mut core = self.state.core_state.write().await;
            if qc.view_number > core.highest_seen_qc.view_number {
                info!("[CONSENSUS ANCHOR] Received new VALID QC from network for Round #{}. Updating anchor.", qc.view_number);
                core.highest_seen_qc = qc.clone();

                parent_exists_locally = self
                    .state
                    .pending_proposals
                    .read()
                    .await
                    .contains_key(&new_batch_hash);
            } else {
                return;
            }
        }

        if !parent_exists_locally {
            warn!(
                "[CONSENSUS SYNC] Received QC for batch 0x{} we don't have. Requesting full data.",
                hex::encode(&new_batch_hash[..4])
            );

            self.state
                .proposal_queues
                .write()
                .await
                .stale_qc_request
                .insert(new_batch_hash.clone(), (qc.view_number, Instant::now()));

            let cmd = P2pCommand::SendDirectRequest {
                destination: source_peer,
                request: SyncRequest::GetFullProposal(new_batch_hash),
            };
            if self.p2p_cmd_tx.send(cmd).await.is_err() {
                error!("[CONSENSUS] Failed to send missing batch request to P2P.");
            }
        }
    }

    async fn determine_sub_committee(&self, round: u64, seed_hash: &[u8]) -> Vec<Address> {
        let validators: Vec<Address> = self
            .address_book
            .lock()
            .await
            .address_to_identity
            .keys()
            .cloned()
            .collect();

        if validators.is_empty() {
            warn!(
                "[CONSENSUS ELECTION] No validators found in address book for round {}.",
                round
            );
            return Vec::new();
        }

        let mut sorted_validators = validators;
        sorted_validators.sort();

        let seed_material = {
            let mut hasher = sha2::Sha256::new();
            hasher.update(seed_hash);
            hasher.update(&round.to_be_bytes());
            hasher.finalize()
        };

        let seed: [u8; 32] = seed_material.into();
        let mut rng = rand::rngs::StdRng::from_seed(seed);
        sorted_validators.shuffle(&mut rng);

        let committee = sorted_validators
            .into_iter()
            .take(self.genesis_params.sub_committee_size)
            .collect::<Vec<_>>();

        if !committee.is_empty() {
            debug!(
                "[CONSENSUS ELECTION] Round #{}: Sub-committee elected (first proposer): 0x{}",
                round,
                hex::encode(committee[0].as_ref())
            );
        }

        committee
    }

    fn verify_vote_signature(
        ab: &AddressBook,
        voter_address: &Address,
        round_id: u64,
        batch_hash: &[u8],
        signature: &[u8],
    ) -> bool {
        let peer_info = match ab.address_to_identity.get(voter_address) {
            Some(info) => info,
            None => return false,
        };

        let pub_key = match &peer_info.public_key {
            Some(pk) if pk.len() == crate::crypto::PUBLIC_KEY_SIZE => pk,
            _ => return false,
        };

        let mut full_pk = [0u8; crate::crypto::PUBLIC_KEY_SIZE];
        full_pk.copy_from_slice(pub_key);

        let dummy_vote = VelocityVote {
            round_id,
            batch_hash: batch_hash.to_vec(),
            voter_address: *voter_address,
            signature: vec![],
        };

        let msg = dummy_vote.canonical_bytes(&full_pk);
        crate::crypto::verify(&crate::FullPublicKey(full_pk), &msg, signature)
    }

    fn verify_batch_signature(ab: &AddressBook, header: &BatchHeader) -> bool {
        let peer_info = match ab.address_to_identity.get(&header.authority) {
            Some(info) => info,
            None => return false,
        };

        let pub_key = match &peer_info.public_key {
            Some(pk) if pk.len() == crate::crypto::PUBLIC_KEY_SIZE => pk,
            _ => return false,
        };

        let mut full_pk = [0u8; crate::crypto::PUBLIC_KEY_SIZE];
        full_pk.copy_from_slice(pub_key);

        let Some(vrf_pk_bytes) = &peer_info.vrf_public_key else { return false; };
        let Ok(vrf_pubkey) = schnorrkel::PublicKey::from_bytes(vrf_pk_bytes) else { return false; };
        let Ok(preout) = schnorrkel::vrf::VRFPreOut::from_bytes(&header.vrf_output) else { return false; };
        let Ok(proof) = schnorrkel::vrf::VRFProof::from_bytes(&header.vrf_proof) else { return false; };

        let ctx = schnorrkel::signing_context(b"evice-vrf");
        if vrf_pubkey.vrf_verify(ctx.bytes(&header.prev_hash), &preout, &proof).is_err() {
            return false;
        }

        let msg = header.canonical_bytes_for_signing();
        crate::crypto::verify(&crate::FullPublicKey(full_pk), &msg, &header.signature)
    }
}
