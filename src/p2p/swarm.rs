use borsh::BorshDeserialize;
use libp2p::{
    futures::StreamExt,
    gossipsub::{self, MessageAcceptance},
    identify,
    identity::Keypair as P2pKeypair,
    kad, request_response,
    swarm::SwarmEvent,
    Multiaddr, PeerId, StreamProtocol,
};
use log::{debug, error, info, warn};
use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    select,
    sync::{mpsc, Mutex, RwLock},
    time::interval,
};

use crate::{
    consensus::{ConsensusMessage, ConsensusState, OptimisticConfirmation, PendingBatch},
    p2p::types::{
        AddressBook, AppBehaviour, AppBehaviourEvent, P2pCommand, PeerInfo, PendingResponse,
        SyncRequest, SyncResponse, NETWORK_STABILITY_WINDOW, PENALTY_DESERIALIZATION_ERROR,
        REWARD_VALID_MESSAGE,
    },
    ChainMessage, PayloadBatch,
};

pub static DEV_MODE: AtomicBool = AtomicBool::new(false);

fn is_loopback(addr: &Multiaddr) -> bool {
    if DEV_MODE.load(Ordering::SeqCst) {
        return false;
    }
    addr.iter().any(|protocol| match protocol {
        libp2p::multiaddr::Protocol::Ip4(ip) => ip.is_loopback(),
        libp2p::multiaddr::Protocol::Ip6(ip) => ip.is_loopback(),
        _ => false,
    })
}

pub async fn run(
    p2p_keypair: P2pKeypair,
    bootstrap_nodes: Vec<String>,
    p2p_port: u16,
    p2p_to_consensus_tx: mpsc::Sender<(
        ConsensusMessage,
        PeerId,
        Option<tokio::sync::oneshot::Sender<SyncResponse>>,
    )>,
    _txs_response_to_consensus_tx: mpsc::Sender<SyncResponse>,
    is_bootstrap_node: bool,
    consensus_state: Option<Arc<RwLock<ConsensusState>>>,
    mut p2p_cmd_rx: mpsc::Receiver<P2pCommand>,
    p2p_cmd_tx: mpsc::Sender<P2pCommand>,
    network_ready_flag: Arc<AtomicBool>,
    address_book: Arc<Mutex<AddressBook>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let local_key = p2p_keypair;
    let local_peer_id = PeerId::from(local_key.public());
    info!("Local Peer ID: {}", local_peer_id);

    let peer_scores = Arc::new(Mutex::new(HashMap::<PeerId, PeerInfo>::new()));
    let known_peers = Arc::new(Mutex::new(HashMap::<PeerId, Multiaddr>::new()));
    let gossip_topic = gossipsub::IdentTopic::new("evice-sequencer-topic");
    let fallback_sync_topic = gossipsub::IdentTopic::new("evice-sequencer-fallback-topic");
    let mut pending_dials = HashSet::<PeerId>::new();

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp(
            Default::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_quic()
        .with_behaviour(|key| {
            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(1))
                .mesh_n_low(4)
                .history_gossip(3)
                .validation_mode(gossipsub::ValidationMode::Strict)
                .build()
                .expect("Valid gossipsub config");

            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )
            .unwrap();

            let kademlia =
                kad::Behaviour::new(local_peer_id, kad::store::MemoryStore::new(local_peer_id));
            let identify = identify::Behaviour::new(identify::Config::new(
                "/evice-sequencer/1.0.0".to_string(),
                key.public(),
            ));
            let sync = request_response::Behaviour::new(
                [(
                    StreamProtocol::new("/evice-sequencer/sync/1.0"),
                    request_response::ProtocolSupport::Full,
                )],
                request_response::Config::default(),
            );

            Ok(AppBehaviour {
                gossipsub,
                kademlia,
                identify,
                sync,
            })
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    swarm.behaviour_mut().gossipsub.subscribe(&gossip_topic)?;
    swarm.behaviour_mut().gossipsub.subscribe(&fallback_sync_topic)?;

    for remote_addr_str in &bootstrap_nodes {
        if let Ok(remote_addr) = Multiaddr::from_str(remote_addr_str) {
            info!("Attempting to connect to bootstrap node: {}", remote_addr);
            if let Err(e) = swarm.dial(remote_addr.clone()) {
                error!("Failed to dial bootstrap node {}: {:?}", remote_addr, e);
            }
        }
    }

    if let Err(e) = swarm.behaviour_mut().kademlia.bootstrap() {
        warn!("P2P: Failed to start initial Kademlia bootstrap: {:?}", e);
    }

    let required_peer_threshold = {
        let num_validators = address_book.lock().await.get_all_peer_ids().len();
        if num_validators > 0 {
            (num_validators * 2 / 3).max(1)
        } else {
            1
        }
    };
    info!(
        "[P2P] Peer connection threshold for consensus set to: {} peers",
        required_peer_threshold
    );

    let listen_addr_tcp = format!("/ip4/0.0.0.0/tcp/{}", p2p_port).parse()?;
    swarm.listen_on(listen_addr_tcp)?;
    let listen_addr_quic = format!("/ip4/0.0.0.0/udp/{}/quic-v1", p2p_port).parse()?;
    swarm.listen_on(listen_addr_quic)?;

    let mut network_stability_check = interval(Duration::from_secs(1));
    let mut stable_since: Option<Instant> = None;
    let mut initial_discovery_triggered = false;
    let (response_tx, mut response_rx) = mpsc::channel::<PendingResponse>(32);

    loop {
        select! {
            _ = network_stability_check.tick() => {
                let current_peers = swarm.connected_peers().count();

                if current_peers >= required_peer_threshold {
                    let now = Instant::now();
                    let stable_instant = stable_since.get_or_insert(now);

                    if now.duration_since(*stable_instant) >= NETWORK_STABILITY_WINDOW {
                        if !network_ready_flag.load(Ordering::SeqCst) {
                            info!("[P2P] Network stable (connected to {}/{} peers for >{} seconds). Sending NetworkReady signal.", current_peers, required_peer_threshold, NETWORK_STABILITY_WINDOW.as_secs());
                            network_ready_flag.store(true, Ordering::SeqCst);
                        }
                    }
                } else {
                    if stable_since.is_some() {
                        stable_since = None;
                    }
                    if network_ready_flag.load(Ordering::SeqCst) {
                        warn!("[P2P] Network became unstable (connections dropped to {}/{} peers). Pausing consensus.", current_peers, required_peer_threshold);
                        network_ready_flag.store(false, Ordering::SeqCst);
                    }
                }
            },

            Some(cmd) = p2p_cmd_rx.recv() => {
                match cmd {
                    P2pCommand::BroadcastConsensusMessage(msg) => {
                        let chain_msg = ChainMessage::NewConsensusMessage(msg);
                        if let Ok(encoded) = borsh::to_vec(&chain_msg) {
                            if let Err(e) = swarm.behaviour_mut().gossipsub.publish(gossip_topic.clone(), encoded) {
                                error!("[P2P GOSSIP] Failed to broadcast consensus message: {:?}", e);
                            }
                        }
                    }
                    P2pCommand::SendDirectRequest { destination, request } => {
                        match &request {
                            SyncRequest::SubmitVote(vote) => {
                                debug!("[P2P DIRECT] Sending vote for batch 0x{} to peer {}", hex::encode(&vote.batch_hash[..4]), destination);
                            }
                            _ => {}
                        }
                        swarm.behaviour_mut().sync.send_request(&destination, request);
                    }
                    P2pCommand::ApplyPenalty { peer_id, penalty } => {
                        info!("[P2P] Applying consensus penalty of {} to peer {}", penalty, peer_id);
                        let mut scores = peer_scores.lock().await;
                        if let Some(peer_info) = scores.get_mut(&peer_id) {
                            peer_info.apply_penalty(penalty);
                        }
                    }
                    P2pCommand::DialAddress(addr) => {
                        if let Some(peer_id) = addr.iter().last().and_then(|p| if let libp2p::multiaddr::Protocol::P2p(id) = p { Some(id) } else { None }) {
                            if !swarm.is_connected(&peer_id) && !pending_dials.contains(&peer_id) {
                                info!("PEER EXCHANGE: Attempting to connect to new peer from list: {}", addr);
                                if let Err(e) = swarm.dial(addr.clone()) {
                                    warn!("PEER EXCHANGE: Failed to dial {}: {:?}", addr, e);
                                } else {
                                    pending_dials.insert(peer_id);
                                }
                            }
                        }
                    }
                    P2pCommand::GetConnectedPeers(sender) => {
                        let peers: Vec<PeerId> = swarm.connected_peers().cloned().collect();
                        if sender.send(peers).is_err() {
                            warn!("[P2P] Failed to send connected peer list: receiver dropped.");
                        }
                    }
                }
            },

            Some(pending) = response_rx.recv() => {
                if let Err(e) = swarm.behaviour_mut().sync.send_response(pending.channel, pending.response) {
                    warn!("[P2P] Failed to send processed response: {:?}", e);
                }
            },

            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::Behaviour(AppBehaviourEvent::Kademlia(kad::Event::OutboundQueryProgressed { 
                        result, 
                        .. 
                    })) => {
                        if let kad::QueryResult::GetClosestPeers(Ok(ok)) = result {
                            for peer_info in ok.peers {
                                let discovered_peer_id = peer_info.peer_id;
                                if discovered_peer_id != local_peer_id && !swarm.is_connected(&discovered_peer_id) {
                                    info!("KAD: Discovered new peer {:?}, attempting to connect...", discovered_peer_id);
                                    if let Err(e) = swarm.dial(discovered_peer_id) {
                                        warn!("Failed to dial newly discovered peer: {:?}", e);
                                    }
                                }
                            }
                        }
                    },
                    SwarmEvent::Behaviour(AppBehaviourEvent::Identify(identify::Event::Received {
                        peer_id,
                        info,
                        ..
                    })) => {
                        info!("IDENTIFY: Received address info from peer {}: {:?}", peer_id, info.listen_addrs);
                        let mut valid_addrs = Vec::new();
                        for addr in info.listen_addrs {
                            if !is_loopback(&addr) {
                                let full_addr = addr.clone().with(libp2p::multiaddr::Protocol::P2p(peer_id));
                                swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                                valid_addrs.push(full_addr);
                            } else {
                                debug!("IDENTIFY: Ignoring loopback address {} from peer {}.", addr, peer_id);
                            }
                        }

                        if is_bootstrap_node && !valid_addrs.is_empty() {
                            let mut peers_guard = known_peers.lock().await;
                            if !peers_guard.contains_key(&peer_id) {
                                let existing_peers_list: Vec<String> = peers_guard.values().map(|a| a.to_string()).collect();
                                if !existing_peers_list.is_empty() {
                                    info!("BOOTSTRAP: Sending {} existing peer addresses to new peer {}", existing_peers_list.len(), peer_id);
                                    let request = SyncRequest::InformAboutPeers(existing_peers_list);
                                    swarm.behaviour_mut().sync.send_request(&peer_id, request);
                                }

                                let newcomer_addr_list: Vec<String> = valid_addrs.iter().map(|a| a.to_string()).collect();
                                let all_other_peers: Vec<PeerId> = peers_guard.keys().cloned().collect();
                                for other_peer_id in all_other_peers {
                                    info!("BOOTSTRAP: Informing peer {} about arrival of {}", other_peer_id, peer_id);
                                    let request = SyncRequest::InformAboutPeers(newcomer_addr_list.clone());
                                    swarm.behaviour_mut().sync.send_request(&other_peer_id, request);
                                }

                                peers_guard.insert(peer_id, valid_addrs.first().expect("guarded by is_empty check").clone());
                            }
                        }
                    },
                    SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                        info!("P2P: Connection successfully established with peer: {}", peer_id);
                        pending_dials.remove(&peer_id);

                        let addr = endpoint.get_remote_address().clone();
                        swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);

                        let mut scores = peer_scores.lock().await;
                        scores.entry(peer_id).or_insert_with(PeerInfo::new);

                        if !initial_discovery_triggered && swarm.connected_peers().count() > 0 {
                            info!("[P2P Discovery] Initiating active peer discovery with GetClosestPeers query...");
                            swarm.behaviour_mut().kademlia.get_closest_peers(local_peer_id);
                            initial_discovery_triggered = true;
                        }
                    },
                    SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                        warn!("P2P: Connection with peer {} closed. Cause: {:?}", peer_id, cause);
                        pending_dials.remove(&peer_id);

                        let mut scores = peer_scores.lock().await;
                        scores.remove(&peer_id);
                    },
                    SwarmEvent::NewListenAddr { address, .. } => {
                        info!("P2P: Local node is now listening on: {}/p2p/{}", address, local_peer_id);
                    },
                    SwarmEvent::Behaviour(AppBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                        propagation_source: peer_id,
                        message_id,
                        message,
                    })) => {
                        if message.topic == fallback_sync_topic.hash() {
                            if let Ok(SyncRequest::GetFullProposal(hash)) = SyncRequest::try_from_slice(&message.data) {
                                info!("[P2P FALLBACK] Received gossip request for block 0x{} from {}. Checking local availability...", hex::encode(&hash[..4]), peer_id);

                                let consensus_state_clone = consensus_state.clone();
                                let p2p_cmd_tx_clone = p2p_cmd_tx.clone();

                                tokio::spawn(async move {
                                    let mut found_batch: Option<PendingBatch> = None;

                                    if found_batch.is_none() {
                                        if let Some(cs) = consensus_state_clone {
                                            if let Some(pending_batch) = cs.read().await.pending_proposals.read().await.get(&hash) {
                                                info!("[P2P FALLBACK] Found batch 0x{} in `pending_proposals` for peer {}.", hex::encode(&hash[..4]), peer_id);
                                                found_batch = Some(pending_batch.clone());
                                            } else if let Some(batch) = cs.read().await.core_state.read().await.optimistically_confirmed_batches.iter().find(|b| b.header.calculate_hash() == hash) {
                                                info!("[P2P FALLBACK] Found batch 0x{} in `optimistically_confirmed_batches` for peer {}.", hex::encode(&hash[..4]), peer_id);
                                                found_batch = Some(PendingBatch {
                                                    header: batch.header.clone(),
                                                    payloads: batch.payloads.clone(),
                                                    parent_qc: batch.justify.clone(),
                                                    round: batch.round,
                                                });
                                            }
                                        }
                                    }

                                    if let Some(batch) = found_batch {
                                        let confirmation = OptimisticConfirmation {
                                            header: batch.header.clone(),
                                            payload_hashes: batch.payloads.iter().map(|p| p.message_hash()).collect(),
                                            parent_qc: batch.parent_qc.clone(),
                                            round: batch.round,
                                        };

                                        let full_proposal_response = SyncRequest::FullProposalForCommittee {
                                            confirmation: Box::new(confirmation),
                                            payloads: batch.payloads,
                                        };

                                        let cmd = P2pCommand::SendDirectRequest {
                                            destination: peer_id,
                                            request: full_proposal_response,
                                        };

                                        if p2p_cmd_tx_clone.send(cmd).await.is_err() {
                                            error!("[P2P FALLBACK] Failed to send full batch response to peer {}.", peer_id);
                                        } else {
                                            info!("[P2P FALLBACK] Successfully sent full batch 0x{} directly to peer {}.", hex::encode(&hash[..4]), peer_id);
                                        }
                                    } else {
                                        debug!("[P2P FALLBACK] Could not find requested batch 0x{} for {}.", hex::encode(&hash[..4]), peer_id);
                                    }
                                });
                            }
                            continue;
                        }

                        let acceptance = MessageAcceptance::Accept;
                        let report_sent_successfully = swarm.behaviour_mut().gossipsub.report_message_validation_result(&message_id, &peer_id, acceptance);

                        if !report_sent_successfully {
                            warn!("Failed to report initial validation result for message_id: {}", message_id);
                        }

                        let p2p_to_consensus_tx_clone = p2p_to_consensus_tx.clone();
                        let peer_scores_clone = Arc::clone(&peer_scores);

                        tokio::spawn(async move {
                            let mut scores = peer_scores_clone.lock().await;
                            let peer_info = scores.entry(peer_id).or_insert_with(PeerInfo::new);

                            let penalty = match borsh::from_slice::<ChainMessage>(&message.data) {
                                Ok(chain_message) => match chain_message {
                                    ChainMessage::NewConsensusMessage(ConsensusMessage::IntentBatchProposal(ref batch)) => {
                                        if p2p_to_consensus_tx_clone.send((ConsensusMessage::IntentBatchProposal(batch.clone()), peer_id, None)).await.is_err() {
                                            error!("P2P (Task): Failed to send valid proposal to Consensus Engine.");
                                        }
                                        0
                                    }
                                    ChainMessage::NewConsensusMessage(other_consensus_msg) => {
                                        if p2p_to_consensus_tx_clone.send((other_consensus_msg, peer_id, None)).await.is_err() {
                                            error!("P2P (Task): Failed to send consensus message to Consensus Engine.");
                                        }
                                        0
                                    }
                                    ChainMessage::NewPayload(_) => {
                                        // Ignore payloads directly handled by L2
                                        0
                                    }
                                },
                                Err(_) => PENALTY_DESERIALIZATION_ERROR,
                            };

                            if penalty < 0 {
                                peer_info.apply_penalty(penalty);
                            } else {
                                peer_info.apply_reward(REWARD_VALID_MESSAGE);
                            }
                        });
                    },

                    SwarmEvent::Behaviour(AppBehaviourEvent::Sync(request_response::Event::Message {
                        peer,
                        message,
                        ..
                    })) => {
                        match message {
                            request_response::Message::Request { request, channel, .. } => {
                                match &request {
                                    SyncRequest::SubmitVote(vote) => {
                                        debug!("[SYNC] Received vote for batch 0x{} from peer {}", hex::encode(&vote.batch_hash[..4]), peer);
                                    }
                                    SyncRequest::FullProposalForCommittee { confirmation, payloads } => {
                                        info!(
                                            "[SYNC] Received full proposal for batch #{} ({} payloads) from peer {}",
                                            confirmation.header.index,
                                            payloads.len(),
                                            peer
                                        );
                                    }
                                    _ => {
                                        info!("[SYNC] Received {:?} request from peer {}", request, peer);
                                    }
                                }

                                let response_tx_clone = response_tx.clone();
                                let p2p_to_consensus_tx_clone = p2p_to_consensus_tx.clone();
                                let p2p_cmd_tx_clone = p2p_cmd_tx.clone();
                                let local_peer_id_clone = local_peer_id;
                                let consensus_state_clone = consensus_state.clone();

                                tokio::spawn(async move {
                                    match request {
                                        SyncRequest::SubmitVote(vote) => {
                                            if p2p_to_consensus_tx_clone.send((ConsensusMessage::VelocityVoteMsg(*vote), peer, None)).await.is_err() {
                                                error!("[P2P DIRECT] Failed to forward vote to consensus engine.");
                                            }
                                            let response = SyncResponse::VoteAck;
                                            let pending = PendingResponse { channel, response };
                                            if response_tx_clone.send(pending).await.is_err() {
                                                error!("[P2P] Failed to send VoteAck to internal channel.");
                                            }
                                        }
                                        SyncRequest::ConsensusRequest(consensus_msg) => {
                                            if let Err(e) = p2p_to_consensus_tx_clone.send((*consensus_msg, peer, None)).await {
                                                error!("P2P: Failed to forward direct consensus message to engine: {}", e);
                                            }

                                            let response = SyncResponse::ConsensusResponse(None);
                                            let pending = PendingResponse { channel, response };
                                            if response_tx_clone.send(pending).await.is_err() {
                                                error!("[P2P] Failed to send consensus ACK response to internal channel.");
                                            }
                                        }
                                        SyncRequest::GetFullProposal(batch_hash) => {
                                            let mut found_batch: Option<PendingBatch> = None;

                                            // Check in cache
                                            if found_batch.is_none() {
                                                if let Some(cs) = consensus_state_clone {
                                                    let consensus_state_guard = cs.read().await;
                                                    let pending_proposals_guard = consensus_state_guard.pending_proposals.read().await;
                                                    if let Some(pending) = pending_proposals_guard.get(&batch_hash) {
                                                        info!("[P2P SYNC] Found batch 0x{} in `pending_proposals`.", hex::encode(&batch_hash[..4]));
                                                        found_batch = Some(pending.clone());
                                                    } else {
                                                        let core_state_guard = consensus_state_guard.core_state.read().await;
                                                        if let Some(optimistic) = core_state_guard.optimistically_confirmed_batches.iter().find(|b| b.header.calculate_hash() == batch_hash) {
                                                            info!("[P2P SYNC] Found batch 0x{} in `optimistically_confirmed_batches`.", hex::encode(&batch_hash[..4]));
                                                            found_batch = Some(PendingBatch {
                                                                header: optimistic.header.clone(),
                                                                payloads: optimistic.payloads.clone(),
                                                                parent_qc: optimistic.justify.clone(),
                                                                round: optimistic.round,
                                                            });
                                                        }
                                                    }
                                                }
                                            }

                                            let response = if let Some(batch) = found_batch {
                                                SyncResponse::FullProposal(Some(Box::new(batch)))
                                            } else {
                                                warn!("[P2P SYNC] Failed to find proposal 0x{} for peer {}.", hex::encode(&batch_hash[..4]), peer);
                                                SyncResponse::FullProposal(None)
                                            };

                                            let pending = PendingResponse { channel, response };
                                            if response_tx_clone.send(pending).await.is_err() {
                                                error!("[P2P] Failed to send FullProposal response to internal channel.");
                                            }
                                        }
                                        SyncRequest::FullProposalForCommittee { confirmation, payloads } => {
                                            let batch_proposal = PayloadBatch {
                                                header: confirmation.header.clone(),
                                                payloads: payloads.clone(),
                                                round: confirmation.round,
                                                justify: confirmation.parent_qc.clone(),
                                            };

                                            let msg_tuple = (
                                                ConsensusMessage::IntentBatchProposal(Box::new(batch_proposal)),
                                                peer,
                                                None
                                            );

                                            if p2p_to_consensus_tx_clone.send(msg_tuple).await.is_err() {
                                                error!("[P2P DIRECT] Failed to forward FullProposalForCommittee to consensus engine.");
                                            }

                                            let response = SyncResponse::FullProposalReceivedAck;
                                            let pending = PendingResponse { channel, response };
                                            if response_tx_clone.send(pending).await.is_err() {
                                                error!("[P2P] Failed to send FullProposalReceivedAck to internal channel.");
                                            }
                                        }
                                        SyncRequest::InformAboutPeers(peer_addrs) => {
                                            info!("PEER EXCHANGE: Received list of {} peers from {}", peer_addrs.len(), peer);
                                            for addr_str in peer_addrs {
                                                if let Ok(addr) = Multiaddr::from_str(&addr_str) {
                                                    if let Some(peer_id_from_addr) = addr.iter().last().and_then(|p| if let libp2p::multiaddr::Protocol::P2p(id) = p { Some(id) } else { None }) {
                                                        if peer_id_from_addr != local_peer_id_clone {
                                                            let _ = p2p_cmd_tx_clone.send(P2pCommand::DialAddress(addr)).await;
                                                        }
                                                    }
                                                }
                                            }

                                            let response = SyncResponse::PeersReceivedAck;
                                            let pending = PendingResponse { channel, response };
                                            if response_tx_clone.send(pending).await.is_err() {
                                                error!("[P2P] Failed to send PeersReceivedAck to internal channel.");
                                            }
                                        }
                                    }
                                });
                            },
                            request_response::Message::Response { response, .. } => {
                                match response {
                                    SyncResponse::PeersReceivedAck => {
                                        debug!("PEER EXCHANGE: Peer {} confirmed receipt of peer list.", peer);
                                    },
                                    SyncResponse::ConsensusResponse(Some(consensus_msg)) => {
                                        info!("[P2P DIRECT] Received consensus response from {}: {:?}", peer, consensus_msg);
                                        if p2p_to_consensus_tx.send((*consensus_msg, peer, None)).await.is_err() {
                                            warn!("[P2P DIRECT] Failed to send consensus response to engine (no listeners).");
                                        }
                                    },
                                    SyncResponse::ConsensusResponse(None) => {
                                        debug!("[P2P DIRECT] Received consensus ack from peer {}", peer);
                                    }
                                    SyncResponse::FullProposal(Some(pending_batch)) => {
                                        info!("[SYNC] Received full proposal for batch 0x{} from peer {}", hex::encode(&pending_batch.header.calculate_hash()[..4]), peer);
                                        let batch_proposal = PayloadBatch {
                                            header: pending_batch.header.clone(),
                                            payloads: pending_batch.payloads.clone(),
                                            round: pending_batch.round,
                                            justify: pending_batch.parent_qc.clone(),
                                        };

                                        let msg_tuple = (
                                            ConsensusMessage::IntentBatchProposal(Box::new(batch_proposal)),
                                            peer,
                                            None
                                        );
                                        if p2p_to_consensus_tx.send(msg_tuple).await.is_err() {
                                            error!("[P2P] Failed to send synced proposal to consensus channel.");
                                        }
                                    },
                                    SyncResponse::FullProposal(None) => {
                                        warn!("[SYNC] Peer {} responded but could not find the requested proposal.", peer);
                                    },
                                    _ => {
                                        info!("[SYNC] Received synchronization response from peer {}", peer);
                                    }
                                }
                            }
                        }
                    },
                    _ => {}
                }
            }
        }
    }
}
