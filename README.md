# Evice Multi Sequencer

This library contains the lightweight, high-performance intent-centric consensus and peer-to-peer networking engine for the decentralized ecosystem. It is designed to act as an off-chain ordering layer that achieves fast multi-sequencer consensus (PBFT-style) and settles batched intent payloads efficiently.

## Architecture

The `evice-multi-sequencer` crate is derived from the **Aegis Consensus Architecture** of the [Evice Blockchain Aegis](https://github.com/syafiqeil/evice-blockchain-aegis) project. It simply orders arbitrary application payloads (`AppPayload`).

It consists of two main modules:
- **Consensus (`consensus/`)**: A leader-based PBFT mechanism for fast optimistic confirmations.
  - Implements an optimistic view-change driven by sub-committees.
  - Generates `QuorumCertificate` (QC) after achieving 2/3 + 1 consensus.
- **Networking (`p2p/`)**: Built heavily on `libp2p`.
  - Subscribes to Gossipsub for fast block propagation and message distribution.
  - Uses Kademlia for Peer discovery.
  - Implements custom Request/Response protocols for synchronization.

## Cryptography
- Post-Quantum Dilithium2 for future-proofing against quantum computing threats.
- Schnorrkel VRF (Verifiable Random Function) for deterministic leader election.
- ChaCha20Poly1305 and Scrypt for secure Keystore encryption.

## Integration

To integrate the sequencer into your application, you must initialize the cryptographic keys, the peer-to-peer network, and the consensus state before running the engine.

Here is a high-level example of how to instantiate the sequencer node:

```rust
use std::sync::Arc;
use tokio::sync::{RwLock, Mutex, mpsc};
use evice_multi_sequencer::{
    consensus::{ConsensusEngine, ConsensusState, QuorumCertificate},
    crypto::ValidatorKeys,
    genesis::Genesis,
    p2p::{types::AddressBook, swarm::setup_swarm},
};

// 1. Initialize Validator Keys (Dilithium2 + Schnorrkel VRF)
let keys = Arc::new(ValidatorKeys::generate());
let my_address = evice_multi_sequencer::crypto::public_key_to_address(&keys.signing_keys.public_key_bytes());

// 2. Load Genesis & Address Book
let genesis = Genesis::load_from_file("genesis.json").unwrap();
let mut address_book = AddressBook::default();
address_book.update_from_genesis(&genesis);
let address_book = Arc::new(Mutex::new(address_book));

// 3. Initialize Consensus State & Mempool
let initial_qc = QuorumCertificate::genesis_qc();
let state = ConsensusState::new(initial_qc);
let mempool = Arc::new(RwLock::new(Vec::new()));

// 4. Setup P2P Swarm Channels
let (p2p_cmd_tx, p2p_cmd_rx) = mpsc::channel(100);
let (consensus_msg_tx, consensus_msg_rx) = mpsc::channel(100);
let (tx_to_p2p_tx, tx_to_p2p_rx) = mpsc::channel(100);

// 5. Initialize and Spawn the Consensus Engine
let engine = ConsensusEngine {
    my_address,
    validator_keys: keys,
    p2p_cmd_tx,
    state,
    consensus_ready: Arc::clone(&consensus_ready_flag),
    address_book,
    pending_tx_requests: Arc::new(RwLock::new(HashMap::new())),
    tx_gossip: tx_to_p2p_tx,
    mempool,
    chain_id: genesis.chain_id.clone(),
    genesis_params: genesis.parameters.clone(),
};

// Run the core loops concurrently
tokio::spawn(engine.run(consensus_msg_rx, tx_to_p2p_rx));
// tokio::spawn(run_swarm(...)); 
```

Applications push their transactions directly to the network via P2P and listen to confirmed `PayloadBatch` structures emitted by the consensus engine.

## Security 
Note: The engine generates batches optimistically. A rollup settlement component on the host node is responsible for submitting these sequenced intents to a smart contract to achieve true finality via ZK-Proofs.
