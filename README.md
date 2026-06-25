# Evice Multi Sequencer

A **decentralized ordering engine** that any application can plug in to achieve censorship-resistant, fair payload sequencing — with finality delegated to a settlement layer.

Built in Rust. Stateless by design. No smart contracts, no tokens, no state trie — just fast, fair ordering of raw `PayloadBatch` data (`Vec<u8>`).

## Why Decentralized Sequencing?

Most rollup and off-chain sequencers today are **centralized** — a single operator controlling what gets ordered, when, and in what sequence. This creates:

- **Single Point of Failure** — If the sequencer goes down, the entire system halts.
- **Censorship Risk** — A single operator can selectively exclude or reorder payloads.
- **MEV Extraction** — Centralized ordering enables front-running and sandwich attacks.

`evice-sequencer` eliminates these risks by distributing ordering responsibility across multiple independent nodes that reach **BFT consensus** on payload sequence.

> **Trust Model:** The sequencer does *not* guarantee execution correctness — that responsibility belongs to the settlement layer (e.g., ZK-Proofs on L1). The sequencer guarantees **liveness**, **fairness**, and **censorship resistance** of ordering.

## Architecture

Derived from the **Aegis Consensus Architecture** ([evice-blockchain-aegis](https://github.com/syafiqeil/evice-blockchain-aegis)), heavily refactored from a monolithic L1 blockchain into a **stateless, modular ordering engine**.

```
┌─────────────────────────────────────────────────────┐
│              Host Application (e.g. DEX)            │
│                                                     │
│  ┌───────────┐    PayloadBatch    ┌──────────────┐  │
│  │ Matching  │◄───────────────────│  Consensus   │  │
│  │  Engine   │    (confirmed)     │   Engine     │  │
│  └───────────┘                    │  (PBFT/QC)   │  │
│                                   └──────┬───────┘  │
│                                          │          │
│                                   ┌──────▼───────┐  │
│                                   │  P2P Layer   │  │
│                                   │  (libp2p)    │  │
│                                   └──────────────┘  │
└─────────────────────────────────────────────────────┘
        │                │                │
   ┌────▼────┐      ┌────▼────┐      ┌───▼─────┐
   │ Node 1  │      │ Node 2  │      │ Node N  │
   └─────────┘      └─────────┘      └─────────┘
```

### Core Modules

- **Consensus (`consensus/`)**: Leader-based PBFT mechanism for fast optimistic confirmations.
  - VRF-driven leader election via Schnorrkel for unpredictable, verifiable rotation.
  - Sub-committee based view-change for Byzantine fault tolerance.
  - Generates `QuorumCertificate` (QC) after achieving **2/3 + 1** agreement.

- **Networking (`p2p/`)**: Built on `libp2p`.
  - **Gossipsub** for fast payload propagation and consensus message distribution.
  - **Kademlia DHT** for decentralized peer discovery.
  - Custom **Request/Response** protocols for state synchronization.

## Cryptography

| Primitive | Purpose |
|-----------|---------|
| **Dilithium2** (Post-Quantum) | Payload & vote signing — future-proof against quantum threats |
| **Schnorrkel VRF** | Deterministic, verifiable leader election |
| **ChaCha20Poly1305** | Keystore encryption at rest |
| **Scrypt** | Key derivation for keystore passphrase |

## Integration

The sequencer is designed as a **library dependency** (`cargo add`), not a standalone binary. Your application initializes the engine, submits payloads, and receives confirmed batches via async channels.

```rust
use std::sync::{Arc, atomic::AtomicBool};
use tokio::sync::{RwLock, Mutex, mpsc};
use evice_sequencer::{
    consensus::{ConsensusEngine, ConsensusState, QuorumCertificate},
    crypto::ValidatorKeys,
    genesis::Genesis,
    p2p::{types::AddressBook, swarm::setup_swarm},
    AppPayload,
};

// 1. Initialize Validator Keys (Dilithium2 + Schnorrkel VRF)
let keys = Arc::new(ValidatorKeys::generate());
let my_address = evice_sequencer::crypto::public_key_to_address(&keys.signing_keys.public_key_bytes());

// 2. Load Genesis & Address Book
let genesis = Genesis::load_from_file("genesis.json").unwrap();
let mut address_book = AddressBook::default();
address_book.update_from_genesis(&genesis);
let address_book = Arc::new(Mutex::new(address_book));

// 3. Initialize Consensus State & Mempool
let initial_qc = QuorumCertificate::genesis_qc();
let state = ConsensusState::new(initial_qc);
let mempool = Arc::new(RwLock::new(Vec::new()));

// 4. Setup Channels
let (p2p_cmd_tx, p2p_cmd_rx) = mpsc::channel(100);
let (consensus_msg_tx, consensus_msg_rx) = mpsc::channel(100);
let (tx_to_p2p_tx, tx_to_p2p_rx) = mpsc::channel(100);

// 5. Create the output channel for confirmed batches
let (confirmed_batch_tx, mut confirmed_batch_rx) = mpsc::channel(64);

// 6. Initialize the Consensus Engine
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
    confirmed_batch_tx,
    shutdown: Arc::new(AtomicBool::new(false)),
};

// 7. Submit payloads via the public API
engine.submit_payload(AppPayload(b"raw_intent_data".to_vec())).await;

// 8. Spawn the engine and listen for confirmed batches
let engine_handle = engine.clone();
tokio::spawn(engine_handle.run(consensus_msg_rx, tx_to_p2p_rx));

// 9. Your application receives confirmed batches here
while let Some(confirmed_batch) = confirmed_batch_rx.recv().await {
    println!("Batch #{} confirmed with {} payloads",
        confirmed_batch.header.index,
        confirmed_batch.payloads.len(),
    );
    // Feed into your matching engine, settlement layer, etc.
}

// 10. Graceful shutdown
engine.request_shutdown();
```

The three primary APIs:
- **`submit_payload()`** — Push a payload into the mempool and gossip it to peers.
- **`confirmed_batch_rx`** — Receive confirmed `PayloadBatch` structures after quorum is reached.
- **`request_shutdown()`** — Gracefully stop the consensus engine loop.

## Security Model

The engine operates on an **optimistic ordering** model:

- The sequencer network agrees on **order**, not on **validity**.
- A settlement component on the host application is responsible for submitting sequenced payloads to a smart contract for **true finality** via ZK-Proofs.
- This separation of concerns (ordering vs. settlement) allows the sequencer to remain stateless and fast while delegating trust to the cryptographic guarantees of the settlement layer.

## License

Dual-licensed under MIT and Apache 2.0
