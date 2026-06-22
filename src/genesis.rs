use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs::File, path::Path};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GenesisParameters {
    pub sub_committee_size: usize,
    pub proposer_timeout_ms: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Genesis {
    pub genesis_time: u64,
    pub chain_id: String,
    pub parameters: GenesisParameters,
    pub accounts: HashMap<String, GenesisAccount>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GenesisAccount {
    pub public_key: String,
    pub vrf_public_key: Option<String>,
    pub network_identity: Option<String>,
}

impl Genesis {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let file = File::open(path)?;
        let genesis: Self = serde_json::from_reader(file)?;
        Ok(genesis)
    }
}
