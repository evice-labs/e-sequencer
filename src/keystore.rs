use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use cipher::InvalidLength;
use rand::Rng;
use scrypt::{
    errors::{InvalidOutputLen, InvalidParams},
    scrypt, Params as ScryptParams,
};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::crypto::{public_key_to_address, PRIVATE_KEY_SIZE, PUBLIC_KEY_SIZE};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Keystore {
    pub address: String,
    pub public_key: String,
    crypto: Crypto,
    pub id: String,
    pub version: u8,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Crypto {
    cipher: String,
    ciphertext: String,
    cipherparams: CipherParams,
    kdf: String,
    kdfparams: KdfParams,
    mac: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct CipherParams {
    nonce: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct KdfParams {
    dklen: u32,
    n: u32,
    p: u32,
    r: u32,
    salt: String,
}

#[derive(Error, Debug)]
pub enum KeystoreError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("Hex decoding error: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("Scrypt params error: {0}")]
    ScryptParams(#[from] InvalidParams),
    #[error("Scrypt output length error: {0}")]
    ScryptOutputLen(#[from] InvalidOutputLen),
    #[error("Cipher error: {0}")]
    Cipher(#[from] InvalidLength),
    #[error("Padding error during decryption")]
    PaddingError,
    #[error("Invalid password or corrupted keystore")]
    InvalidPassword,
    #[error("Decrypted key has invalid length")]
    InvalidKeyLength,
    #[error("Unsupported keystore version: {0}")]
    UnsupportedVersion(u8),
    #[error("AEAD encryption/decryption error")]
    AeadError,
}

impl From<chacha20poly1305::Error> for KeystoreError {
    fn from(_: chacha20poly1305::Error) -> Self {
        KeystoreError::AeadError
    }
}

impl Keystore {
    pub fn new(
        pk_bytes: &[u8; PRIVATE_KEY_SIZE],
        password: &str,
        pub_key_full_bytes: &[u8; PUBLIC_KEY_SIZE],
    ) -> Result<Self, KeystoreError> {
        let mut salt = [0u8; 32];
        rand::rng().fill_bytes(&mut salt);

        let mut nonce_bytes = [0u8; 24];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from(nonce_bytes);

        let kdfparams = KdfParams {
            dklen: 32,
            n: 262144,
            p: 1,
            r: 8,
            salt: hex::encode(salt),
        };

        let mut derived_key = [0u8; 32];
        let scrypt_params = ScryptParams::new(18, 8, 1)?;
        scrypt(password.as_bytes(), &salt, &scrypt_params, &mut derived_key)?;

        let cipher = XChaCha20Poly1305::new(&derived_key.into());
        let ciphertext_vec = cipher.encrypt(&nonce, pk_bytes.as_ref())?;
        let ciphertext = hex::encode(&ciphertext_vec);

        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(&derived_key[16..32]);
        mac_input.extend_from_slice(&ciphertext_vec);
        let mac = Keccak256::digest(&mac_input);

        let address_hex = hex::encode(public_key_to_address(pub_key_full_bytes).as_ref());
        let pub_key_full_hex = hex::encode(pub_key_full_bytes);

        Ok(Self {
            address: address_hex,
            public_key: pub_key_full_hex,
            crypto: Crypto {
                cipher: "xchacha20poly1305".to_string(),
                ciphertext,
                cipherparams: CipherParams {
                    nonce: hex::encode(nonce_bytes),
                },
                kdf: "scrypt".to_string(),
                kdfparams,
                mac: hex::encode(mac),
            },
            id: Uuid::new_v4().to_string(),
            version: 4,
        })
    }

    pub fn decrypt(&self, password: &str) -> Result<Vec<u8>, KeystoreError> {
        if self.version < 4 {
            return Err(KeystoreError::UnsupportedVersion(self.version));
        }

        let salt = hex::decode(&self.crypto.kdfparams.salt)?;
        let nonce_bytes = hex::decode(&self.crypto.cipherparams.nonce)?;

        let mut nonce_array = [0u8; 24];
        nonce_array.copy_from_slice(&nonce_bytes);
        let nonce = XNonce::from(nonce_array);

        let ciphertext_bytes = hex::decode(&self.crypto.ciphertext)?;

        let mut derived_key = [0u8; 32];
        let scrypt_params = ScryptParams::new(
            self.crypto.kdfparams.n.ilog2() as u8,
            self.crypto.kdfparams.r,
            self.crypto.kdfparams.p,
        )?;
        scrypt(password.as_bytes(), &salt, &scrypt_params, &mut derived_key)?;

        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(&derived_key[16..32]);
        mac_input.extend_from_slice(&ciphertext_bytes);
        let expected_mac = Keccak256::digest(&mac_input);

        if hex::encode(expected_mac) != self.crypto.mac {
            derived_key.zeroize();
            return Err(KeystoreError::InvalidPassword);
        }

        let cipher = XChaCha20Poly1305::new(&derived_key.into());
        let decrypted_vec = cipher.decrypt(&nonce, ciphertext_bytes.as_ref())?;
        derived_key.zeroize();

        if decrypted_vec.len() != PRIVATE_KEY_SIZE {
            return Err(KeystoreError::InvalidKeyLength);
        }

        Ok(decrypted_vec)
    }

    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self, KeystoreError> {
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        Ok(serde_json::from_str(&contents)?)
    }

    pub fn save_to_path<P: AsRef<Path>>(&self, path: P) -> Result<(), KeystoreError> {
        let path_ref = path.as_ref();
        let dir = path_ref
            .parent()
            .ok_or(KeystoreError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                "No parent dir",
            )))?;

        let tmp_name = format!(".{}.tmp", Uuid::new_v4());
        let tmp_path = dir.join(tmp_name);

        let json = serde_json::to_string_pretty(self)?;

        {
            let mut opts = OpenOptions::new();
            opts.write(true).create_new(true);

            #[cfg(unix)]
            {
                opts.mode(0o600);
            }

            let mut file = opts.open(&tmp_path)?;
            file.write_all(json.as_bytes())?;
            file.sync_all()?;
        }

        std::fs::rename(&tmp_path, path_ref)?;

        #[cfg(unix)]
        {
            let dir_file = File::open(dir)?;
            dir_file.sync_all()?;
        }

        Ok(())
    }

    pub fn zeroize_private_key_bytes(bytes: &mut [u8]) {
        bytes.zeroize();
    }
}
