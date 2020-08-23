// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

use serde::Deserialize;
use crypto::{
    hash::HashType,
    crypto_box::{PrecomputedKey, precompute, decrypt, CryptoError},
    nonce::{NoncePair, Nonce, generate_nonces},
};
use std::{path::Path, ops::Add};
use num_bigint::BigUint;

#[derive(Deserialize, Clone, Debug, PartialEq)]
/// Node identity information
pub struct Identity {
    peer_id: String,
    public_key: String,
    secret_key: String,
    proof_of_work_stamp: String,
}

impl Identity {
    pub fn from_path<P>(path: P) -> Result<Self, failure::Error>
    where
        P: AsRef<Path>,
    {
        use std::fs;

        let content = fs::read_to_string(path.as_ref())?;
        let mut identity: Identity = serde_json::from_str(&content)?;
        let decoded = hex::decode(&identity.public_key)?;
        identity.public_key = HashType::CryptoboxPublicKeyHash.bytes_to_string(&decoded);
        Ok(identity)
    }

    pub fn decipher(&self, initiator_chunk: &[u8], responder_chunk: &[u8]) -> Option<Decipher> {
        let initiator_pk_string =
            HashType::CryptoboxPublicKeyHash.bytes_to_string(&initiator_chunk[4..36]);
        let responder_pk_string =
            HashType::CryptoboxPublicKeyHash.bytes_to_string(&responder_chunk[4..36]);
        let other_pk = if initiator_pk_string == self.public_key {
            responder_chunk[4..36].to_owned()
        } else if responder_pk_string == self.public_key {
            initiator_chunk[4..36].to_owned()
        } else {
            None?
        };

        Some(Decipher {
            key: precompute(&hex::encode(&other_pk), &self.secret_key).ok()?,
            nonce: generate_nonces(initiator_chunk, responder_chunk, false),
        })
    }
}

pub struct Decipher {
    key: PrecomputedKey,
    nonce: NoncePair,
}

#[derive(Copy, Clone)]
pub enum NonceAddition {
    Initiator(u64),
    Responder(u64),
}

impl Add<usize> for NonceAddition {
    type Output = Self;

    fn add(self, rhs: usize) -> Self::Output {
        match self {
            NonceAddition::Initiator(x) => NonceAddition::Initiator(x + rhs as u64),
            NonceAddition::Responder(x) => NonceAddition::Responder(x + rhs as u64),
        }
    }
}

impl Decipher {
    pub fn decrypt(&self, enc: &[u8], chunk_number: NonceAddition) -> Result<Vec<u8>, CryptoError> {
        let add = |nonce: &Nonce, addition: u64| -> Nonce {
            let bytes = nonce.get_bytes();
            let n = BigUint::from_bytes_be(bytes.as_slice());
            let bytes = <BigUint as Add<u64>>::add(n, addition).to_bytes_be();
            Nonce::new(bytes.as_slice())
        };

        let nonce = match chunk_number {
            NonceAddition::Initiator(addition) => add(&self.nonce.local, addition),
            NonceAddition::Responder(addition) => add(&self.nonce.remote, addition),
        };

        decrypt(enc, &nonce, &self.key)
    }
}
