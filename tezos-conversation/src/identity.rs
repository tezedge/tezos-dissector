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

pub enum IdentityError {
    Invalid,
    CannotDecrypt,
}

impl Identity {
    /// Read and deserialize the identity from json file using serde.
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

    /// Create a decipher object using connection message pair.
    pub fn decipher(
        &self,
        initiator_chunk: &[u8],
        responder_chunk: &[u8],
    ) -> Result<Decipher, IdentityError> {
        let initiator_pk_string =
            HashType::CryptoboxPublicKeyHash.bytes_to_string(&initiator_chunk[4..36]);
        let responder_pk_string =
            HashType::CryptoboxPublicKeyHash.bytes_to_string(&responder_chunk[4..36]);
        // check if the identity belong to one of the parties
        let other_pk = if initiator_pk_string == self.public_key {
            responder_chunk[4..36].to_owned()
        } else if responder_pk_string == self.public_key {
            initiator_chunk[4..36].to_owned()
        } else {
            return Err(IdentityError::CannotDecrypt);
        };

        Ok(Decipher {
            key: precompute(&hex::encode(&other_pk), &self.secret_key)
                .map_err(|_| IdentityError::Invalid)?,
            // initiator/responder is not the same as local/remote party,
            // but let's only in this module treat initiator as local party, and responder as remote
            nonce: generate_nonces(initiator_chunk, responder_chunk, false),
        })
    }
}

/// Decipher object, contains precomputed key and initial nonces
pub struct Decipher {
    key: PrecomputedKey,
    nonce: NoncePair,
}

/// Identification of the chunk, its number and direction
#[derive(Copy, Clone)]
pub enum NonceAddition {
    Initiator(u64),
    Responder(u64),
}

impl Decipher {
    pub fn decrypt(&self, enc: &[u8], chunk_number: NonceAddition) -> Result<Vec<u8>, CryptoError> {
        // it will be better to implement it as method of `Nonce`
        let add = |nonce: &Nonce, addition: u64| -> Nonce {
            let bytes = nonce.get_bytes();
            let n = BigUint::from_bytes_be(bytes.as_slice());
            let bytes = <BigUint as Add<u64>>::add(n, addition).to_bytes_be();
            Nonce::new(bytes.as_slice())
        };

        // prepare the actual nonce for the message
        let nonce = match chunk_number {
            NonceAddition::Initiator(addition) => add(&self.nonce.local, addition),
            NonceAddition::Responder(addition) => add(&self.nonce.remote, addition),
        };

        decrypt(enc, &nonce, &self.key)
    }
}
