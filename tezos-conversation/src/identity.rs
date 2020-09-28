// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

use serde::Deserialize;
use crypto::{
    crypto_box::{PrecomputedKey, precompute, decrypt, encrypt, CryptoError},
    nonce::{NoncePair, Nonce, generate_nonces},
};
use tezos_messages::p2p::encoding::{
    connection::ConnectionMessage,
    version::NetworkVersion,
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
        let content = std::fs::read_to_string(path.as_ref())?;
        serde_json::from_str(&content).map_err(Into::into)
    }

    pub fn connection_message(&self) -> ConnectionMessage {
        let version = NetworkVersion::new("testnet".to_owned(), 0, 0);
        ConnectionMessage::new(1234, &self.public_key, &self.proof_of_work_stamp, [0; 24].as_ref(), vec![version])
    }

    /// Create a decipher object using connection message pair.
    pub fn decipher(
        &self,
        initiator_chunk: &[u8],
        responder_chunk: &[u8],
    ) -> Result<Decipher, IdentityError> {
        let initiator_pk_string = hex::encode(&initiator_chunk[4..36]);
        let responder_pk_string = hex::encode(&responder_chunk[4..36]);
        // check if the identity belong to one of the parties
        let other_pk = if initiator_pk_string == self.public_key {
            responder_pk_string
        } else if responder_pk_string == self.public_key {
            initiator_pk_string
        } else {
            return Err(IdentityError::CannotDecrypt);
        };

        Ok(Decipher {
            key: precompute(&other_pk, &self.secret_key)
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

// it will be better to implement it as method of `Nonce`
fn add_nonce(nonce: &Nonce, addition: u64) -> Nonce {
    let bytes = nonce.get_bytes();
    let n = BigUint::from_bytes_be(bytes.as_slice());
    let bytes = <BigUint as Add<u64>>::add(n, addition).to_bytes_be();
    Nonce::new(bytes.as_slice())
}

impl Decipher {
    pub fn decrypt(&self, enc: &[u8], chunk_number: NonceAddition) -> Result<Vec<u8>, CryptoError> {
        // prepare the actual nonce for the message
        let nonce = match chunk_number {
            NonceAddition::Initiator(addition) => add_nonce(&self.nonce.local, addition),
            NonceAddition::Responder(addition) => add_nonce(&self.nonce.remote, addition),
        };

        decrypt(enc, &nonce, &self.key)
    }

    pub fn encrypt(&self, msg: &[u8], chunk_number: NonceAddition) -> Result<Vec<u8>, CryptoError> {
        let nonce = match chunk_number {
            NonceAddition::Initiator(addition) => add_nonce(&self.nonce.local, addition),
            NonceAddition::Responder(addition) => add_nonce(&self.nonce.remote, addition),
        };

        encrypt(msg, &nonce, &self.key)
    }
}
