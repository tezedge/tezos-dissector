use serde::Deserialize;
use crypto::{
    hash::HashType,
    crypto_box::{PrecomputedKey, precompute, decrypt, CryptoError},
    nonce::{NoncePair, Nonce, generate_nonces},
};
use tezos_messages::p2p::binary_message::{BinaryChunk, cache::CachedData};
use std::{path::Path, ops::Add};
use num_bigint::BigUint;
use crate::conversation::ConnectionMessage;

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

    pub fn decipher(
        &self,
        initiator_message: &ConnectionMessage,
        responder_message: &ConnectionMessage,
    ) -> Option<Decipher> {
        let initiator_pk_string =
            HashType::CryptoboxPublicKeyHash.bytes_to_string(&initiator_message.public_key);
        let other_pk = if initiator_pk_string == self.public_key {
            responder_message.public_key.clone()
        } else {
            initiator_message.public_key.clone()
        };

        let initiator_cache = initiator_message.cache_reader().get().unwrap();
        let initiator_cache = BinaryChunk::from_content(&initiator_cache).ok()?;

        let responder_cache = responder_message.cache_reader().get().unwrap();
        let responder_cache = BinaryChunk::from_content(&responder_cache).ok()?;

        Some(Decipher {
            key: precompute(&hex::encode(&other_pk), &self.secret_key).ok()?,
            nonce: generate_nonces(initiator_cache.raw(), responder_cache.raw(), false),
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
