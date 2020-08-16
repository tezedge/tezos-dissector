use serde::Deserialize;
use crypto::hash::HashType;
use std::path::Path;
use crate::network::prelude::{ConnectionMessage, EncryptedMessageDecoder};

#[derive(Deserialize, Clone, Debug, PartialEq)]
/// Node identity information
pub struct Identity {
    pub peer_id: String,
    pub public_key: String,
    pub secret_key: String,
    pub proof_of_work_stamp: String,
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

    pub fn decipher_pair(
        &self,
        incoming_message: &ConnectionMessage,
        outgoing_message: &ConnectionMessage,
    ) -> Option<(EncryptedMessageDecoder, EncryptedMessageDecoder)> {
        let _ = (incoming_message, outgoing_message);
        // TODO:
        None
    }
}
