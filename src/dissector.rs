use wireshark_epan_adapter::{Dissector, dissector::DissectorHelper};
use serde::Deserialize;
use crate::network::prelude::ConnectionMessage;

#[derive(Deserialize, Clone, Debug, PartialEq)]
/// Node identity information
pub struct Identity {
    pub peer_id: String,
    pub public_key: String,
    pub secret_key: String,
    pub proof_of_work_stamp: String,
}

pub struct TezosDissector {
    identity: Option<Identity>,
}

impl TezosDissector {
    pub fn new() -> Self {
        TezosDissector { identity: None }
    }
}

impl Dissector for TezosDissector {
    fn prefs_update(&mut self, filenames: Vec<&str>) {
        use std::fs;
        use crypto::hash::HashType;

        // TODO: error handling
        if let Some(identity_path) = filenames.first().cloned() {
            if !identity_path.is_empty() {
                let content = fs::read_to_string(identity_path).unwrap();
                let mut identity: Identity = serde_json::from_str(&content).unwrap();
                let decoded = hex::decode(&identity.public_key).unwrap();
                identity.public_key = HashType::CryptoboxPublicKeyHash.bytes_to_string(&decoded);
                self.identity = Some(identity);
            }
        }
    }

    fn consume(&mut self, helper: DissectorHelper) -> usize {
        pub fn process_connection_msg(
            payload: Vec<u8>,
        ) -> Result<ConnectionMessage, failure::Error> {
            use std::convert::TryFrom;
            use tezos_messages::p2p::binary_message::BinaryChunk;

            let chunk = BinaryChunk::try_from(payload)?;
            let conn_msg = ConnectionMessage::try_from(chunk)?;
            Ok(conn_msg)
        }

        let mut helper = helper;
        let payload = helper.payload();
        let length = payload.len();
        let mut _c = helper.context::<Context>();
        match process_connection_msg(payload) {
            Ok(connection) => {
                let subtree = helper.tree_mut().subtree(0, 0..length);
                helper.tree_mut().add_string_field(
                    &subtree,
                    "tezos.connection_msg\0",
                    format!("{:?}\0", connection),
                    0..length,
                )
            },
            Err(_) => (),
        }
        length
    }
}

pub struct Context(Vec<u8>);

impl Default for Context {
    fn default() -> Self {
        let mut x = Vec::new();
        x.resize(0x100, 0);
        log::info!("allocated {:?}", x.as_ptr());
        Context(x)
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        log::info!("dropped {:?}", self.0.as_ptr());
    }
}
