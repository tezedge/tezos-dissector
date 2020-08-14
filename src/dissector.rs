use wireshark_epan_adapter::{Dissector, dissector::DissectorHelper};
use serde::Deserialize;

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

    fn recognize(&mut self, helper: DissectorHelper) -> usize {
        self.consume(helper)
    }

    fn consume(&mut self, helper: DissectorHelper) -> usize {
        use crate::network::prelude::ConnectionMessage;

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

        let mut context = helper.conversation_context::<()>();
        let c = context.as_mut();
        if c.is_none() {
            log::info!("new conversation {:?}", c as *const _);
            *c = Some(());
        }

        let payload = helper.payload();
        let length = payload.len();
        match process_connection_msg(payload) {
            Ok(connection) => helper.tree_mut().add_string_field(
                0,
                "tezos.connection_msg\0",
                format!("{:?}\0", connection),
            ),
            Err(_) => (),
        }
        length
    }
}
