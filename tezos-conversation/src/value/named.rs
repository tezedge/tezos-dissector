// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

use tezos_messages::p2p::encoding::{
    ack::AckMessage, metadata::MetadataMessage, peer::PeerMessageResponse,
    connection::ConnectionMessage,
};
use super::fields::Named;

// implement `Named` for all types that we expect to see in the dissector

impl Named for ConnectionMessage {
    const NAME: &'static str = "connection_message";
}

impl Named for AckMessage {
    const NAME: &'static str = "ack_message";
}

impl Named for MetadataMessage {
    const NAME: &'static str = "metadata_message";
}

impl Named for PeerMessageResponse {
    const NAME: &'static str = "peer_message";
}

#[cfg(test)]
mod tests {
    use wireshark_definitions::HasFields;
    use super::{ConnectionMessage, AckMessage, MetadataMessage, PeerMessageResponse};
    use crate::value::TezosEncoded;

    #[test]
    fn connection_message_fields() {
        let fields = TezosEncoded::<ConnectionMessage>::fields();
        println!("{:#?}", fields);
    }

    #[test]
    fn ack_message_fields() {
        let fields = TezosEncoded::<AckMessage>::fields();
        println!("{:#?}", fields);
    }

    #[test]
    fn metadata_message_fields() {
        let fields = TezosEncoded::<MetadataMessage>::fields();
        println!("{:#?}", fields);
    }

    #[test]
    fn peer_message_fields() {
        let fields = TezosEncoded::<PeerMessageResponse>::fields();
        println!("{:#?}", fields);
    }
}
