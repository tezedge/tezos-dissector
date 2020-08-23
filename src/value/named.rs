// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

use tezos_messages::p2p::encoding::{
    metadata::MetadataMessage, peer::PeerMessageResponse, version::NetworkVersion,
};
use tezos_encoding::encoding::{Field, HasEncoding, Encoding};
use super::fields::Named;

pub struct ConnectionMessage;

impl HasEncoding for ConnectionMessage {
    fn encoding() -> Encoding {
        Encoding::Obj(vec![
            Field::new("port", Encoding::Uint16),
            Field::new("public_key", Encoding::sized(32, Encoding::Bytes)),
            Field::new("proof_of_work_stamp", Encoding::sized(24, Encoding::Bytes)),
            Field::new("message_nonce", Encoding::sized(24, Encoding::Bytes)),
            //Field::new("versions", Encoding::list(NetworkVersion::encoding())),
            // WARNING: fix it
            Field::new("versions", NetworkVersion::encoding()),
        ])
    }
}

impl Named for ConnectionMessage {
    const NAME: &'static str = "connection_message";
}

impl Named for MetadataMessage {
    const NAME: &'static str = "metadata_message";
}

impl Named for PeerMessageResponse {
    const NAME: &'static str = "peer_message";
}

#[cfg(test)]
mod tests {
    use wireshark_epan_adapter::dissector::HasFields;
    use super::{ConnectionMessage, MetadataMessage, PeerMessageResponse};
    use crate::value::TezosEncoded;

    #[test]
    fn connection_message_fields() {
        let fields = TezosEncoded::<ConnectionMessage>::fields();
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
