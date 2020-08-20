use tezos_messages::p2p::encoding::{metadata::MetadataMessage, peer::PeerMessageResponse};
use super::value::Named;

impl Named for MetadataMessage {
    const NAME: &'static str = "metadata_message";
}

impl Named for PeerMessageResponse {
    const NAME: &'static str = "peer_message";
}

#[cfg(test)]
mod tests {
    use wireshark_epan_adapter::dissector::HasFields;
    use super::*;
    use crate::value::TezosEncoded;

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
