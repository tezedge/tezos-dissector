use wireshark_epan_adapter::dissector::{Tree, PacketInfo};
use tezos_messages::p2p::binary_message::cache::CachedData;
use std::task::Poll;
use crate::identity::Identity;
use super::{Handshake, Sender, MaybePlain, DecryptionError};

pub struct Context {
    handshake: Handshake,
    chunks_from_initiator: Vec<MaybePlain>,
    chunks_from_responder: Vec<MaybePlain>,
}

impl Context {
    pub fn invalid(&self) -> bool {
        self.handshake.invalid()
    }

    pub fn consume(
        &mut self,
        payload: &[u8],
        packet_info: &PacketInfo,
        identity: Option<&Identity>,
    ) {
        match self.handshake.consume(payload, packet_info, identity) {
            Poll::Ready(Ok(Sender::Initiator(mut m))) => self.chunks_from_initiator.append(&mut m),
            Poll::Ready(Ok(Sender::Responder(mut m))) => self.chunks_from_responder.append(&mut m),
            _ => (),
        }
    }

    pub fn id(&self) -> String {
        self.handshake.id()
    }

    pub fn visualize(&mut self, payload: &[u8], packet_info: &PacketInfo, root: &mut Tree) {
        use wireshark_epan_adapter::dissector::TreeLeaf;

        let mut main = root.add("tezos", 0..payload.len(), TreeLeaf::nothing()).subtree();
        main.add("conversation_id", 0..0, TreeLeaf::Display(self.id()));

        let f = packet_info.frame_number();
        let (caption, messages, first_offset, last_offset, start) = {
            let (initiator, range) = self.handshake.frame_description(f);
            let c_range = (range.start.index as usize)..(range.end.index as usize);
            (
                if initiator { "from initiator" } else { "from responder" },
                if initiator {
                    &self.chunks_from_initiator[c_range]
                } else {
                    &self.chunks_from_responder[c_range]
                },
                range.start.offset as usize,
                range.end.offset as usize,
                range.start.index,
            )
        };
        main.add("direction", 0..0, TreeLeaf::Display(caption));

        let mut offset = 0;
        for (i, message) in messages.iter().enumerate() {
            let this_offset = offset;
            let header_end = match i {
                // first chunk in the packet
                0 => {
                    offset += message.length() - first_offset + 2;
                    2 - usize::min(2, first_offset)
                },
                // middle chunk in the packet
                l if l < messages.len() - 1 => {
                    offset += message.length() + 2;
                    2
                },
                // last chunk in the packet
                l if l == messages.len() - 1 => {
                    if last_offset == 0 {
                        offset += message.length() + 2;
                        2
                    } else {
                        usize::min(2, last_offset)
                    }
                },
                _ => panic!(),
            };
            let header_range = 0..header_end;
            let body_end = header_end + message.length() - 16;
            let body_upper_bound = usize::min(payload.len(), body_end);
            let body_range = header_end..body_upper_bound;
            let mac_upper_bound = usize::min(payload.len(), body_end + 16);
            let mac_range = body_upper_bound..mac_upper_bound;

            let chunk_range = this_offset..(this_offset + mac_upper_bound);

            let index = start as i64 + i as i64;
            let mut c_tree = main.add("chunk", chunk_range, TreeLeaf::dec(index)).subtree();
            c_tree.add("length", header_range, TreeLeaf::dec(message.length() as _));

            match message {
                &MaybePlain::Error(ref chunk, DecryptionError::HasNoIdentity) => {
                    let l = format!("encrypted: {}", hex::encode(chunk.content()));
                    c_tree.add("identity_required", body_range, TreeLeaf::Display(l));
                },
                &MaybePlain::Error(ref chunk, DecryptionError::WrongMac) => {
                    let l = format!("encrypted: {}", hex::encode(chunk.content()));
                    c_tree.add("mac_error", body_range, TreeLeaf::Display(l));
                },
                &MaybePlain::Connection(_, ref connection) => {
                    main.show(connection, &[]);
                    let plain = connection.cache_reader().get().unwrap();
                    c_tree.add("decrypted_data", body_range, TreeLeaf::Display(hex::encode(plain)));
                },
                &MaybePlain::Plain(ref plain) => {
                    c_tree.add("decrypted_data", body_range, TreeLeaf::Display(hex::encode(plain)));
                },
            }
            c_tree.add("mac", mac_range, TreeLeaf::Display(""));
        }
    }
}

impl Default for Context {
    fn default() -> Self {
        Context {
            handshake: Handshake::new(),
            chunks_from_initiator: Vec::new(),
            chunks_from_responder: Vec::new(),
        }
    }
}
