use wireshark_epan_adapter::dissector::{Tree, PacketInfo};
use tezos_messages::p2p::binary_message::cache::CachedData;
use std::{task::Poll, ops::Range};
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

    pub fn visualize(&mut self, packet_length: usize, packet_info: &PacketInfo, root: &mut Tree) {
        use wireshark_epan_adapter::dissector::TreeLeaf;

        let mut main = root.add("tezos", 0..packet_length, TreeLeaf::nothing()).subtree();
        main.add("conversation_id", 0..0, TreeLeaf::Display(self.id()));

        let f = packet_info.frame_number();

        let (caption, messages, first_offset, last_offset, start, maybe_last) = {
            let (initiator, range) = self.handshake.frame_description(f);
            let chunks = if initiator {
                &self.chunks_from_initiator
            } else {
                &self.chunks_from_responder
            };
            let c_range = (range.start.index as usize)..(range.end.index as usize);
            (
                if initiator { "from initiator" } else { "from responder" },
                &chunks[c_range],
                range.start.offset as usize,
                range.end.offset as usize,
                range.start.index,
                if range.end.offset > 0 {
                    chunks.get(range.end.index as usize)
                } else {
                    None
                }
            )
        };
        main.add("direction", 0..0, TreeLeaf::Display(caption));

        fn show_chunk(
            chunk: &MaybePlain,
            main: &mut Tree,
            index: usize,
            chunk_range: Range<usize>,
            header_range: Range<usize>,
            body_range: Range<usize>,
            mac_range: Range<usize>,
        ) {
            let mut c_tree = main.add("chunk", chunk_range, TreeLeaf::dec(index as _)).subtree();
            c_tree.add("length", header_range, TreeLeaf::dec(chunk.length() as _));
            match chunk {
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

        let mut offset = 0;
        for (i, message) in messages.iter().enumerate() {
            let this_offset = offset;
            let header_end = match i {
                // first chunk in the packet
                0 => {
                    offset += message.length() - first_offset + 2;
                    2 - usize::min(2, first_offset)
                },
                // middle chunk in the packet, last chunk will be processes later
                l if l < messages.len() => {
                    offset += message.length() + 2;
                    2
                },
                _ => panic!(),
            };
            let header_range = 0..header_end;
            let body_end = header_end + message.length() - 16;
            let body_upper_bound = usize::min(packet_length, body_end);
            let body_range = header_end..body_upper_bound;
            let mac_upper_bound = usize::min(packet_length, body_end + 16);
            let mac_range = body_upper_bound..mac_upper_bound;

            let chunk_range = this_offset..(this_offset + mac_upper_bound);

            let index = start as usize + i;
            show_chunk(message, &mut main, index, chunk_range, header_range, body_range, mac_range);
        }

        if last_offset > 0 {
            let index = start as usize + messages.len();
            let chunk_range = offset..(offset + last_offset);

            if let Some(last) = maybe_last {
                show_chunk(last, &mut main, index, chunk_range, 0..0, 0..0, 0..0);
            } else {
                let index = index as i64;
                let mut c_tree = main.add("chunk", chunk_range, TreeLeaf::dec(index)).subtree();
                let length = maybe_last.map(MaybePlain::length).unwrap_or(0) as i64;
                c_tree.add("length", 0..0, TreeLeaf::dec(length));
                c_tree.add("buffering", 0..0, TreeLeaf::Display("..."));
                c_tree.add("mac", 0..0, TreeLeaf::Display(""));
            }
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
