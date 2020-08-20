use wireshark_epan_adapter::dissector::{Tree, PacketInfo};
use std::task::Poll;
use crate::identity::Identity;
use super::{Handshake, Sender, ChunkBuffer, MaybePlain, DecryptionError};

pub struct Context {
    handshake: Handshake,
    from_initiator: ChunkBuffer,
    from_responder: ChunkBuffer,
    chunks_from_initiator: Vec<MaybePlain>,
    chunks_from_responder: Vec<MaybePlain>,
}

impl Context {
    pub fn invalid(&self) -> bool {
        match &self.handshake {
            &Handshake::Unrecognized => true,
            _ => false,
        }
    }

    pub fn consume(
        &mut self,
        payload: &[u8],
        packet_info: &PacketInfo,
        identity: Option<&Identity>,
    ) {
        let i = &mut self.from_initiator;
        let r = &mut self.from_responder;
        match self.handshake.consume(i, r, payload, packet_info, identity) {
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
        let i = self.from_initiator.frames_description(f);
        let r = self.from_responder.frames_description(f);
        let (caption, messages, first_offset, last_offset) = match (i, r) {
            (Some(_), Some(_)) => panic!(),
            (None, None) => panic!(),
            (Some(range), None) => {
                let c_range = (range.start.index as usize)..(range.end.index as usize);
                (
                    "from initiator",
                    &self.chunks_from_initiator[c_range],
                    range.start.offset as usize,
                    range.end.offset as usize,
                )
            },
            (None, Some(range)) => {
                let c_range = (range.start.index as usize)..(range.end.index as usize);
                (
                    "from responder",
                    &self.chunks_from_responder[c_range],
                    range.start.offset as usize,
                    range.end.offset as usize,
                )
            },
        };
        main.add("direction", 0..0, TreeLeaf::Display(caption));

        let mut offset = 0;
        for (i, message) in messages.iter().enumerate() {
            let chunk_header_range = match i {
                // first chunk in the packet
                0 => {
                    let r = if first_offset < 2 {
                        Some(0..(2 - first_offset))
                    } else {
                        None
                    };
                    offset += message.length() - first_offset + 2;
                    r
                },
                // middle chunk in the packet
                l if l < messages.len() - 1 => {
                    let r = Some(offset..(offset + 2));
                    offset += message.length() + 2;
                    r
                },
                // last chunk in the packet
                l if l == messages.len() - 1 => {
                    if last_offset == 0 {
                        let r = Some(offset..(offset + 2));
                        offset += message.length() + 2;
                        r
                    } else {
                        Some(offset..(offset + usize::min(2, last_offset)))
                    }
                },
                _ => panic!(),
            };
            let header_end = chunk_header_range.clone().unwrap_or(0..0).end;
            if let Some(range) = chunk_header_range {
                main.add("chunk_length", range, TreeLeaf::dec(message.length() as _));
            }
            let body_end = header_end + message.length() - 16;
            let body_upper_bound = usize::min(payload.len(), body_end);
            let body_range = header_end..body_upper_bound;
            let mac_upper_bound = usize::min(payload.len(), body_end + 16);
            let mac_range = body_upper_bound..mac_upper_bound;
            match message {
                &MaybePlain::Error(ref chunk, DecryptionError::HasNoIdentity) => {
                    let l = format!("encrypted: {}", hex::encode(chunk.content()));
                    main.add("identity_required", body_range, TreeLeaf::Display(l));
                },
                &MaybePlain::Error(ref chunk, DecryptionError::WrongMac) => {
                    let l = format!("encrypted: {}", hex::encode(chunk.content()));
                    main.add("error", body_range, TreeLeaf::Display(l));
                },
                &MaybePlain::Connection(_, ref connection) => {
                    main.show(connection, &[]);
                },
                &MaybePlain::Plain(ref plain) => {
                    main.add("decrypted_data", body_range, TreeLeaf::Display(hex::encode(plain)));
                },
            }
            main.add("mac", mac_range, TreeLeaf::Display(""));
        }
    }
}

impl Default for Context {
    fn default() -> Self {
        Context {
            handshake: Handshake::Initial,
            from_initiator: ChunkBuffer::new(),
            from_responder: ChunkBuffer::new(),
            chunks_from_initiator: Vec::new(),
            chunks_from_responder: Vec::new(),
        }
    }
}
