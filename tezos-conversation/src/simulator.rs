use wireshark_definitions::{NetworkPacket, SocketAddress, TreePresenter, TreeLeaf};
use tezos_messages::p2p::{
    binary_message::{BinaryChunk, BinaryMessage},
    encoding::connection::ConnectionMessage,
};
use sodiumoxide::crypto::box_;
use std::{fmt, ops::Range, task::Poll};
use crate::{Conversation, BinaryChunkStorage, Identity, NonceAddition};

#[derive(Default, Clone)]
pub struct Tree {
    panic_on_decryption_error: bool,
}

impl Tree {
    pub fn panic_on_decryption_error(self) -> Self {
        let mut s = self;
        s.panic_on_decryption_error = true;
        s
    }
}

impl TreePresenter for Tree {
    fn subtree(&mut self) -> Self {
        self.clone()
    }

    fn add<D>(&mut self, path: &str, range: Range<usize>, v: TreeLeaf<D>) -> Self
    where
        D: fmt::Display,
    {
        let _ = (range, v);
        if self.panic_on_decryption_error && path.contains("decryption_error") {
            panic!()
        }
        self.clone()
    }
}

struct Packet {
    source: SocketAddress,
    destination: SocketAddress,
    number: u64,
    swapped: bool,
}

#[derive(Clone)]
pub struct PacketDescriptor {
    length: usize,
    swap: bool,
}

impl PacketDescriptor {
    pub fn new(length: usize, swap: bool) -> Result<Self, ()> {
        if length < u16::MAX as usize {
            Ok(PacketDescriptor { length, swap })
        } else {
            Err(())
        }
    }
}

fn packet_iter(descriptors: impl Iterator<Item = PacketDescriptor>) -> impl Iterator<Item = (Packet, usize)> {
    descriptors.enumerate()
        .map(|(number, PacketDescriptor { length, swap })| {
            let length = length.clone();
            // first message never swapped
            let swap = swap.clone() && number != 0;
            let source = SocketAddress::Ip("132.132.132.132:1234".parse().unwrap());
            let destination = SocketAddress::Ip("123.123.123.123:1234".parse().unwrap());
            (
                Packet {
                    source: if swap { destination.clone() } else { source.clone() },
                    destination: if swap { source.clone() } else { destination.clone() },
                    number: (number + 1) as _,
                    swapped: swap,
                },
                length,
            )
        })
}

pub fn simulate_foreign<T>(descriptors: &[PacketDescriptor], data: &[u8], output: &mut T)
where
    T: TreePresenter,
{
    let context = Conversation::new(0.0);
    let _ = packet_iter(descriptors.iter().cloned())
        .fold((context, 0), |(mut context, pos), (metadata, length)| {
            let end = pos + length;
            if data.len() > end {
                let packet = NetworkPacket {
                    source: metadata.source,
                    destination: metadata.destination,
                    number: metadata.number,
                    payload: data[pos..end].to_vec(),
                };
                match context.add(None, &packet) {
                    Poll::Ready(_) => panic!(),
                    Poll::Pending => (),
                }
                context.visualize(&packet, &BinaryChunkStorage::new(), output);
            }
            (context, end)
        });
}

pub fn simulate_handshake<T>(descriptors: &[PacketDescriptor], data: &[u8], output: &mut T)
where
    T: TreePresenter,
{
    let context = Conversation::new(0.0);
    let _ = packet_iter(descriptors.iter().cloned())
        .fold((context, 0), |(mut context, pos), (metadata, length)| {
            let end = pos + length;
            if data.len() > end {
                let chunk = BinaryChunk::from_content(&data[pos..end]).unwrap();
                let packet = NetworkPacket {
                    source: metadata.source,
                    destination: metadata.destination,
                    number: metadata.number,
                    payload: chunk.raw().to_vec(),
                };
                match context.add(None, &packet) {
                    Poll::Ready(_) => (),
                    Poll::Pending => panic!(),
                }
                context.visualize(&packet, &BinaryChunkStorage::new(), output);
            }
            (context, end)
        });
}

#[derive(Clone)]
pub struct ChunkDescriptor {
    length: usize,
}

impl ChunkDescriptor {
    pub fn new(length: usize) -> Result<Self, ()> {
        if length + 32 < u16::MAX as usize {
            Ok(ChunkDescriptor { length })
        } else {
            Err(())
        }
    }
}

pub fn simulate_encrypted<T>(
    descriptors: &[PacketDescriptor],
    initiator_chunk_descriptors: &[ChunkDescriptor],
    responder_chunk_descriptors: &[ChunkDescriptor],
    data: &[u8],
    output: &mut T,
) where
    T: TreePresenter,
{
    let path = "data/identity.json".to_owned();
    let identity = Identity::from_path(&path).unwrap();
    let cm_a = identity.connection_message();
    let (pk, _) = box_::gen_keypair();
    let cm_b = ConnectionMessage::new(4321, &hex::encode(pk.as_ref()), &hex::encode([0; 24]), [0; 24].as_ref(), cm_a.versions.clone());
    let chunk_a = BinaryChunk::from_content(&cm_a.as_bytes().unwrap()).unwrap();
    let chunk_b = BinaryChunk::from_content(&cm_b.as_bytes().unwrap()).unwrap();
    let (data_a, data_b) = encrypt_conversation(descriptors, data, initiator_chunk_descriptors, responder_chunk_descriptors, &chunk_a, &chunk_b, &identity);

    let handshake_descriptors = [
        PacketDescriptor::new(chunk_a.content().len() + 2, false).unwrap(),
        PacketDescriptor::new(chunk_b.content().len() + 2, true).unwrap(),
    ];

    let id = (identity, path);
    let context = Conversation::new(0.0);
    let _ = packet_iter(handshake_descriptors.iter().cloned().chain(descriptors.iter().cloned()))
        .fold((context, 0, 0), |(mut context, pos_a, pos_b), (metadata, length)| {
            let (end_a, end_b, slice) = if metadata.swapped {
                let end = pos_b + length;
                if data_b.len() <= end {
                    return (context, pos_a, end)
                }
                (pos_a, end, &data_b[pos_b..end])
            } else {
                let end = pos_a + length;
                if data_a.len() <= end {
                    return (context, end, pos_b)
                }
                (end, pos_b, &data_a[pos_a..end])
            };
            let packet = NetworkPacket {
                source: metadata.source,
                destination: metadata.destination,
                number: metadata.number,
                payload: slice.to_vec(),
            };
            match context.add(Some(&id), &packet) {
                Poll::Ready(_) => (),
                Poll::Pending => (),
            }
            context.visualize(&packet, &BinaryChunkStorage::new(), output);
            (context, end_a, end_b)
        });
}

fn encrypt_conversation(
    descriptors: &[PacketDescriptor],
    data: &[u8],
    initiator_chunk_descriptors: &[ChunkDescriptor],
    responder_chunk_descriptors: &[ChunkDescriptor],
    chunk_a: &BinaryChunk,
    chunk_b: &BinaryChunk,
    id: &Identity,
) -> (Vec<u8>, Vec<u8>) {
    let decipher = id.decipher(chunk_a.raw(), chunk_b.raw()).ok().unwrap();

    let mut encrypted_a = chunk_a.raw().clone();
    let mut encrypted_b = chunk_b.raw().clone();

    let mut separated_a = Vec::new();
    let mut separated_b = Vec::new();
    let mut pos = 0;
    for descriptor in descriptors {
        let end = pos + descriptor.length;
        if data.len() <= end {
            break;
        }
        if descriptor.swap {
            separated_b.extend_from_slice(&data[pos..end]);
        } else {
            separated_a.extend_from_slice(&data[pos..end]);
        }
        pos = end;
    }

    pos = 0;
    for (i, c_descriptor) in initiator_chunk_descriptors.iter().enumerate() {
        let end = pos + c_descriptor.length;
        if separated_a.len() <= end {
            break;
        }
        let nonce = NonceAddition::Initiator(i as u64);
        encrypted_a.extend_from_slice((c_descriptor.length as u16 + 16).to_be_bytes().as_ref());
        encrypted_a.append(&mut decipher.encrypt(&separated_a[pos..end], nonce).unwrap());
        pos = end;
    }

    pos = 0;
    for (i, c_descriptor) in responder_chunk_descriptors.iter().enumerate() {
        let end = pos + c_descriptor.length;
        if separated_b.len() <= end {
            break;
        }
        let nonce = NonceAddition::Responder(i as u64);
        encrypted_b.extend_from_slice((c_descriptor.length as u16 + 16).to_be_bytes().as_ref());
        encrypted_b.append(&mut decipher.encrypt(&separated_b[pos..end], nonce).unwrap());
        pos = end;
    }

    (encrypted_a, encrypted_b)
}

#[cfg(test)]
mod tests {
    use super::{simulate_encrypted, PacketDescriptor, ChunkDescriptor, Tree};

    #[test]
    fn basic() {
        let mut output = Tree::default().panic_on_decryption_error();

        let data = [93, 79, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 15, 64, 1, 95, 95, 95, 100, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 161, 160, 160, 160, 160, 160, 160, 153, 95, 95, 95, 95, 95, 95, 95, 95, 95, 93, 79, 0, 0, 0, 0, 0, 0, 0, 188, 188, 188, 188, 4, 0, 64, 1, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 95];
        let chunk_oversize = 18;
        let descriptors = [
            PacketDescriptor::new(chunk_oversize + 15, false).unwrap(),
            PacketDescriptor::new(chunk_oversize + 12, true).unwrap(),
            PacketDescriptor::new(chunk_oversize + 25, false).unwrap(),
            PacketDescriptor::new(chunk_oversize + 18, true).unwrap(),
        ];
        let ic = [
            ChunkDescriptor::new(13).unwrap(),
            ChunkDescriptor::new(12).unwrap(),
            ChunkDescriptor::new(15).unwrap(),
        ];
        let rc = [
            ChunkDescriptor::new(8).unwrap(),
            ChunkDescriptor::new(12).unwrap(),
            ChunkDescriptor::new(10).unwrap(),
        ];
        simulate_encrypted(descriptors.as_ref(), ic.as_ref(), rc.as_ref(), data.as_ref(), &mut output);
    }
}
