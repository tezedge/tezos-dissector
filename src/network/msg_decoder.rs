use crypto::{
    crypto_box::{PrecomputedKey, decrypt},
    nonce::Nonce,
};
use tezos_encoding::{binary_reader::BinaryReaderError};
use tezos_messages::p2p::{
    binary_message::{BinaryChunk, BinaryMessage},
    encoding::peer::PeerMessageResponse,
};
use std::convert::TryFrom;
use bytes::Buf;
//use crate::actors::peer_message::*;
//use crate::storage::{MessageStore, StoreMessage};
use tezos_messages::p2p::encoding::metadata::MetadataMessage;

use super::raw_packet_msg::RawPacketMessage;
use std::fmt;

/// P2P Message decrypter from captured connection messages
pub struct EncryptedMessageDecoder {
    //db: MessageStore,
    precomputed_key: PrecomputedKey,
    remote_nonce: Nonce,
    peer_id: String,
    processing: bool,
    metadata: bool,
    inc_buf: Vec<u8>,
    out_buf: Vec<u8>,
    dec_buf: Vec<u8>,
    input_remaining: usize,
}

/// Types of encrypted messages
pub enum EncryptedMessage {
    /// Metadata describing the node (usually first message received/send, p2p communication start after receiving metadata)
    Metadata(MetadataMessage),
    /// P2P message
    PeerResponse(PeerMessageResponse),
}
impl fmt::Display for EncryptedMessage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            EncryptedMessage::Metadata(ref m) => write!(f, "metadata:{:?}", m),
            EncryptedMessage::PeerResponse(ref p2p) => write!(f, "peerresponse:{:?}", p2p),
        }
    }
}
impl fmt::Debug for EncryptedMessage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl EncryptedMessageDecoder {
    /// Create new message decoder from precomputed key (made from public/private key pair) and nonce
    pub fn new(precomputed_key: PrecomputedKey, remote_nonce: Nonce, peer_id: String) -> Self {
        Self {
            precomputed_key,
            remote_nonce,
            peer_id,
            processing: false,
            metadata: false,
            inc_buf: Default::default(),
            out_buf: Default::default(),
            dec_buf: Default::default(),
            input_remaining: 0,
        }
    }

    /// Process received message, if complete message is received, decypher, deserialize and store it.
    pub fn recv_msg(&mut self, enc: &RawPacketMessage) -> Option<EncryptedMessage> {
        log::info!(
            "recv_msg: raw-len:{}; inc_buf-len:{}; out_buf-len:{}; dec_buf-len:{}",
            enc.payload().len(),
            self.inc_buf.len(),
            self.out_buf.len(),
            self.dec_buf.len()
        );
        if enc.has_payload() {
            self.inc_buf.extend_from_slice(&enc.payload());

            if self.inc_buf.len() > 2 {
                self.try_decrypt()
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Try decrypting buffer containig (hopefully) complete message. Encrypted message is deserialized
    /// IFF all packets from message are received and all correct keys are used to decrypt
    fn try_decrypt(&mut self) -> Option<EncryptedMessage> {
        let len = (&self.inc_buf[0..2]).get_u16() as usize;
        log::info!("try_decrypt: len: {}", len);
        if self.inc_buf[2..].len() >= len {
            let chunk = match BinaryChunk::try_from(self.inc_buf[0..len + 2].to_vec()) {
                Ok(chunk) => chunk,
                Err(e) => {
                    log::error!("Failed to load binary chunk: {}", e);
                    return None;
                },
            };

            self.inc_buf.drain(0..len + 2);
            match decrypt(chunk.content(), &self.nonce_fetch(), &self.precomputed_key) {
                Ok(msg) => {
                    self.nonce_increment();
                    self.try_deserialize(msg)
                },
                Err(e) => {
                    log::error!("Failed to decrypt: {}", e);
                    None
                },
            }
        } else {
            None
        }
    }

    /// Try deserializing deciphered message, this will work IFF encrypted received message
    /// was correctly serialized
    fn try_deserialize(&mut self, mut msg: Vec<u8>) -> Option<EncryptedMessage> {
        if !self.metadata {
            Some(EncryptedMessage::Metadata(
                self.try_deserialize_meta(&mut msg)?,
            ))
        } else {
            Some(EncryptedMessage::PeerResponse(
                self.try_deserialize_p2p(&mut msg)?,
            ))
        }
    }

    /// Try to deserialized metadata message
    fn try_deserialize_meta(&mut self, msg: &mut Vec<u8>) -> Option<MetadataMessage> {
        if self.input_remaining >= msg.len() {
            self.input_remaining -= msg.len();
        } else {
            self.input_remaining = 0;
        }

        self.dec_buf.append(msg);

        if self.input_remaining == 0 {
            loop {
                match MetadataMessage::from_bytes(self.dec_buf.clone()) {
                    Ok(msg) => {
                        self.dec_buf.clear();
                        self.metadata = true;
                        return Some(msg);
                    },
                    Err(BinaryReaderError::Underflow { bytes }) => {
                        self.input_remaining += bytes;
                        return None;
                    },
                    Err(BinaryReaderError::Overflow { bytes }) => {
                        self.dec_buf.drain(self.dec_buf.len() - bytes..);
                    },
                    Err(e) => {
                        log::error!("Failed to deserialize message: {}", e);
                        return None;
                    },
                }
            }
        } else {
            None
        }
    }

    /// Try to deserialized p2p message
    fn try_deserialize_p2p(&mut self, msg: &mut Vec<u8>) -> Option<PeerMessageResponse> {
        if self.input_remaining >= msg.len() {
            self.input_remaining -= msg.len();
        } else {
            self.input_remaining = 0;
        }

        self.dec_buf.append(msg);

        if self.input_remaining == 0 {
            loop {
                match PeerMessageResponse::from_bytes(self.dec_buf.clone()) {
                    Ok(msg) => {
                        self.dec_buf.clear();
                        return if msg.messages().len() == 0 {
                            None
                        } else {
                            Some(msg)
                        };
                    },
                    Err(BinaryReaderError::Underflow { bytes }) => {
                        self.input_remaining += bytes;
                        return None;
                    },
                    Err(BinaryReaderError::Overflow { bytes }) => {
                        self.dec_buf.drain(self.dec_buf.len() - bytes..);
                    },
                    Err(e) => {
                        log::error!("Failed to deserialize p2p message: {}", e);
                        return None;
                    },
                }
            }
        } else {
            None
        }
    }

    #[inline]
    #[allow(dead_code)]
    /// Increment internal nonce after decrypting message
    fn nonce_fetch_increment(&mut self) -> Nonce {
        let incremented = self.remote_nonce.increment();
        std::mem::replace(&mut self.remote_nonce, incremented)
    }

    #[inline]
    fn nonce_fetch(&self) -> Nonce {
        self.remote_nonce.clone()
    }

    #[inline]
    fn nonce_increment(&mut self) {
        self.remote_nonce = self.remote_nonce.increment();
    }

    /// Store decrypted message
    fn store_message(&mut self, msg: PeerMessageResponse) {
        log::trace!("Message received: {:?}", msg);
    }
}
