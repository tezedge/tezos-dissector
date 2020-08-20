use tezos_messages::p2p::binary_message::{BinaryChunk, CONTENT_LENGTH_FIELD_BYTES};
use std::{collections::BTreeMap, convert::TryFrom, task::Poll, ops::Range};

// TODO: cyclic buffer length 0x10000 if allocations significantly affect performance
pub struct ChunkBuffer {
    buffer: Vec<u8>,
    frames_description: BTreeMap<FrameIndex, Range<FrameCoordinate>>,
    temp: ChunkBufferTemporal,
}

struct ChunkBufferTemporal {
    last_frame: Option<FrameIndex>,
    chunks_counter: u64,
}

impl ChunkBufferTemporal {
    fn new() -> Self {
        ChunkBufferTemporal {
            last_frame: None,
            chunks_counter: 0,
        }
    }
}

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq)]
struct FrameIndex(u64);

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct FrameCoordinate {
    /// addition to the nonce
    pub index: u64,
    /// offset in the chunk where this frame begins
    pub offset: u16,
}

impl ChunkBuffer {
    pub fn new() -> Self {
        ChunkBuffer {
            buffer: Vec::new(),
            frames_description: BTreeMap::new(),
            temp: ChunkBufferTemporal::new(),
        }
    }

    pub fn consume(&mut self, frame_index: u64, payload: &[u8]) -> Poll<(u64, Vec<BinaryChunk>)> {
        let nonce = self.temp.chunks_counter;

        let frame_start = match &self.temp.last_frame {
            &None => FrameCoordinate {
                index: self.temp.chunks_counter,
                offset: self.buffer.len() as _,
            },
            &Some(ref f) => self.frames_description[f].end.clone(),
        };
        self.temp.last_frame = Some(FrameIndex(frame_index));

        self.buffer.extend_from_slice(payload);

        let mut v = Vec::new();
        loop {
            match self.length() {
                Poll::Pending => {
                    let frame_end = FrameCoordinate {
                        index: self.temp.chunks_counter,
                        offset: self.buffer.len() as u16,
                    };
                    self.frames_description
                        .insert(FrameIndex(frame_index), frame_start..frame_end);
                    break if v.is_empty() {
                        Poll::Pending
                    } else {
                        Poll::Ready((nonce, v))
                    };
                },
                Poll::Ready(length) => {
                    if self.buffer.len() < length {
                        let frame_end = FrameCoordinate {
                            index: self.temp.chunks_counter,
                            offset: self.buffer.len() as u16,
                        };
                        self.frames_description
                            .insert(FrameIndex(frame_index), frame_start..frame_end);
                        break {
                            if v.is_empty() {
                                Poll::Pending
                            } else {
                                Poll::Ready((nonce, v))
                            }
                        };
                    } else {
                        let buffer = std::mem::replace(&mut self.buffer, Vec::new());
                        let (chunk_data, reminder) = buffer.split_at(length);
                        self.temp.chunks_counter += 1;
                        v.push(
                            BinaryChunk::try_from(chunk_data.to_owned())
                                .map_err(|e| {
                                    log::error!("{}", e);
                                })
                                .unwrap(),
                        );
                        self.buffer = reminder.to_owned();
                    }
                },
            }
        }
    }

    pub fn frames_description(&self, frame_index: u64) -> Option<Range<FrameCoordinate>> {
        self.frames_description
            .get(&FrameIndex(frame_index))
            .cloned()
    }

    fn length(&self) -> Poll<usize> {
        use bytes::Buf;

        if self.buffer.len() < CONTENT_LENGTH_FIELD_BYTES {
            Poll::Pending
        } else {
            let length = (&self.buffer[..CONTENT_LENGTH_FIELD_BYTES]).get_u16() as usize;
            Poll::Ready(length + CONTENT_LENGTH_FIELD_BYTES)
        }
    }
}
