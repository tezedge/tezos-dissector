use tezos_messages::p2p::binary_message::{BinaryChunk, BinaryChunkError, CONTENT_LENGTH_FIELD_BYTES};
use std::{
    collections::BTreeMap,
    convert::TryFrom,
    task::Poll,
};

pub struct ChunkBuffer {
    first_frame: u64,
    chunk_index: u64,
    frames_count: u16,
    buffer: Vec<u8>,
    chunk_description: BTreeMap<FrameIndex, ChunkIndex>,
}

#[derive(Ord, PartialOrd, Eq, PartialEq)]
struct FrameIndex(u64);

#[derive(Clone)]
pub struct ChunkIndex {
    // addition to the nonce
    pub index: u64,
    // how many frames
    pub frames_count: u16,
    // offset in the chunk where this frame begins
    pub offset: u16,
}

#[derive(Debug)]
pub struct ChunkBufferError {
    pub first_frame: u64,
    pub overflow_at_frame: u64,
    pub required_length: u16,
}

impl ChunkBuffer {
    pub fn new() -> Self {
        ChunkBuffer {
            first_frame: 0,
            chunk_index: 0,
            frames_count: 0,
            buffer: Vec::new(),
            chunk_description: BTreeMap::new(),
        }
    }

    pub fn chunk_index(&self, frame_index: u64) -> Option<ChunkIndex> {
        self.chunk_description.get(&FrameIndex(frame_index)).cloned()
    }

    pub fn last_chunks_index(&self) -> u64 {
        self.chunk_index
    }

    pub fn consume(
        &mut self,
        frame_index: u64,
        payload: &[u8],
    ) -> Poll<Result<Vec<BinaryChunk>, ChunkBufferError>> {
        let mut p = payload;
        let mut v = Vec::new();
        loop {
            match self.consume_one(frame_index, p) {
                Poll::Ready(Ok(c)) => v.push(c),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    return if v.is_empty() {
                        Poll::Pending
                    } else {
                        Poll::Ready(Ok(v))
                    }
                },
            }
            p = &[];
        }
    }

    pub fn consume_one(
        &mut self,
        frame_index: u64,
        payload: &[u8],
    ) -> Poll<Result<BinaryChunk, ChunkBufferError>> {
        use bytes::Buf;

        if self.first_frame == 0 {
            self.first_frame = frame_index;
        }
        let chunk_index = ChunkIndex {
            index: self.chunk_index,
            frames_count: self.frames_count + 1,
            offset: self.buffer.len() as _,
        };
        self.buffer.extend_from_slice(payload);
        // Hope, rust backend is smart enough to optimize it
        // and does not do allocation in case of error
        match BinaryChunk::try_from(self.buffer.clone()) {
            Ok(chunk) => {
                self.chunk_description.insert(FrameIndex(frame_index), chunk_index);
                self.first_frame = 0;
                self.chunk_index += 1;
                self.frames_count = 0;
                self.buffer.clear();
                Poll::Ready(Ok(chunk))
            },
            Err(BinaryChunkError::IncorrectSizeInformation { 
                expected,
                actual,
            }) => {
                self.chunk_description.insert(FrameIndex(frame_index), chunk_index);
                if actual < expected {
                    self.frames_count += 1;
                    Poll::Pending
                } else {
                    self.first_frame = 0;
                    self.chunk_index += 1;
                    self.frames_count = 0;
                    let mid = expected + CONTENT_LENGTH_FIELD_BYTES;
                    let (first, second) = self.buffer.split_at(mid);
                    let chunk = BinaryChunk::try_from(first.to_vec()).unwrap();
                    self.buffer = second.to_vec();
                    Poll::Ready(Ok(chunk))
                }
            },
            Err(BinaryChunkError::MissingSizeInformation) => Poll::Pending, // TODO: recheck
            Err(BinaryChunkError::OverflowError) => {
                let e = ChunkBufferError {
                    first_frame: self.first_frame,
                    overflow_at_frame: frame_index,
                    required_length: (&self.buffer[0..2]).get_u16(),
                };
                self.first_frame = 0;
                self.frames_count = 0;
                self.buffer.clear();
                Poll::Ready(Err(e))
            },
        }
    }
}
