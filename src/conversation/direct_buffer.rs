use std::{
    ops::Range,
    collections::BTreeMap,
};
use bytes::Buf;

pub struct DirectBuffer {
    data: Vec<u8>,
    chunks: Vec<Range<usize>>,
    packets: BTreeMap<u64, Range<usize>>,
}

impl DirectBuffer {
    pub fn new() -> Self {
        DirectBuffer {
            data: Vec::new(),
            chunks: Vec::new(),
            packets: BTreeMap::new(),
        }
    }

    pub fn consume(&mut self, payload: &[u8], frame_index: u64) {
        let start = self.data.len();
        self.data.extend_from_slice(payload);
        let end = self.data.len();
        self.packets.insert(frame_index, start..end);
        let range = self.chunks.last().unwrap_or(&(0..0));

        let mut position = range.end;
        let mut new_chunks = Vec::new();
        loop {
            if position >= end {
                break;
            } else {
                if position + 2 < end {
                    let length = (&self.data[position..(position + 2)]).get_u16() as usize;
                    let this_end = position + 2 + length;
                    new_chunks.push(position..this_end);
                    position = this_end;
                } else {
                    break;
                }
            }
        }

        self.chunks.extend_from_slice(new_chunks.as_slice());
    }

    pub fn data(&self) -> &[u8] {
        self.data.as_ref()
    }

    pub fn data_mut(&mut self) -> &mut [u8] {
        self.data.as_mut()
    }

    pub fn chunks(&self) -> &[Range<usize>] {
        self.chunks.as_ref()
    }

    pub fn packet(&self, index: u64) -> Range<usize> {
        self.packets.get(&index).unwrap().clone()
    }
}
