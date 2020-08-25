// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

use tezos_encoding::encoding::{Encoding, SchemaType};
use wireshark_epan_adapter::dissector::{Tree, TreeLeaf};
use bytes::Buf;
use chrono::NaiveDateTime;
use std::ops::Range;
use failure::Fail;
use crate::range_tool::intersect;

pub trait HasBodyRange {
    fn body(&self) -> Range<usize>;
}

#[derive(Debug, Fail)]
pub enum DecodingError {
    #[fail(display = "Not enough bytes")]
    NotEnoughData,
    #[fail(display = "Tag size not supported")]
    TagSizeNotSupported,
    #[fail(display = "Tag not found")]
    TagNotFound,
}

#[derive(Debug)]
pub struct ChunkedData<'a, C>
where
    C: HasBodyRange,
{
    data: &'a [u8],
    chunks: &'a [C],
}

#[derive(Clone, Debug)]
pub struct ChunkedDataOffset {
    pub data_offset: usize,
    pub chunks_offset: usize,
}

impl ChunkedDataOffset {
    pub fn following(&self, length: usize) -> Range<usize> {
        self.data_offset..(self.data_offset + length)
    }
}

impl<'a, C> ChunkedData<'a, C>
where
    C: HasBodyRange,
{
    pub fn new(data: &'a [u8], chunks: &'a [C]) -> Self {
        ChunkedData { data, chunks }
    }

    fn limit(&self, offset: &ChunkedDataOffset, limit: usize) -> Result<Self, DecodingError> {
        let r = |i| -> Range<usize> {
            self.chunks.get(offset.chunks_offset + i)
                .map(|info: &C| {
                    let range = info.body();
                    let o = offset.data_offset;
                    let l = self.data.len();
                    usize::max(o, range.start)..usize::min(range.end, l)
                })
                .unwrap_or(0..0)
        };
        let mut limit = limit;
        let mut i = 0;
        let end = loop {
            if limit <= r(i).len() {
                break r(i).start + limit;
            } else if r(i).len() == 0 {
                Err(DecodingError::NotEnoughData)?;
            } else {
                limit -= r(i).len();
                i += 1;
            }
        };
        Ok(ChunkedData {
            data: &self.data[..end],
            chunks: self.chunks,
        })
    }

    // try to cut `length` bytes, update offset
    // TODO: simplify it
    fn cut<F, T>(
        &self,
        offset: &mut ChunkedDataOffset,
        length: usize,
        f: F,
    ) -> Result<T, DecodingError>
    where
        F: FnOnce(&mut dyn Buf) -> T,
    {
        let range = self.chunks[offset.chunks_offset].body();
        assert!(
            range.contains(&offset.data_offset)
                || (offset.data_offset == range.end && length == 0)
        );
        let remaining = offset.data_offset..usize::min(range.end, self.data.len());
        if remaining.len() >= length {
            let end = remaining.start + length;
            offset.data_offset += length;
            Ok(f(&mut &self.data[remaining.start..end]))
        } else {
            let mut v = Vec::with_capacity(length);
            offset.data_offset += remaining.len();
            let mut length = length - remaining.len();
            v.extend_from_slice(&self.data[remaining]);
            loop {
                offset.chunks_offset += 1;
                if self.chunks.len() == offset.chunks_offset {
                    if length == 0 {
                        break;
                    } else {
                        Err(DecodingError::NotEnoughData)?;
                    }
                } else {
                    let range = self.chunks[offset.chunks_offset].body();
                    let remaining = range.start..usize::min(range.end, self.data.len());
                    if remaining.len() >= length {
                        offset.data_offset = self.chunks[offset.chunks_offset].body().start + length;
                        if length > 0 {
                            let end = remaining.start + length;
                            length = 0;
                            v.extend_from_slice(&self.data[remaining.start..end]);
                        }
                        break;
                    } else {
                        offset.data_offset += remaining.len();
                        length -= remaining.len();
                        v.extend_from_slice(&self.data[remaining]);
                    }
                }
            }
            assert_eq!(length, 0);
            Ok(f(&mut v.as_slice()))
        }
    }

    fn empty(&self, offset: &ChunkedDataOffset) -> bool {
        self.available(offset) == 0
    }

    fn available(&self, offset: &ChunkedDataOffset) -> usize {
        let end = usize::min(
            self.chunks[offset.chunks_offset].body().end,
            self.data.len(),
        );
        let available = end - offset.data_offset;
        // if it is the first message it always goes in the single chunk
        if offset.chunks_offset != 0 && self.chunks.len() - 1 > offset.chunks_offset {
            self.chunks[(offset.chunks_offset + 1)..]
                .iter()
                .fold(available, |a, c| {
                    if self.data.len() >= c.body().end {
                        a + c.body().len()
                    } else if self.data.len() > c.body().start {
                        a + (self.data.len() - c.body().start)
                    } else {
                        a
                    }
                })
        } else {
            available
        }
    }

    pub fn show(
        &self,
        offset: &mut ChunkedDataOffset,
        encoding: &Encoding,
        space: &Range<usize>,
        base: &str,
        node: &mut Tree,
    ) -> Result<(), DecodingError> {
        match encoding {
            &Encoding::Unit => (),
            &Encoding::Int8 => {
                let item = offset.following(1);
                let value = self.cut(offset, item.len(), |b| b.get_i8())?;
                node.add(base, intersect(space, item), TreeLeaf::dec(value as _));
            },
            &Encoding::Uint8 => {
                let item = offset.following(1);
                let value = self.cut(offset, item.len(), |b| b.get_u8())?;
                node.add(base, intersect(space, item), TreeLeaf::dec(value as _));
            },
            &Encoding::Int16 => {
                let item = offset.following(2);
                let value = self.cut(offset, item.len(), |b| b.get_i16())?;
                node.add(base, intersect(space, item), TreeLeaf::dec(value as _));
            },
            &Encoding::Uint16 => {
                let item = offset.following(2);
                let value = self.cut(offset, item.len(), |b| b.get_u16())?;
                node.add(base, intersect(space, item), TreeLeaf::dec(value as _));
            },
            &Encoding::Int31 | &Encoding::Int32 => {
                let item = offset.following(4);
                let value = self.cut(offset, item.len(), |b| b.get_i32())?;
                node.add(base, intersect(space, item), TreeLeaf::dec(value as _));
            },
            &Encoding::Uint32 => {
                let item = offset.following(4);
                let value = self.cut(offset, item.len(), |b| b.get_u32())?;
                node.add(base, intersect(space, item), TreeLeaf::dec(value.into()));
            },
            &Encoding::Int64 => {
                let item = offset.following(8);
                let value = self.cut(offset, item.len(), |b| b.get_i64())?;
                node.add(base, intersect(space, item), TreeLeaf::dec(value as _));
            },
            &Encoding::RangedInt => unimplemented!(),
            &Encoding::Z | &Encoding::Mutez => unimplemented!(),
            &Encoding::Float => {
                let item = offset.following(8);
                let value = self.cut(offset, item.len(), |b| b.get_f64())?;
                node.add(base, intersect(space, item), TreeLeaf::float(value as _));
            },
            &Encoding::RangedFloat => unimplemented!(),
            &Encoding::Bool => {
                let item = offset.following(1);
                let value = self.cut(offset, item.len(), |d| d.get_u8() == 0xff)?;
                node.add(base, intersect(space, item), TreeLeaf::Display(value));
            },
            &Encoding::String => {
                let mut item = offset.following(4);
                let length = self.cut(offset, item.len(), |b| b.get_u32())? as usize;
                let f = |b: &mut dyn Buf| String::from_utf8((b.bytes()).to_owned()).ok();
                let string = self.cut(offset, length, f)?;
                item.end = offset.data_offset;
                if let Some(s) = string {
                    node.add(base, intersect(space, item), TreeLeaf::Display(s));
                }
            },
            &Encoding::Bytes => {
                let item = offset.following(self.available(offset));
                let string = self.cut(offset, item.len(), |d| hex::encode(d.bytes()))?;
                node.add(base, intersect(space, item), TreeLeaf::Display(string));
            },
            &Encoding::Tags(ref tag_size, ref tag_map) => {
                let id = match tag_size {
                    &1 => self.cut(offset, 1, |b| b.get_u8())? as u16,
                    &2 => self.cut(offset, 2, |b| b.get_u16())?,
                    _ => Err(DecodingError::TagSizeNotSupported)?,
                };
                if let Some(tag) = tag_map.find_by_id(id) {
                    let encoding = tag.get_encoding();
                    let mut temp_offset = offset.clone();
                    let size = self.estimate_size(&mut temp_offset, encoding)?;
                    let item = offset.following(size);
                    let range = intersect(space, item);
                    let mut sub_node = node.add(base, range, TreeLeaf::nothing()).subtree();
                    let variant = tag.get_variant();
                    self.show(offset, encoding, space, variant, &mut sub_node)?;
                } else {
                    Err(DecodingError::TagNotFound)?
                }
            },
            &Encoding::List(ref encoding) => {
                if let &Encoding::Uint8 = encoding.as_ref() {
                    self.show(offset, &Encoding::Bytes, space, base, node)?;
                } else {
                    while !self.empty(offset) {
                        self.show(offset, encoding, space, base, node)?;
                    }
                }
            },
            &Encoding::Enum => unimplemented!(),
            &Encoding::Option(ref encoding) => {
                let _ = encoding;
                unimplemented!()
            },
            &Encoding::OptionalField(ref encoding) => {
                let _ = encoding;
                unimplemented!()
            },
            &Encoding::Obj(ref fields) => {
                let mut temp_offset = offset.clone();
                let size = self.estimate_size(&mut temp_offset, &Encoding::Obj(fields.clone()))?;
                let item = offset.following(size);
                let range = intersect(space, item);
                let mut sub_node = node.add(base, range, TreeLeaf::nothing()).subtree();
                for field in fields {
                    self.show(
                        offset,
                        field.get_encoding(),
                        space,
                        field.get_name(),
                        &mut sub_node,
                    )?;
                }
            },
            &Encoding::Tup(ref encodings) => {
                let _ = encodings;
                unimplemented!()
            },
            &Encoding::Dynamic(ref encoding) => {
                // TODO: use item, highlight the length
                let item = offset.following(4);
                let length = self.cut(offset, item.len(), |b| b.get_u32())? as usize;
                if length <= self.available(offset) {
                    self.limit(offset, length)?
                        .show(offset, encoding, space, base, node)?;
                } else {
                    // report error
                }
            },
            &Encoding::Sized(ref size, ref encoding) => {
                self.limit(offset, size.clone())?
                    .show(offset, encoding, space, base, node)?;
            },
            &Encoding::Greedy(ref encoding) => {
                let _ = encoding;
                unimplemented!()
            },
            &Encoding::Hash(ref hash_type) => {
                let item = offset.following(hash_type.size());
                let string = self.cut(offset, item.len(), |d| hex::encode(d.bytes()))?;
                node.add(base, intersect(space, item), TreeLeaf::Display(string));
            },
            &Encoding::Split(ref f) => {
                self.show(offset, &f(SchemaType::Binary), space, base, node)?;
            },
            &Encoding::Timestamp => {
                let item = offset.following(8);
                let value = self.cut(offset, item.len(), |b| b.get_i64())?;
                let time = NaiveDateTime::from_timestamp(value, 0);
                node.add(base, intersect(space, item), TreeLeaf::Display(time));
            },
            &Encoding::Lazy(ref f) => {
                self.show(offset, &f(), space, base, node)?;
            },
        };
        Ok(())
    }

    pub fn estimate_size(
        &self,
        offset: &mut ChunkedDataOffset,
        encoding: &Encoding,
    ) -> Result<usize, DecodingError> {
        match encoding {
            &Encoding::Unit => Ok(0),
            &Encoding::Int8 | &Encoding::Uint8 => self.cut(offset, 1, |a| a.bytes().len()),
            &Encoding::Int16 | &Encoding::Uint16 => self.cut(offset, 2, |a| a.bytes().len()),
            &Encoding::Int31 | &Encoding::Int32 | &Encoding::Uint32 => {
                self.cut(offset, 4, |a| a.bytes().len())
            },
            &Encoding::Int64 => self.cut(offset, 8, |a| a.bytes().len()),
            &Encoding::RangedInt => unimplemented!(),
            &Encoding::Z | &Encoding::Mutez => unimplemented!(),
            &Encoding::Float => self.cut(offset, 8, |a| a.bytes().len()),
            &Encoding::RangedFloat => unimplemented!(),
            &Encoding::Bool => self.cut(offset, 1, |a| a.bytes().len()),
            &Encoding::String => {
                let l = self.cut(offset, 4, |b| b.get_u32())? as usize;
                self.cut(offset, l, |a| a.bytes().len() + 4)
            },
            &Encoding::Bytes => {
                let l = self.available(offset);
                self.cut(offset, l, |a| a.bytes().len())
            },
            &Encoding::Tags(ref tag_size, ref tag_map) => {
                let id = match tag_size {
                    &1 => self.cut(offset, 1, |b| b.get_u8())? as u16,
                    &2 => self.cut(offset, 2, |b| b.get_u16())?,
                    _ => {
                        log::warn!("unsupported tag size");
                        Err(DecodingError::TagSizeNotSupported)?
                    },
                };
                if let Some(tag) = tag_map.find_by_id(id) {
                    self.estimate_size(offset, tag.get_encoding())
                        .map(|s| s + tag_size.clone())
                } else {
                    Err(DecodingError::TagNotFound)
                }
            },
            &Encoding::List(_) => {
                let l = self.available(offset);
                self.cut(offset, l, |a| a.bytes().len())
            },
            &Encoding::Obj(ref fields) => fields
                .into_iter()
                .map(|f| self.estimate_size(offset, f.get_encoding()))
                .try_fold(0, |sum, size_at_field| size_at_field.map(|s| s + sum)),
            &Encoding::Dynamic(_) => {
                let l = self.cut(offset, 4, |b| b.get_u32())? as usize;
                self.cut(offset, l, |a| a.bytes().len() + 4)
            },
            &Encoding::Sized(ref size, _) => self.cut(offset, size.clone(), |a| a.bytes().len()),
            &Encoding::Hash(ref hash_type) => {
                self.cut(offset, hash_type.size(), |a| a.bytes().len())
            },
            &Encoding::Timestamp => self.cut(offset, 8, |a| a.bytes().len()),
            &Encoding::Split(ref f) => self.estimate_size(offset, &f(SchemaType::Binary)),
            &Encoding::Lazy(ref f) => self.estimate_size(offset, &f()),
            t => unimplemented!("{:?}", t),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Range;
    use super::{ChunkedData, ChunkedDataOffset, HasBodyRange};

    impl HasBodyRange for Range<usize> {
        fn body(&self) -> Range<usize> {
            self.clone()
        }
    }

    fn with_test_data<F>(f: F)
    where
        F: FnOnce(ChunkedData<Range<usize>>),
    {
        let data = {
            let mut v = Vec::new();
            v.resize(128, 'x' as u8);
            v
        };
        let (data, chunks, _) = [
            ['a' as u8; 12].as_ref(),
            ['b' as u8; 16].as_ref(),
            ['c' as u8; 24].as_ref(),
            ['d' as u8; 8].as_ref(),
        ]
            .iter()
            .fold((data, Vec::new(), 0), |(mut data, mut chunks, mut start), c| {
                let end = start + c.len();
                data[start..end].clone_from_slice(*c);
                chunks.push(start..end);
                start = end + 4;
                (data, chunks, start)
            });

        f(ChunkedData {
            data: data.as_ref(),
            chunks: chunks.as_ref(),
        })
    }

    #[test]
    fn simple_cut() {
        let mut offset = ChunkedDataOffset {
            chunks_offset: 0,
            data_offset: 0,
        };

        with_test_data(|data| {
            let cut = data
                .cut(&mut offset, 25, |b| String::from_utf8(b.to_bytes().to_vec()).unwrap())
                .unwrap();
            assert_eq!(cut, "aaaaaaaaaaaabbbbbbbbbbbbb");
            let cut = data
                .cut(&mut offset, 35, |b| String::from_utf8(b.to_bytes().to_vec()).unwrap())
                .unwrap();
            assert_eq!(cut, "bbbccccccccccccccccccccccccdddddddd");
        });
    }
}
