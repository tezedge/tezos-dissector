// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

use tezos_encoding::encoding::{Encoding, SchemaType};
use wireshark_epan_adapter::dissector::{Tree, TreeLeaf};
use bytes::Buf;
use chrono::NaiveDateTime;
use std::ops::Range;

pub struct ChunkedData<'a> {
    data: &'a [u8],
    chunks: &'a [Range<usize>],
}

#[derive(Clone)]
pub struct ChunkedDataOffset {
    pub data_offset: usize,
    pub chunks_offset: usize,
}

impl ChunkedDataOffset {
    pub fn following(&self, length: usize) -> Range<usize> {
        self.data_offset..(self.data_offset + length)
    }
}

impl<'a> ChunkedData<'a> {
    pub fn new(data: &'a [u8], chunks: &'a [Range<usize>]) -> Self {
        ChunkedData { data, chunks }
    }

    pub fn limit(&self, limit: usize) -> Self {
        // TODO: account chunks
        ChunkedData {
            data: &self.data[..limit],
            chunks: self.chunks,
        }
    }

    // try to cut `length` bytes, update offset
    pub fn cut<F, T>(&self, offset: &mut ChunkedDataOffset, length: usize, f: F) -> Result<T, ()>
    where
        F: FnOnce(&mut &'a [u8]) -> T,
    {
        self.chunks
            .get(offset.chunks_offset)
            .and_then(|range| {
                assert!(range.contains(&offset.data_offset));
                let remaining = offset.data_offset..range.end;
                if remaining.len() < length {
                    None
                } else if remaining.len() == length {
                    offset.chunks_offset += 1;
                    offset.data_offset = self
                        .chunks
                        .get(offset.chunks_offset)
                        .map(|s| s.start)
                        .unwrap_or(0);
                    Some(f(&mut &self.data[remaining]))
                } else {
                    let end = remaining.start + length;
                    offset.data_offset += length;
                    Some(f(&mut &self.data[remaining.start..end]))
                }
            })
            .ok_or(())
    }

    pub fn show(
        &self,
        offset: &mut ChunkedDataOffset,
        encoding: &Encoding,
        space: &Range<usize>,
        base: &str,
        node: &mut Tree,
    ) -> Result<(), ()> {
        fn intersect(space: &Range<usize>, item: Range<usize>) -> Range<usize> {
            if item.end <= space.start {
                0..0
            } else if item.start >= space.end {
                space.len()..space.len()
            } else {
                let start = usize::max(space.start, item.start) - space.start;
                let end = usize::min(space.end, item.end) - space.start;
                start..end
            }
        }

        match encoding {
            &Encoding::Unit => (),
            &Encoding::Int8 => {
                let item = offset.following(1);
                let value = self.cut(offset, item.len(), Buf::get_i8)?;
                node.add(base, intersect(space, item), TreeLeaf::dec(value as _));
            },
            &Encoding::Uint8 => {
                let item = offset.following(1);
                let value = self.cut(offset, item.len(), Buf::get_u8)?;
                node.add(base, intersect(space, item), TreeLeaf::dec(value as _));
            },
            &Encoding::Int16 => {
                let item = offset.following(2);
                let value = self.cut(offset, item.len(), Buf::get_i16)?;
                node.add(base, intersect(space, item), TreeLeaf::dec(value as _));
            },
            &Encoding::Uint16 => {
                let item = offset.following(2);
                let value = self.cut(offset, item.len(), Buf::get_u16)?;
                node.add(base, intersect(space, item), TreeLeaf::dec(value as _));
            },
            &Encoding::Int31 | &Encoding::Int32 => {
                let item = offset.following(4);
                let value = self.cut(offset, item.len(), Buf::get_i32)?;
                node.add(base, intersect(space, item), TreeLeaf::dec(value as _));
            },
            &Encoding::Uint32 => {
                let item = offset.following(4);
                let value = self.cut(offset, item.len(), Buf::get_u32)?;
                node.add(base, intersect(space, item), TreeLeaf::dec(value.into()));
            },
            &Encoding::Int64 => {
                let item = offset.following(8);
                let value = self.cut(offset, item.len(), Buf::get_i64)?;
                node.add(base, intersect(space, item), TreeLeaf::dec(value as _));
            },
            &Encoding::RangedInt => unimplemented!(),
            &Encoding::Z | &Encoding::Mutez => unimplemented!(),
            &Encoding::Float => {
                let item = offset.following(8);
                let value = self.cut(offset, item.len(), Buf::get_f64)?;
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
                let length = self.cut(offset, item.len(), Buf::get_u32)? as usize;
                let f = |data: &mut &[u8]| String::from_utf8((*data).to_owned()).ok();
                let string = self.cut(offset, length, f)?;
                item.end = offset.data_offset;
                if let Some(s) = string {
                    node.add(base, intersect(space, item), TreeLeaf::Display(s));
                }
            },
            &Encoding::Bytes => {
                let item = offset.following(self.data.len() - offset.data_offset);
                let string = self.cut(offset, item.len(), |d| hex::encode(*d))?;
                node.add(base, intersect(space, item), TreeLeaf::Display(string));
            },
            &Encoding::Tags(ref tag_size, ref tag_map) => {
                let id = match tag_size {
                    &1 => self.cut(offset, 1, Buf::get_u8)? as u16,
                    &2 => self.cut(offset, 2, Buf::get_u16)?,
                    _ => {
                        log::warn!("unsupported tag size");
                        Err(())?
                    },
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
                }
            },
            &Encoding::List(ref encoding) => {
                while offset.data_offset < self.data.len() {
                    self.show(offset, encoding, space, base, node)?;
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
                let length = self.cut(offset, item.len(), Buf::get_u32)? as usize;
                if offset.data_offset + length <= self.data.len() {
                    self.limit(offset.data_offset + length)
                        .show(offset, encoding, space, base, node)?;
                }
            },
            &Encoding::Sized(ref size, ref encoding) => {
                self.limit(offset.data_offset + size.clone())
                    .show(offset, encoding, space, base, node)?;
            },
            &Encoding::Greedy(ref encoding) => {
                let _ = encoding;
                unimplemented!()
            },
            &Encoding::Hash(ref hash_type) => {
                let item = offset.following(hash_type.size());
                let string = self.cut(offset, item.len(), |d| hex::encode(*d))?;
                node.add(base, intersect(space, item), TreeLeaf::Display(string));
            },
            &Encoding::Split(ref f) => {
                self.show(offset, &f(SchemaType::Binary), space, base, node)?;
            },
            &Encoding::Timestamp => {
                let item = offset.following(8);
                let value = self.cut(offset, item.len(), Buf::get_i64)?;
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
    ) -> Result<usize, ()> {
        match encoding {
            &Encoding::Unit => Ok(0),
            &Encoding::Int8 | &Encoding::Uint8 => self.cut(offset, 1, |a| a.len()),
            &Encoding::Int16 | &Encoding::Uint16 => self.cut(offset, 2, |a| a.len()),
            &Encoding::Int31 | &Encoding::Int32 | &Encoding::Uint32 => {
                self.cut(offset, 4, |a| a.len())
            },
            &Encoding::Int64 => self.cut(offset, 8, |a| a.len()),
            &Encoding::RangedInt => unimplemented!(),
            &Encoding::Z | &Encoding::Mutez => unimplemented!(),
            &Encoding::Float => self.cut(offset, 8, |a| a.len()),
            &Encoding::RangedFloat => unimplemented!(),
            &Encoding::Bool => self.cut(offset, 1, |a| a.len()),
            &Encoding::String => {
                let l = self.cut(offset, 4, Buf::get_u32)? as usize;
                self.cut(offset, l, |a| a.len() + 4)
            },
            &Encoding::Bytes => {
                let l = self.data.len() - offset.data_offset;
                self.cut(offset, l, |a| a.len())
            },
            &Encoding::Tags(ref tag_size, ref tag_map) => {
                let id = match tag_size {
                    &1 => self.cut(offset, 1, Buf::get_u8)? as u16,
                    &2 => self.cut(offset, 2, Buf::get_u16)?,
                    _ => {
                        log::warn!("unsupported tag size");
                        Err(())?
                    },
                };
                if let Some(tag) = tag_map.find_by_id(id) {
                    self.estimate_size(offset, tag.get_encoding()).map(|s| s + tag_size.clone())
                } else {
                    Err(())
                }
            },
            &Encoding::List(_) => {
                let l = self.data.len() - offset.data_offset;
                self.cut(offset, l, |a| a.len())
            },
            &Encoding::Obj(ref fields) => {
                fields.into_iter()
                    .map(|f| self.estimate_size(offset, f.get_encoding()))
                    .try_fold(0, |sum, size_at_field| size_at_field.map(|s| s + sum))
            },
            &Encoding::Dynamic(_) => {
                let l = self.cut(offset, 4, Buf::get_u32)? as usize;
                self.cut(offset, l, |a| a.len() + 4)
            },
            &Encoding::Sized(ref size, _) => self.cut(offset, size.clone(), |a| a.len()),
            &Encoding::Hash(ref hash_type) => self.cut(offset, hash_type.size(), |a| a.len()),
            &Encoding::Timestamp => self.cut(offset, 8, |a| a.len()),
            &Encoding::Split(ref f) => self.estimate_size(offset, &f(SchemaType::Binary)),
            t => unimplemented!("{:?}", t),
        }
    }
}
