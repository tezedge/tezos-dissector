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

pub struct ChunkedData<'a, C>
where
    C: HasBodyRange,
{
    data: &'a [u8],
    chunks: &'a [C],
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

impl<'a, C> ChunkedData<'a, C>
where
    C: HasBodyRange,
{
    pub fn new(data: &'a [u8], chunks: &'a [C]) -> Self {
        ChunkedData { data, chunks }
    }

    fn limit(&self, limit: usize) -> Self {
        // TODO: account chunks
        ChunkedData {
            data: &self.data[..limit],
            chunks: self.chunks,
        }
    }

    // try to cut `length` bytes, update offset
    fn cut<F, T>(
        &self,
        offset: &mut ChunkedDataOffset,
        length: usize,
        f: F,
    ) -> Result<T, DecodingError>
    where
        F: FnOnce(&mut dyn Buf) -> T,
    {
        // TODO:
        self.chunks
            .get(offset.chunks_offset)
            .and_then(|info| {
                let range = info.body();
                assert!(range.contains(&offset.data_offset));
                let remaining = offset.data_offset..range.end;
                if remaining.len() < length {
                    None
                } else if remaining.len() == length {
                    offset.chunks_offset += 1;
                    offset.data_offset = self
                        .chunks
                        .get(offset.chunks_offset)
                        .map(|s| s.body().start)
                        .unwrap_or(0);
                    Some(f(&mut &self.data[remaining]))
                } else {
                    let end = remaining.start + length;
                    offset.data_offset += length;
                    Some(f(&mut &self.data[remaining.start..end]))
                }
            })
            .ok_or(DecodingError::NotEnoughData)
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
                let f = |data: &mut dyn Buf| String::from_utf8((data.bytes()).to_owned()).ok();
                let string = self.cut(offset, length, f)?;
                item.end = offset.data_offset;
                if let Some(s) = string {
                    node.add(base, intersect(space, item), TreeLeaf::Display(s));
                }
            },
            &Encoding::Bytes => {
                let item = offset.following(self.data.len() - offset.data_offset);
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
                let length = self.cut(offset, item.len(), |b| b.get_u32())? as usize;
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
                let l = self.data.len() - offset.data_offset;
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
                let l = self.data.len() - offset.data_offset;
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
            t => unimplemented!("{:?}", t),
        }
    }
}
