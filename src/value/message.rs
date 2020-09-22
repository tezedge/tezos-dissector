// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

use tezos_encoding::encoding::{Encoding, SchemaType};
use wireshark_epan_adapter::dissector::{TreePresenter, TreeLeaf};
use chrono::NaiveDateTime;
use std::ops::Range;
use bit_vec::BitVec;
use crypto::hash::HashType;
use crate::range_tool::intersect;
use super::{
    chunked_data::{ChunkedData, ChunkedDataInner, DecodingError},
    HasBodyRange,
};

pub trait TezosReader {
    fn read_z(&mut self) -> Result<String, DecodingError>;
    fn read_mutez(&mut self) -> Result<String, DecodingError>;
    fn read_path(&mut self, v: &mut Vec<String>) -> Result<(), DecodingError>;
}

impl<'a, C> TezosReader for ChunkedDataInner<'a, C>
where
    ChunkedData<'a, C>: Clone,
    C: HasBodyRange,
{
    fn read_z(&mut self) -> Result<String, DecodingError> {
        // read first byte
        let byte = self.get_u8()?;
        let negative = byte & (1 << 6) != 0;
        if byte <= 0x3F {
            let mut num = i32::from(byte);
            if negative {
                num *= -1;
            }
            Ok(format!("{:x}", num))
        } else {
            let mut bits = BitVec::new();
            for bit_idx in 0..6 {
                bits.push(byte & (1 << bit_idx) != 0);
            }

            let mut has_next_byte = true;
            while has_next_byte {
                let byte = self.get_u8()?;
                for bit_idx in 0..7 {
                    bits.push(byte & (1 << bit_idx) != 0)
                }

                has_next_byte = byte & (1 << 7) != 0;
            }

            let bytes = to_byte_vec(&trim_left(&reverse(&bits)));

            let mut str_num = bytes
                .iter()
                .enumerate()
                .map(|(idx, b)| match idx {
                    0 => format!("{:x}", *b),
                    _ => format!("{:02x}", *b),
                })
                .fold(String::new(), |mut str_num, val| {
                    str_num.push_str(&val);
                    str_num
                });
            if negative {
                str_num = String::from("-") + str_num.as_str();
            }

            Ok(str_num)
        }
    }

    fn read_mutez(&mut self) -> Result<String, DecodingError> {
        let mut bits = BitVec::new();

        let mut has_next_byte = true;
        while has_next_byte {
            let byte = self.get_u8()?;
            for bit_idx in 0..7 {
                bits.push(byte & (1 << bit_idx) != 0)
            }

            has_next_byte = byte & (1 << 7) != 0;
        }

        let bytes = to_byte_vec(&trim_left(&reverse(&bits)));

        let str_num = bytes
            .iter()
            .enumerate()
            .map(|(idx, b)| match idx {
                0 => format!("{:x}", *b),
                _ => format!("{:02x}", *b),
            })
            .fold(String::new(), |mut str_num, val| {
                str_num.push_str(&val);
                str_num
            });

        Ok(str_num)
    }

    fn read_path(&mut self, v: &mut Vec<String>) -> Result<(), DecodingError> {
        match self.get_u8()? {
            0x00 => Ok(()),
            0xf0 => {
                self.read_path(v)?;
                let l = HashType::OperationListListHash.size();
                let hash = hex::encode(self.copy_to_vec(l)?);
                v.push(format!("left: {}", hash));
                Ok(())
            },
            0x0f => {
                let l = HashType::OperationListListHash.size();
                let hash = hex::encode(self.copy_to_vec(l)?);
                self.read_path(v)?;
                v.push(format!("right: {}", hash));
                Ok(())
            },
            _ => Err(DecodingError::BadPathTag),
        }
    }
}

pub fn show<'a, C, P>(
    data: &mut ChunkedData<'a, C>,
    space: &Range<usize>,
    encoding: &Encoding,
    base: &str,
    node: &mut P,
) -> Result<(), DecodingError>
where
    C: HasBodyRange + Clone,
    P: TreePresenter,
{
    show_inner(data.inner_mut(), space, encoding, base, node)
}

pub fn show_inner<'a, C, P>(
    data: &mut ChunkedDataInner<'a, C>,
    space: &Range<usize>,
    encoding: &Encoding,
    base: &str,
    node: &mut P,
) -> Result<(), DecodingError>
where
    C: HasBodyRange + Clone,
    P: TreePresenter,
{
    match encoding {
        &Encoding::Unit => (),
        &Encoding::Int8 => {
            let item = data.following(1);
            let value = data.get_i8()?;
            node.add(base, intersect(space, item), TreeLeaf::dec(value as _));
        },
        &Encoding::Uint8 => {
            let item = data.following(1);
            let value = data.get_u8()?;
            node.add(base, intersect(space, item), TreeLeaf::dec(value as _));
        },
        &Encoding::Int16 => {
            let item = data.following(2);
            let value = data.get_i16()?;
            node.add(base, intersect(space, item), TreeLeaf::dec(value as _));
        },
        &Encoding::Uint16 => {
            let item = data.following(2);
            let value = data.get_u16()?;
            node.add(base, intersect(space, item), TreeLeaf::dec(value as _));
        },
        &Encoding::Int31 | &Encoding::Int32 => {
            let item = data.following(4);
            let value = data.get_i32()?;
            node.add(base, intersect(space, item), TreeLeaf::dec(value as _));
        },
        &Encoding::Uint32 => {
            let item = data.following(4);
            let value = data.get_u32()?;
            node.add(base, intersect(space, item), TreeLeaf::dec(value.into()));
        },
        &Encoding::Int64 => {
            let item = data.following(8);
            let value = data.get_i64()?;
            node.add(base, intersect(space, item), TreeLeaf::dec(value as _));
        },
        &Encoding::RangedInt => unimplemented!(),
        &Encoding::Z => {
            let mut item = data.following(0);
            let value = data.read_z()?;
            item.end = data.offset();
            node.add(base, intersect(space, item), TreeLeaf::Display(value));
        },
        &Encoding::Mutez => {
            let mut item = data.following(0);
            let value = data.read_mutez()?;
            item.end = data.offset();
            node.add(base, intersect(space, item), TreeLeaf::Display(value));
        },
        &Encoding::Float => {
            let item = data.following(8);
            let value = data.get_f64()?;
            node.add(base, intersect(space, item), TreeLeaf::float(value as _));
        },
        &Encoding::RangedFloat => unimplemented!(),
        &Encoding::Bool => {
            let item = data.following(1);
            let value = data.get_u8()? == 0xff;
            node.add(base, intersect(space, item), TreeLeaf::Display(value));
        },
        &Encoding::String => {
            let mut item = data.following(4);
            let length = data.get_u32()? as usize;
            let string = String::from_utf8(data.copy_to_vec(length)?).ok();
            item.end = data.offset();
            if let Some(s) = string {
                node.add(base, intersect(space, item), TreeLeaf::Display(s));
            }
        },
        &Encoding::Bytes => {
            let item = data.following(data.remaining());
            let string = hex::encode(data.copy_to_vec(item.len())?);
            node.add(base, intersect(space, item), TreeLeaf::Display(string));
        },
        &Encoding::Tags(ref tag_size, ref tag_map) => {
            let id = match tag_size {
                &1 => data.get_u8()? as u16,
                &2 => data.get_u16()?,
                _ => return Err(DecodingError::TagSizeNotSupported),
            };
            if let Some(tag) = tag_map.find_by_id(id) {
                let encoding = tag.get_encoding();
                let size = estimate_size(data, encoding)?;
                let item = data.following(size);
                let range = intersect(space, item);
                let mut sub_node = node.add(base, range, TreeLeaf::nothing()).subtree();
                let variant = tag.get_variant();
                show_inner(data, space, encoding, variant, &mut sub_node)?;
            } else {
                return Err(DecodingError::TagNotFound);
            }
        },
        &Encoding::List(ref encoding) => {
            if let &Encoding::Uint8 = encoding.as_ref() {
                show_inner(data, space, &Encoding::Bytes, base, node)?;
            } else {
                while data.remaining() != 0 {
                    show_inner(data, space, encoding, base, node)?;
                }
            }
        },
        &Encoding::Enum => show_inner(data, space, &Encoding::Uint32, base, node)?,
        &Encoding::Option(ref encoding) | &Encoding::OptionalField(ref encoding) => {
            match data.get_u8()? {
                0 => (),
                1 => show_inner(data, space, encoding, base, node)?,
                _ => return Err(DecodingError::UnexpectedOptionDiscriminant),
            }
        },
        &Encoding::Obj(ref fields) => {
            if fields.len() == 1 && fields[0].get_name() == "messages" {
                show_inner(data, space, &fields[0].get_encoding(), base, node)?;
            } else {
                let size = estimate_size(data, &Encoding::Obj(fields.clone()))?;
                let item = data.following(size);
                let range = intersect(space, item);
                let mut sub_node = node.add(base, range, TreeLeaf::nothing()).subtree();
                for field in fields {
                    if field.get_name() == "operation_hashes_path" {
                        let mut item = data.following(0);
                        let mut path = Vec::new();
                        data.read_path(&mut path)?;
                        item.end = data.offset();
                        let range = intersect(space, item);
                        let mut p = sub_node
                            .add(field.get_name(), range, TreeLeaf::nothing())
                            .subtree();
                        for component in path.into_iter().rev() {
                            p.add("path_component", 0..0, TreeLeaf::Display(component));
                        }
                    } else {
                        show_inner(
                            data,
                            space,
                            field.get_encoding(),
                            field.get_name(),
                            &mut sub_node,
                        )?;
                    }
                }
            }
        },
        &Encoding::Tup(ref encodings) => {
            let size = estimate_size(data, &Encoding::Tup(encodings.clone()))?;
            let item = data.following(size);
            let range = intersect(space, item);
            let mut sub_node = node.add(base, range, TreeLeaf::nothing()).subtree();
            for (i, encoding) in encodings.iter().enumerate() {
                let n = format!("{}", i);
                show_inner(data, space, encoding, &n, &mut sub_node)?;
            }
        },
        &Encoding::Dynamic(ref encoding) => {
            // TODO: use item, highlight the length
            let _item = data.following(4);
            let length = data.get_u32()? as usize;
            if data.has(length) {
                data.push_limit(length);
                show_inner(data, space, encoding, base, node)?;
                data.pop_limit();
            } else {
                // report error
            }
        },
        &Encoding::Sized(ref size, ref encoding) => {
            data.push_limit(size.clone());
            show_inner(data, space, encoding, base, node)?;
            data.pop_limit();
        },
        &Encoding::Greedy(ref encoding) => {
            show_inner(data, space, encoding, base, node)?;
        },
        &Encoding::Hash(ref hash_type) => {
            let item = data.following(hash_type.size());
            let string = hex::encode(data.copy_to_vec(item.len())?);
            node.add(base, intersect(space, item), TreeLeaf::Display(string));
        },
        &Encoding::Split(ref f) => {
            show_inner(data, space, &f(SchemaType::Binary), base, node)?;
        },
        &Encoding::Timestamp => {
            let item = data.following(8);
            let value = data.get_i64()?;
            let time = NaiveDateTime::from_timestamp(value, 0);
            node.add(base, intersect(space, item), TreeLeaf::Display(time));
        },
        &Encoding::Lazy(ref _f) => {
            panic!("should not happen");
        },
    };
    Ok(())
}

fn estimate_size<'a, C>(
    s: &ChunkedDataInner<'a, C>,
    encoding: &Encoding,
) -> Result<usize, DecodingError>
where
    C: HasBodyRange + Clone,
{
    estimate_size_inner(&mut s.clone(), encoding)
}

// TODO: it is double work, optimize it out
// we should store decoded data and show it only when whole node is collected
fn estimate_size_inner<'a, C>(
    data: &mut ChunkedDataInner<'a, C>,
    encoding: &Encoding,
) -> Result<usize, DecodingError>
where
    C: HasBodyRange + Clone,
{
    match encoding {
        &Encoding::Unit => Ok(0),
        &Encoding::Int8 | &Encoding::Uint8 => data.advance(1),
        &Encoding::Int16 | &Encoding::Uint16 => data.advance(2),
        &Encoding::Int31 | &Encoding::Int32 | &Encoding::Uint32 => data.advance(4),
        &Encoding::Int64 => data.advance(8),
        &Encoding::RangedInt => unimplemented!(),
        &Encoding::Z => {
            let start = data.offset();
            let _ = data.read_z()?;
            Ok(data.offset() - start)
        },
        &Encoding::Mutez => {
            let start = data.offset();
            let _ = data.read_mutez()?;
            Ok(data.offset() - start)
        },
        &Encoding::Float => data.advance(8),
        &Encoding::RangedFloat => unimplemented!(),
        &Encoding::Bool => data.advance(1),
        &Encoding::String => {
            let l = data.get_u32()? as usize;
            data.advance(l)
        },
        &Encoding::Bytes => {
            let l = data.remaining();
            data.advance(l)
        },
        &Encoding::Tags(ref tag_size, ref tag_map) => {
            let id = match tag_size {
                &1 => data.get_u8()? as u16,
                &2 => data.get_u16()?,
                _ => {
                    log::warn!("unsupported tag size");
                    return Err(DecodingError::TagSizeNotSupported);
                },
            };
            if let Some(tag) = tag_map.find_by_id(id) {
                estimate_size_inner(data, tag.get_encoding()).map(|s| s + tag_size.clone())
            } else {
                Err(DecodingError::TagNotFound)
            }
        },
        &Encoding::List(_) => {
            let l = data.remaining();
            data.advance(l)
        },
        &Encoding::Enum => estimate_size_inner(data, &Encoding::Uint32),
        &Encoding::Option(ref encoding) | &Encoding::OptionalField(ref encoding) => {
            match data.get_u8()? {
                0 => Ok(1),
                1 => estimate_size_inner(data, encoding).map(|s| s + 1),
                _ => Err(DecodingError::UnexpectedOptionDiscriminant),
            }
        },
        &Encoding::Tup(ref encodings) => encodings
            .iter()
            .map(|e| estimate_size_inner(data, e))
            .try_fold(0, |sum, size_at| size_at.map(|s| s + sum)),
        &Encoding::Obj(ref fields) => fields
            .iter()
            .map(|f| {
                if f.get_name() == "operation_hashes_path" {
                    let start = data.offset();
                    data.read_path(&mut Vec::new())?;
                    Ok(data.offset() - start)
                } else {
                    estimate_size_inner(data, f.get_encoding())
                }
            })
            .try_fold(0, |sum, size_at_field| size_at_field.map(|s| s + sum)),
        &Encoding::Dynamic(_) => {
            let l = data.get_u32()? as usize;
            data.advance(l).map(|l| l + 4)
        },
        &Encoding::Sized(ref size, _) => data.advance(size.clone()),
        &Encoding::Greedy(_) => {
            let l = data.remaining();
            data.advance(l)
        },
        &Encoding::Hash(ref hash_type) => data.advance(hash_type.size()),
        &Encoding::Timestamp => data.advance(8),
        &Encoding::Split(ref f) => estimate_size_inner(data, &f(SchemaType::Binary)),
        &Encoding::Lazy(ref _f) => panic!("should not happen"),
    }
}

fn reverse(s: &BitVec) -> BitVec {
    let mut reversed = BitVec::new();
    for bit in s.iter().rev() {
        reversed.push(bit)
    }
    reversed
}

fn trim_left(s: &BitVec) -> BitVec {
    let mut trimmed: BitVec = BitVec::new();

    let mut notrim = false;
    for bit in s.iter() {
        if bit {
            trimmed.push(bit);
            notrim = true;
        } else if notrim {
            trimmed.push(bit);
        }
    }
    trimmed
}

fn to_byte_vec(s: &BitVec) -> Vec<u8> {
    let mut bytes = vec![];
    let mut byte = 0;
    let mut offset = 0;
    for (idx_bit, bit) in s.iter().rev().enumerate() {
        let idx_byte = (idx_bit % 8) as u8;
        if bit {
            byte |= 1 << idx_byte;
        } else {
            byte &= !(1 << idx_byte);
        }
        if idx_byte == 7 {
            bytes.push(byte);
            byte = 0;
        }
        offset = idx_byte;
    }
    if offset != 7 {
        bytes.push(byte);
    }
    bytes.reverse();
    bytes
}
