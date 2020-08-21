use tezos_encoding::encoding::Encoding;
use wireshark_epan_adapter::dissector::{Tree, TreeLeaf};
use bytes::Buf;
use std::ops::Range;

// the buffer and chunks on it
// try to cut `length` or less bytes from it,
// possibly advance slice by one position and/or update offset
fn cut<'a, F, T>(
    data: &'a [u8],
    length: usize,
    chunks: &mut &[Range<usize>],
    offset: &mut usize,
    f: F,
) -> Result<T, ()>
where
    F: FnOnce(&mut &'a [u8]) -> T,
{
    let mut data = match chunks.first() {
        Some(range) => {
            let start = *offset;
            let end = *offset + length;
            if end < range.end {
                *offset += length;
                &data[start..usize::min(data.len(), end)]
            } else if end == range.end {
                if chunks.len() > 1 {
                    *offset = chunks[1].start;
                    *chunks = &chunks[1..];
                } else {
                    *offset = range.end;
                    *chunks = &[];
                }
                &data[start..usize::min(data.len(), end)]
            } else {
                if start < range.end {
                    *offset = range.end;
                    &data[start..usize::min(data.len(), range.end)]
                } else {
                    &[]
                }
            }
        },
        _ => &[],
    };
    if data.len() == length {
        Ok(f(&mut data))
    } else {
        Err(())
    }
}

fn intersect(space: Range<usize>, item: Range<usize>) -> Range<usize> {
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

pub fn show(
    data: &[u8],
    chunks: &mut &[Range<usize>],
    encoding: &Encoding,
    space: Range<usize>,
    base: &str,
    node: &mut Tree,
    offset: &mut usize,
) -> Result<(), ()>
{
    match encoding {
        &Encoding::Unit => (),
        &Encoding::Int8 => {
            let item = *offset..(*offset + 1);
            let value = cut(data, item.len(), chunks, offset, Buf::get_i8)?;
            node.add(base, intersect(space, item), TreeLeaf::dec(value as _));
        },
        &Encoding::Uint8 => {
            let item = *offset..(*offset + 1);
            let value = cut(data, item.len(), chunks, offset, Buf::get_u8)?;
            node.add(base, intersect(space, item), TreeLeaf::dec(value as _));
        },
        &Encoding::Int16 => {
            let item = *offset..(*offset + 2);
            let value = cut(data, item.len(), chunks, offset, Buf::get_i16)?;
            node.add(base, intersect(space, item), TreeLeaf::dec(value as _));
        },
        &Encoding::Uint16 => {
            let item = *offset..(*offset + 2);
            let value = cut(data, item.len(), chunks, offset, Buf::get_u16)?;
            node.add(base, intersect(space, item), TreeLeaf::dec(value as _));
        },
        &Encoding::Int31 | &Encoding::Int32 => {
            let item = *offset..(*offset + 4);
            let value = cut(data, item.len(), chunks, offset, Buf::get_i32)?;
            node.add(base, intersect(space, item), TreeLeaf::dec(value as _));
        },
        &Encoding::Uint32 => {
            let item = *offset..(*offset + 4);
            let value = cut(data, item.len(), chunks, offset, Buf::get_u32)?;
            node.add(base, intersect(space, item), TreeLeaf::dec(value as _));
        },
        &Encoding::Int64 => {
            let item = *offset..(*offset + 8);
            let value = cut(data, item.len(), chunks, offset, Buf::get_i64)?;
            node.add(base, intersect(space, item), TreeLeaf::dec(value as _));
        },
        &Encoding::RangedInt | 
        &Encoding::Z | &Encoding::Mutez | 
        &Encoding::Float | &Encoding::RangedFloat => unimplemented!(),
        &Encoding::Bool => {
            let item = *offset..(*offset + 1);
            let value = cut(data, item.len(), chunks, offset, |d| d.get_u8() == 0xff)?;
            node.add(base, intersect(space, item), TreeLeaf::Display(value));
        },
        &Encoding::String => {
            let mut item = *offset..(*offset + 4);
            let length = cut(data, item.len(), chunks, offset, Buf::get_u32)? as usize;
            let f = |data: &mut &[u8]| String::from_utf8((*data).to_owned()).ok();
            let string = cut(data, length, chunks, offset, f)?;
            item.end = *offset;
            if let Some(s) = string {
                node.add(base, intersect(space, item), TreeLeaf::Display(s));
            }
        },
        &Encoding::Bytes => {
            let mut item = *offset..*offset;
            let len = chunks.first().map(|c| usize::min(data.len(), c.end) - *offset).unwrap_or(0);
            let string = cut(data, len, chunks, offset, |d| hex::encode(*d))?;
            item.end = *offset;
            node.add(base, intersect(space, item), TreeLeaf::Display(string));
        },
        // recursive
        &Encoding::Tags(ref tag_size, ref tag_map) => {
            if (1..=2).contains(tag_size) {
                // TODO: use item, highlight the tag
                let item = *offset..(*offset + *tag_size);
                let id = if *tag_size == 1 {
                    cut(data, item.len(), chunks, offset, Buf::get_u8)? as u16
                } else {
                    cut(data, item.len(), chunks, offset, Buf::get_u16)? as u16
                };
                if let Some(tag) = tag_map.find_by_id(id) {
                    let sub_space = *offset..space.end;
                    let range = intersect(space.clone(), sub_space.clone());
                    let mut sub_node = node
                        .add(base, range, TreeLeaf::nothing())
                        .subtree();
                    show(data, chunks, tag.get_encoding(), space.clone(), tag.get_variant(), &mut sub_node, offset)?;
                }
                
            } else {
                log::warn!("unsupported tag size");
            }
        },
        &Encoding::List(ref encoding) => {
            while *offset < data.len() {
                show(data, chunks, encoding, space.clone(), base, node, offset)?;
            }
        },
        // ...
        &Encoding::Obj(ref fields) => {
            let sub_space = *offset..space.end;
            let range = intersect(space.clone(), sub_space.clone());
            let mut sub_node = node
                .add(base, range, TreeLeaf::nothing())
                .subtree();
            for field in fields {
                show(data, chunks, field.get_encoding(), space.clone(), field.get_name(), &mut sub_node, offset)?;
            }
        },
        // ...
        &Encoding::Dynamic(ref encoding) => {
            // TODO: use item, highlight the length
            let item = *offset..(*offset + 4);
            let length = cut(data, item.len(), chunks, offset, Buf::get_u32)? as usize;
            if *offset + length <= data.len() {
                show(&data[..(*offset + length)], chunks, encoding, space, base, node, offset)?;
            }
        },
        &Encoding::Sized(ref size, ref encoding) => {
            show(&data[..(*offset + size)], chunks, encoding, space, base, node, offset)?;
        },
        &Encoding::Hash(ref hash_type) => {
            let item = *offset..(*offset + hash_type.size());
            let string = cut(data, item.len(), chunks, offset, |d| hex::encode(*d))?;
            node.add(base, intersect(space, item), TreeLeaf::Display(string));
        }
        // ...
        _ => Err(())?,
    };
    Ok(())
}
