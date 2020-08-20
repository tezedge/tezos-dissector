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
    default: T,
    f: F,
) -> T
where
    F: FnOnce(&mut &'a [u8]) -> T,
{
    let mut data = match chunks.first() {
        Some(range) => {
            let start = *offset;
            let end = *offset + length;
            if end < range.end {
                *offset += length;
                &data[start..end]
            } else if end == range.end {
                if chunks.len() > 1 {
                    *offset = chunks[1].start;
                    *chunks = &chunks[1..];
                } else {
                    *offset = range.end;
                    *chunks = &[];
                }
                &data[start..end]
            } else {
                if start < range.end {
                    *offset = range.end;
                    &data[start..range.end]
                } else {
                    &[]
                }
            }
        },
        _ => &[],
    };
    if data.len() == length {
        f(&mut data)
    } else {
        default
    }
}

fn intersect(space: Range<usize>, item: Range<usize>) -> Range<usize> {
    let start = usize::max(space.start, item.start) - space.start;
    let end = usize::min(space.end, item.end) - space.start;
    start..end
}

pub fn show<'a>(
    data: &[u8],
    chunks: &mut &[Range<usize>],
    encoding: &'a Encoding,
    space: Range<usize>,
    base: &str,
    node: &mut Tree,
    offset: &mut usize,
)
{
    match encoding {
        &Encoding::Unit => (),
        &Encoding::Int8 => {
            let item = *offset..(*offset + 1);
            let value = cut(data, item.len(), chunks, offset, 0, Buf::get_i8);
            node.add(base, intersect(space, item), TreeLeaf::dec(value as _));
        },
        &Encoding::Uint8 => {
            let item = *offset..(*offset + 1);
            let value = cut(data, item.len(), chunks, offset, 0, Buf::get_u8);
            node.add(base, intersect(space, item), TreeLeaf::dec(value as _));
        },
        &Encoding::Int16 => {
            let item = *offset..(*offset + 2);
            let value = cut(data, item.len(), chunks, offset, 0, Buf::get_i16);
            node.add(base, intersect(space, item), TreeLeaf::dec(value as _));
        },
        &Encoding::Uint16 => {
            let item = *offset..(*offset + 2);
            let value = cut(data, item.len(), chunks, offset, 0, Buf::get_u16);
            node.add(base, intersect(space, item), TreeLeaf::dec(value as _));
        },
        &Encoding::Int31 | &Encoding::Int32 => {
            let item = *offset..(*offset + 4);
            let value = cut(data, item.len(), chunks, offset, 0, Buf::get_i32);
            node.add(base, intersect(space, item), TreeLeaf::dec(value as _));
        },
        &Encoding::Uint32 => {
            let item = *offset..(*offset + 4);
            let value = cut(data, item.len(), chunks, offset, 0, Buf::get_u32);
            node.add(base, intersect(space, item), TreeLeaf::dec(value as _));
        },
        &Encoding::Int64 => {
            let item = *offset..(*offset + 8);
            let value = cut(data, item.len(), chunks, offset, 0, Buf::get_i64);
            node.add(base, intersect(space, item), TreeLeaf::dec(value as _));
        },
        &Encoding::RangedInt | 
        &Encoding::Z | &Encoding::Mutez | 
        &Encoding::Float | &Encoding::RangedFloat => unimplemented!(),
        &Encoding::Bool => {
            let item = *offset..(*offset + 1);
            let value = cut(data, item.len(), chunks, offset, false, |d| d.get_u8() == 0xff);
            node.add(base, intersect(space, item), TreeLeaf::Display(value));
        },
        &Encoding::String => {
            let mut item = *offset..(*offset + 4);
            let length = cut(data, item.len(), chunks, offset, 0, Buf::get_u32) as usize;
            let f = |data: &mut &[u8]| String::from_utf8((*data).to_owned()).ok();
            let string = cut(data, length, chunks, offset, None, f);
            item.end = *offset;
            if let Some(s) = string {
                node.add(base, intersect(space, item), TreeLeaf::Display(s));
            }
        },
        &Encoding::Bytes => {
            let mut item = *offset..*offset;
            let len = chunks.first().map(|c| usize::max(data.len(), c.end) - *offset).unwrap_or(0);
            let string = cut(data, len, chunks, offset, String::new(), |d| hex::encode(*d));
            item.end = *offset;
            node.add(base, intersect(space, item), TreeLeaf::Display(string));
        },
        // recursive
        &Encoding::Tags(_, _) => unimplemented!(),
        &Encoding::List(_) => unimplemented!(),
        t => panic!("{:?}", t),
    }
}
