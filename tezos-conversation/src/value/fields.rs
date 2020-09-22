// Copyright (c) SimpleStaking and Tezedge Contributors
// SPDX-License-Identifier: MIT

use tezos_encoding::encoding::{HasEncoding, Encoding, SchemaType, Field};
use wireshark_definitions::{FieldDescriptorOwned, FieldDescriptor, HasFields};

/// The wrapper around the type which has an encoding and a name as a static string.
/// The wrapper needed because it is impossible to implement foreign trait for foreign type.
pub struct TezosEncoded<T>(pub T)
where
    T: HasEncoding + Named;

pub trait Named {
    const NAME: &'static str;
}

enum FieldKind {
    Nothing,
    String,
    IntDec,
}

/// Create `FieldDescriptorOwned` the structure of wireshark-epan-adapter
/// by concatenating base path and last path component.
/// It just prettify the name.
fn to_descriptor(base: &str, this: &str, kind: FieldKind) -> FieldDescriptorOwned {
    let capitalized = {
        let mut v = this.chars().collect::<Vec<_>>();
        v[0] = v[0].to_uppercase().next().unwrap();
        v.into_iter()
            .map(|x| if x == '_' { ' ' } else { x })
            .chain(std::iter::once('\0'))
            .collect()
    };

    let name = capitalized;
    let abbrev = format!("{}.{}\0", base, this);

    match kind {
        FieldKind::Nothing => FieldDescriptorOwned::Nothing { name, abbrev },
        FieldKind::String => FieldDescriptorOwned::String { name, abbrev },
        FieldKind::IntDec => FieldDescriptorOwned::Int64Dec { name, abbrev },
    }
}

// Wireshark requires all tree branches are registered before dissector run.
// We need to resister all types that we expect to decode before start.
impl<T> HasFields for TezosEncoded<T>
where
    T: HasEncoding + Named,
{
    const FIELDS: &'static [FieldDescriptor<'static>] = &[];

    fn fields() -> Vec<FieldDescriptorOwned> {
        // recursive traversal the encoding and generating field descriptor array
        // for example, for `MetadataMessage` it generates
        //  [
        //      Nothing {
        //          name: "Metadata message\u{0}",
        //          abbrev: "tezos.metadata_message\u{0}",
        //      },
        //      String {
        //          name: "Disable mempool\u{0}",
        //          abbrev: "tezos.metadata_message.disable_mempool\u{0}",
        //      },
        //      String {
        //          name: "Private node\u{0}",
        //          abbrev: "tezos.metadata_message.private_node\u{0}",
        //      },
        //  ]
        fn recursive(base: &str, name: &str, encoding: &Encoding) -> Vec<FieldDescriptorOwned> {
            let new_base = format!("{}.{}", base, name);
            let (kind, more) = match encoding {
                &Encoding::Unit => (None, Vec::new()),
                &Encoding::Int8
                | &Encoding::Uint8
                | &Encoding::Int16
                | &Encoding::Uint16
                | &Encoding::Int31
                | &Encoding::Int32
                | &Encoding::Uint32
                | &Encoding::Int64
                | &Encoding::RangedInt => (Some(FieldKind::IntDec), Vec::new()),
                &Encoding::Z | &Encoding::Mutez => (Some(FieldKind::String), Vec::new()),
                &Encoding::Float | &Encoding::RangedFloat => unimplemented!(),
                &Encoding::Bool => (Some(FieldKind::String), Vec::new()),
                &Encoding::String | &Encoding::Bytes => (Some(FieldKind::String), Vec::new()),
                &Encoding::Tags(ref size, ref map) => (
                    Some(FieldKind::Nothing),
                    // have to probe all ids...
                    (0..=(((1usize << (size.clone() * 8)) - 1) as u16))
                        .filter_map(|id| map.find_by_id(id))
                        .map(|tag| {
                            recursive(new_base.as_str(), tag.get_variant(), tag.get_encoding())
                        })
                        .flatten()
                        .collect(),
                ),
                &Encoding::List(ref encoding) => {
                    // list of uint8 can be presented as hex, just like `Encoding::Bytes`
                    // `Encoding::List(Encoding::Uint8)` is the same as `Encoding::Bytes`
                    if let &Encoding::Uint8 = encoding.as_ref() {
                        (Some(FieldKind::String), Vec::new())
                    } else {
                        (None, recursive(base, name, encoding))
                    }
                },
                &Encoding::Enum => (Some(FieldKind::String), Vec::new()),
                &Encoding::Option(ref encoding) | &Encoding::OptionalField(ref encoding) => {
                    (None, recursive(base, name, encoding))
                },
                &Encoding::Obj(ref fields) => (
                    Some(FieldKind::Nothing),
                    if fields.len() == 1 && fields[0].get_name() == "messages" {
                        recursive(base, name, &fields[0].get_encoding())
                    } else {
                        fields
                            .iter()
                            .map(|field| {
                                // make exception for this field
                                // because it is impossible to traversal infinite tree
                                let encoding = if field.get_name() == "operation_hashes_path" {
                                    Encoding::Obj(vec![Field::new(
                                        "path_component",
                                        Encoding::String,
                                    )])
                                } else {
                                    field.get_encoding().clone()
                                };
                                recursive(new_base.as_str(), field.get_name(), &encoding)
                            })
                            .flatten()
                            .collect()
                    },
                ),
                &Encoding::Tup(ref e) => (
                    Some(FieldKind::Nothing),
                    e.iter()
                        .enumerate()
                        .map(|(i, encoding)| {
                            let n = format!("{}", i);
                            recursive(new_base.as_str(), &n, encoding)
                        })
                        .flatten()
                        .collect(),
                ),
                &Encoding::Dynamic(ref encoding) => (None, recursive(base, name, encoding)),
                &Encoding::Sized(_, ref encoding) => (None, recursive(base, name, encoding)),
                &Encoding::Greedy(ref encoding) => (None, recursive(base, name, encoding)),
                &Encoding::Hash(_) => (Some(FieldKind::String), Vec::new()),
                &Encoding::Split(ref f) => (None, recursive(base, name, &f(SchemaType::Binary))),
                &Encoding::Timestamp => (Some(FieldKind::String), Vec::new()),
                // it is impossible to traversal infinite tree,
                // so it should be replaced by something else
                // the only such situation is `operation_hashes_path`,
                // it treated as special case, see above
                &Encoding::Lazy(ref _f) => panic!("should workaround somehow infinite tree"),
            };
            kind.map(|kind| to_descriptor(base, name, kind))
                .into_iter()
                .chain(more)
                .collect()
        }
        recursive("tezos.messages", T::NAME, &T::encoding())
    }
}
