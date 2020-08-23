use tezos_encoding::encoding::{HasEncoding, Encoding, SchemaType};
use wireshark_epan_adapter::{FieldDescriptorOwned, FieldDescriptor, dissector::HasFields};

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

fn to_descriptor(base: &str, this: &str, kind: FieldKind) -> FieldDescriptorOwned {
    let capitalized = {
        let mut v = this.chars().collect::<Vec<_>>();
        v[0] = v[0].to_uppercase().nth(0).unwrap();
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

impl<T> HasFields for TezosEncoded<T>
where
    T: HasEncoding + Named,
{
    const FIELDS: &'static [FieldDescriptor<'static>] = &[];

    fn fields() -> Vec<FieldDescriptorOwned> {
        fn recursive(base: &str, name: &str, encoding: &Encoding) -> Vec<FieldDescriptorOwned> {
            let new_base = format!("{}.{}", base, name);
            let (kind, more) = match encoding {
                &Encoding::Unit => (None, Vec::new()),
                &Encoding::Int8 | &Encoding::Uint8
                | &Encoding::Int16 | &Encoding::Uint16
                | &Encoding::Int31 | &Encoding::Int32 | &Encoding::Uint32
                | &Encoding::Int64 | &Encoding::RangedInt => (Some(FieldKind::IntDec), Vec::new()),
                &Encoding::Z | &Encoding::Mutez => unimplemented!(),
                &Encoding::Float | &Encoding::RangedFloat => unimplemented!(),
                &Encoding::Bool => (Some(FieldKind::String), Vec::new()),
                &Encoding::String | &Encoding::Bytes => (Some(FieldKind::String), Vec::new()),
                &Encoding::Tags(_, ref map) => (
                    Some(FieldKind::Nothing),
                    // have to probe all ids...
                    (0..=u16::MAX)
                        .filter_map(|id| map.find_by_id(id))
                        .map(|tag| {
                            recursive(new_base.as_str(), tag.get_variant(), tag.get_encoding())
                        })
                        .flatten()
                        .collect()
                ),
                &Encoding::List(ref encoding) => (None, recursive(base, name, encoding)),
                &Encoding::Enum => (Some(FieldKind::String), Vec::new()),
                &Encoding::Option(ref encoding)
                | &Encoding::OptionalField(ref encoding) => (None, recursive(base, name, encoding)),
                &Encoding::Obj(ref fields) => (
                    Some(FieldKind::Nothing),
                    fields.iter()
                        .map(|field| {
                            recursive(new_base.as_str(), field.get_name(), field.get_encoding())
                        })
                        .flatten()
                        .collect()
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
                &Encoding::Lazy(_) => (Some(FieldKind::Nothing), Vec::new()),
            };
            kind
                .map(|kind| to_descriptor(base, name, kind))
                .into_iter()
                .chain(more)
                .collect()
        }
        recursive("tezos", T::NAME, &T::encoding())
    }
}
