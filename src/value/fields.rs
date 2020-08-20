use tezos_encoding::encoding::{HasEncoding, Encoding};
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
            .collect()
    };

    let name = capitalized;
    let abbrev = format!("{}.{}", base, this);

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
                &Encoding::Unit => (Some(FieldKind::Nothing), Vec::new()),
                &Encoding::Int8 | &Encoding::Uint8
                | &Encoding::Int16 | &Encoding::Uint16
                | &Encoding::Int31 | &Encoding::Int32 | &Encoding::Uint32
                | &Encoding::Int64 | &Encoding::RangedInt => (Some(FieldKind::IntDec), Vec::new()),
                &Encoding::Z | &Encoding::Mutez => unimplemented!(),
                &Encoding::Float | &Encoding::RangedFloat => unimplemented!(),
                &Encoding::Bool => unimplemented!(),
                &Encoding::String | &Encoding::Bytes => (Some(FieldKind::String), Vec::new()),
                &Encoding::Tags(_, _) => unimplemented!(),
                &Encoding::List(ref encoding) => (None, recursive(base, name, encoding)),
                &Encoding::Obj(ref fields) => (
                    Some(FieldKind::Nothing),
                    fields.iter()
                        .map(|field| {
                            recursive(new_base.as_str(), field.get_name(), field.get_encoding())
                        })
                        .flatten()
                        .collect()
                ),
                &Encoding::Sized(_, ref encoding) => (None, recursive(base, name, encoding)),
                _ => panic!(),
            };
            kind
                .map(|kind| to_descriptor(base, name, kind))
                .into_iter()
                .chain(more.into_iter())
                .collect()
        }
        recursive("tezos", T::NAME, &T::encoding())
    }
}

#[cfg(test)]
#[test]
fn connection_message_fields() {
    use crate::conversation::ConnectionMessage;
    
    impl Named for ConnectionMessage {
        const NAME: &'static str = "connection_message";
    }

    let fields = TezosEncoded::<ConnectionMessage>::fields();
    println!("{:#?}", fields);
}
