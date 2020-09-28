use std::{fmt, ops::Range, net::SocketAddr};

#[derive(Clone, Debug)]
pub enum FieldDescriptor<'a> {
    Nothing { name: &'a str, abbrev: &'a str },
    String { name: &'a str, abbrev: &'a str },
    Int64Dec { name: &'a str, abbrev: &'a str },
}

impl<'a> FieldDescriptor<'a> {
    pub fn to_owned(&self) -> FieldDescriptorOwned {
        match self {
            &FieldDescriptor::Nothing { name, abbrev } => FieldDescriptorOwned::Nothing {
                name: name.to_owned(),
                abbrev: abbrev.to_owned(),
            },
            &FieldDescriptor::String { name, abbrev } => FieldDescriptorOwned::String {
                name: name.to_owned(),
                abbrev: abbrev.to_owned(),
            },
            &FieldDescriptor::Int64Dec { name, abbrev } => FieldDescriptorOwned::Int64Dec {
                name: name.to_owned(),
                abbrev: abbrev.to_owned(),
            },
        }
    }
}

#[derive(Clone, Debug)]
pub enum FieldDescriptorOwned {
    Nothing { name: String, abbrev: String },
    String { name: String, abbrev: String },
    Int64Dec { name: String, abbrev: String },
}

pub trait HasFields {
    const FIELDS: &'static [FieldDescriptor<'static>];
    fn fields() -> Vec<FieldDescriptorOwned>;
}

pub trait TreePresenter {
    fn subtree(&mut self) -> Self;
    fn add<D, P>(&mut self, path: P, range: Range<usize>, v: TreeLeaf<D>) -> Self
    where
        D: fmt::Display,
        P: AsRef<str>;
}

pub enum TreeLeaf<D>
where
    D: fmt::Display,
{
    Nothing,
    Display(D),
    Int64Dec(i64),
    Float64(f64),
}

impl TreeLeaf<String> {
    pub fn dec(v: i64) -> Self {
        TreeLeaf::Int64Dec(v)
    }

    pub fn float(v: f64) -> Self {
        TreeLeaf::Float64(v)
    }

    pub fn nothing() -> Self {
        TreeLeaf::Nothing
    }
}

/// The most common socket address is ip (v4 or v6 and port),
/// but also it might be some other kind of address.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum SocketAddress {
    Ip(SocketAddr),
    Other {
        ip_type: i32,
        ip: Vec<u8>,
        port: u16,
    },
}

impl fmt::Display for SocketAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            &SocketAddress::Ip(ref a) => write!(f, "{}", a),
            &SocketAddress::Other {
                ref ip_type,
                ref ip,
                ref port,
            } => write!(f, "Unknown[{}]:{}:{}", *ip_type, hex::encode(ip), *port),
        }
    }
}

pub trait PacketMetadata {
    fn destination(&self) -> SocketAddress;
    fn source(&self) -> SocketAddress;
    fn frame_number(&self) -> u64;
}
