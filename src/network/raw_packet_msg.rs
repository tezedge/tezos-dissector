use std::vec::Vec;
use std::fmt;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum RawMessageDirection {
    INCOMING,
    OUTGOING,
}
impl fmt::Display for RawMessageDirection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            RawMessageDirection::INCOMING => write!(f, "incoming"),
            RawMessageDirection::OUTGOING => write!(f, "outgoing"),
        }
    }
}

//#[derive(Debug, PartialEq)]
//pub enum RawMessageKind { INNER, OUTER }

pub struct RawPacketMessage {
    direction: RawMessageDirection,
    //    kind: RawMessageKind,
    payload: Vec<u8>,
}
impl RawPacketMessage {
    pub fn new<'a>(
        direction: RawMessageDirection,
        /*kind: RawMessageKind,*/ payload: &'a [u8],
    ) -> Self {
        Self {
            direction,
            /* kind ,*/ payload: payload.to_vec(),
        }
    }

    pub fn has_payload(&self) -> bool {
        self.payload.len() > 0
    }
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn is_incoming(&self) -> bool {
        self.direction == RawMessageDirection::INCOMING
    }

    //    pub fn is_inner(&self) -> bool {
    //        self.kind == RawMessageKind::INNER
    //    }
}
