use wireshark_definitions::{NetworkPacket, TreePresenter};
use super::{
    context::{ContextInner, ErrorPosition},
    addresses::Sender,
};
use crate::identity::Identity;

pub struct Conversation {
    inner: Option<ContextInner>,
    pow_target: f64,
    incoming_frame_result: Result<(), ErrorPosition>,
    outgoing_frame_result: Result<(), ErrorPosition>,
}

impl Conversation {
    pub fn new(pow_target: f64) -> Self {
        Conversation {
            inner: None,
            pow_target,
            incoming_frame_result: Ok(()),
            outgoing_frame_result: Ok(()),
        }
    }

    /// The context becomes invalid if the inner is invalid or
    /// if the decryption error occurs in some previous frame.
    /// If the frame number is equal to the frame where error occurs,
    /// the context still valid, but after that it is invalid.
    /// Let's show the error message once.
    fn invalid(&self, packet: &NetworkPacket) -> bool {
        if let &Some(ref inner) = &self.inner {
            let i_error = self
                .incoming_frame_result
                .as_ref()
                .err()
                .map(|ref e| inner.after(packet, e))
                .unwrap_or(false);
            let o_error = self
                .outgoing_frame_result
                .as_ref()
                .err()
                .map(|ref e| inner.after(packet, e))
                .unwrap_or(false);
            i_error || o_error || inner.invalid()
        } else {
            false
        }
    }

    pub fn add<T>(
        &mut self,
        identity: Option<&(Identity, String)>,
        packet: &NetworkPacket,
        output: &mut T,
    ) -> bool
    where
        T: TreePresenter,
    {
        let pow_target = self.pow_target;
        let inner = self.inner.get_or_insert_with(|| ContextInner::new(packet, pow_target));
        inner.consume(packet, identity);    

        // the context might become invalid if the conversation is not tezos,
        // or if decryption error occurs
        if !self.invalid(packet) {
            match self.inner.as_mut().unwrap().visualize(packet, output) {
                Ok(()) => (),
                Err(r) => match r.sender {
                    Sender::Initiator => self.incoming_frame_result = Err(r),
                    Sender::Responder => self.outgoing_frame_result = Err(r),
                },
            };
            true
        } else {
            false
        }
    }
}
