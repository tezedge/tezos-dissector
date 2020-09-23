use wireshark_definitions::{PacketMetadata, TreePresenter};
use super::{
    context::{ContextInner, ErrorPosition},
    addresses::Sender,
};
use crate::identity::Identity;

pub struct Context {
    inner: Option<ContextInner>,
    incoming_frame_result: Result<(), ErrorPosition>,
    outgoing_frame_result: Result<(), ErrorPosition>,
}

impl Context {
    pub fn new() -> Self {
        Context {
            inner: None,
            incoming_frame_result: Ok(()),
            outgoing_frame_result: Ok(()),
        }
    }

    /// The context becomes invalid if the inner is invalid or
    /// if the decryption error occurs in some previous frame.
    /// If the frame number is equal to the frame where error occurs,
    /// the context still valid, but after that it is invalid.
    /// Let's show the error message once.
    fn invalid<P>(&self, packet_info: &P) -> bool
    where
        P: PacketMetadata,
    {
        if let &Some(ref inner) = &self.inner {
            let i_error = self
                .incoming_frame_result
                .as_ref()
                .err()
                .map(|ref e| inner.after(packet_info, e))
                .unwrap_or(false);
            let o_error = self
                .outgoing_frame_result
                .as_ref()
                .err()
                .map(|ref e| inner.after(packet_info, e))
                .unwrap_or(false);
            i_error || o_error || inner.invalid()
        } else {
            false
        }
    }

    pub fn add<P, T>(
        &mut self,
        identity: Option<&(Identity, String)>,
        data: &[u8],
        metadata: &P,
        output: &mut T,
    ) -> bool
    where
        P: PacketMetadata,
        T: TreePresenter,
    {
        let inner = self.inner.get_or_insert_with(|| ContextInner::new(metadata));
        inner.consume(data, metadata, identity);    

        // the context might become invalid if the conversation is not tezos,
        // or if decryption error occurs
        if !self.invalid(metadata) {
            match self.inner.as_mut().unwrap().visualize(metadata, output) {
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
