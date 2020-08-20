use tezos_encoding::{types::Value, encoding::HasEncoding};
use wireshark_epan_adapter::dissector::{Tree, TreeMessage, TreeMessageMapItem};
use std::marker::PhantomData;

pub struct WrappedValue<T>
where
    T: HasEncoding,
{
    value: Value,
    phantom_data: PhantomData<T>,
}

impl<T> WrappedValue<T>
where
    T: HasEncoding,
{
    pub fn new(value: Value) -> Self {
        WrappedValue {
            value,
            phantom_data: PhantomData,
        }
    }
}

impl<T> TreeMessage for WrappedValue<T>
where
    T: HasEncoding,
{
    fn show_on_tree(&self, node: &mut Tree, map: &[TreeMessageMapItem]) {
        let _ = (&self.value, node, map);
        unimplemented!()
    }
}
