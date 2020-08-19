use std::{collections::BTreeMap, ops::Range, rc::Rc, cell::RefCell, fmt};
use crate::plugin::FieldDescriptor;
use crate::sys;

struct Common {
    fields: BTreeMap<String, i32>,
    ett: i32,
    tvb: *mut sys::tvbuff_t,
}

pub struct Tree {
    common: Rc<RefCell<Common>>,
    parent_path: Option<String>,
    base: usize,
    node: *mut sys::proto_tree,
}

pub enum TreeLeaf<D>
where
    D: fmt::Display,
{
    Nothing,
    Display(D),
    Int64Dec(i64),
}

impl TreeLeaf<String> {
    pub fn dec(v: i64) -> Self {
        TreeLeaf::Int64Dec(v)
    }

    pub fn nothing() -> Self {
        TreeLeaf::Nothing
    }
}

impl Tree {
    pub(crate) fn root(
        fields: BTreeMap<String, i32>,
        ett: i32,
        tvb: *mut sys::tvbuff_t,
        root: *mut sys::proto_tree,
    ) -> Self {
        let common = Common { fields, ett, tvb };

        Tree {
            common: Rc::new(RefCell::new(common)),
            parent_path: None,
            base: 0,
            node: root,
        }
    }

    pub fn subtree(&mut self) -> Self {
        Tree {
            common: self.common.clone(),
            parent_path: self.parent_path.clone(),
            base: self.base,
            node: unsafe { sys::proto_item_add_subtree(self.node, self.common.borrow().ett) },
        }
    }

    pub fn add<D, P>(&mut self, path: P, range: Range<usize>, v: TreeLeaf<D>) -> Self
    where
        D: fmt::Display,
        P: AsRef<str>,
    {
        let full_path = if let &Some(ref base) = &self.parent_path {
            format!("{}.{}\0", base.trim_end_matches('\0'), path.as_ref())
        } else {
            format!("{}\0", path.as_ref())
        };

        let node = match v {
            TreeLeaf::Nothing => unsafe {
                sys::proto_tree_add_item(
                    self.node,
                    self.common.borrow().fields[&full_path],
                    self.common.borrow().tvb,
                    (self.base + range.start) as _,
                    range.len() as _,
                    sys::ENC_NA,
                )
            },
            TreeLeaf::Display(value) => {
                let value = format!("{}\0", value);
                unsafe {
                    sys::proto_tree_add_string(
                        self.node,
                        self.common.borrow().fields[&full_path],
                        self.common.borrow().tvb,
                        (self.base + range.start) as _,
                        range.len() as _,
                        value.as_ptr() as _,
                    )
                }
            },
            TreeLeaf::Int64Dec(value) => unsafe {
                sys::proto_tree_add_int64(
                    self.node,
                    self.common.borrow().fields[&full_path],
                    self.common.borrow().tvb,
                    (self.base + range.start) as _,
                    range.len() as _,
                    value,
                )
            },
        };

        Tree {
            common: self.common.clone(),
            parent_path: Some(full_path),
            base: range.start,
            node,
        }
    }

    pub fn show<M>(&mut self, message: M, offset: isize)
    where
        M: TreeMessage,
    {
        let packet_length = unsafe {
            sys::tvb_captured_length(self.common.borrow().tvb)
        } as usize;
        message.show_on_tree(self, packet_length, offset)
    }
}

pub trait TreeMessage {
    const FIELDS: &'static [FieldDescriptor<'static>];

    // offset is the index of byte on packet which is the first byte of the message
    // might be negative, it meant that message starts on some of previous packet
    fn show_on_tree(&self, node: &mut Tree, packet_length: usize, offset: isize);
}
