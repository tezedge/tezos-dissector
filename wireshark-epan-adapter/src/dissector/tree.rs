use std::{collections::BTreeMap, ops::Range, rc::Rc, cell::RefCell, fmt};
use crate::plugin::{FieldDescriptor, FieldDescriptorOwned};
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

    pub fn show<M>(&mut self, message: &M, map: &[TreeMessageMapItem])
    where
        M: TreeMessage,
    {
        message.show_on_tree(self, map)
    }
}

/// The packet might contain some information not related to the message directly
/// for example
///
/// let the message contains of two chunks, but both of them only partially containing in the packet:
/// |size||            body            ||               MAC              ||size||        body        ||              MAC               |
/// <000e><1212121212121212121212121212><56565656565656565656565656565656><000a><ac6bc9e6fe0ca3ad3310><755463a7e211ef4bbf5146aa8254d881>
///         packet starts here -|121212  56565656565656565656565656565656  000a  ac6bc9e6fe0ca3ad|- packet ends here
///
/// so the packet contain part of previous chunk, and part of some chunk
/// the map will contain two entries:
/// `TreeMessageMapItem { offset_in_message: 11, offset_in_packet: 0, size: 3 }`
/// `TreeMessageMapItem { offset_in_message: 14, offset_in_packet: 21, size: 8 }`
pub struct TreeMessageMapItem {
    pub offset_in_message: usize,
    pub offset_in_packet: usize,
    pub size: usize,
}

pub trait TreeMessage {
    fn show_on_tree(&self, node: &mut Tree, map: &[TreeMessageMapItem]);
}

pub trait HasFields {
    const FIELDS: &'static [FieldDescriptor<'static>];
    fn fields() -> Vec<FieldDescriptorOwned>;
}
