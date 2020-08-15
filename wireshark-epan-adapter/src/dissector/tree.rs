use std::{collections::BTreeMap, ops::Range, rc::Rc, cell::RefCell};
use crate::sys;

struct Common {
    fields: BTreeMap<&'static str, i32>,
    ett: Vec<i32>,
    tvb: *mut sys::tvbuff_t,
}

pub struct DissectorTree {
    common: Rc<RefCell<Common>>,
    parent_path: &'static str,
    base: usize,
    node: *mut sys::proto_tree,
}

pub enum DissectorTreeLeaf {
    Nothing,
    String(String),
    Int64Dec(i64),
}

impl DissectorTree {
    pub(crate) fn root(
        fields: BTreeMap<&'static str, i32>,
        ett: Vec<i32>,
        tvb: *mut sys::tvbuff_t,
        root: *mut sys::proto_tree,
    ) -> Self {
        let common = Common { fields, ett, tvb };

        DissectorTree {
            common: Rc::new(RefCell::new(common)),
            parent_path: "#",
            base: 0,
            node: root,
        }
    }

    pub fn subtree(&mut self) -> Self {
        DissectorTree {
            common: self.common.clone(),
            parent_path: self.parent_path,
            base: self.base,
            node: unsafe { sys::proto_item_add_subtree(self.node, self.common.borrow().ett[0]) },
        }
    }

    pub fn leaf(&mut self, path: &'static str, range: Range<usize>, v: DissectorTreeLeaf) -> Self {
        let node = match v {
            DissectorTreeLeaf::Nothing => unsafe {
                sys::proto_tree_add_item(
                    self.node,
                    self.common.borrow().fields[path],
                    self.common.borrow().tvb,
                    (self.base + range.start) as _,
                    range.len() as _,
                    sys::ENC_NA,
                )
            },
            DissectorTreeLeaf::String(mut value) => {
                value.push('\0');
                unsafe {
                    sys::proto_tree_add_string(
                        self.node,
                        self.common.borrow().fields[path],
                        self.common.borrow().tvb,
                        (self.base + range.start) as _,
                        range.len() as _,
                        value.as_ptr() as _,
                    )
                }
            },
            DissectorTreeLeaf::Int64Dec(_) => unimplemented!(),
        };

        DissectorTree {
            common: self.common.clone(),
            parent_path: path,
            base: range.start,
            node,
        }
    }
}
