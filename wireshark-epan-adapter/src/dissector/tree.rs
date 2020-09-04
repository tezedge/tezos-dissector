use std::{collections::HashMap, ops::Range, rc::Rc, cell::RefCell, fmt};
use crate::plugin::{FieldDescriptor, FieldDescriptorOwned};
use crate::sys;

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

struct Common {
    fields: HashMap<String, i32>,
    ett: i32,
    tvb: *mut sys::tvbuff_t,
}

pub struct Tree {
    common: Rc<RefCell<Common>>,
    parent_path: Option<String>,
    base: usize,
    node: *mut sys::proto_tree,
}

impl Tree {
    pub(crate) fn root(
        fields: HashMap<String, i32>,
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
}

impl TreePresenter for Tree {
    fn subtree(&mut self) -> Self {
        Tree {
            common: self.common.clone(),
            parent_path: self.parent_path.clone(),
            base: self.base,
            node: unsafe { sys::proto_item_add_subtree(self.node, self.common.borrow().ett) },
        }
    }

    fn add<D, P>(&mut self, path: P, range: Range<usize>, v: TreeLeaf<D>) -> Self
    where
        D: fmt::Display,
        P: AsRef<str>,
    {
        if cfg!(debug_assertions) {
            let length = unsafe { sys::tvb_captured_length(self.common.borrow().tvb) } as usize;
            assert!(range.start <= length);
            assert!(range.end <= length);
        }

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
                    range.start as _,
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
                        range.start as _,
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
                    range.start as _,
                    range.len() as _,
                    value,
                )
            },
            TreeLeaf::Float64(value) => {
                let _ = value;
                unimplemented!()
            },
        };

        Tree {
            common: self.common.clone(),
            parent_path: Some(full_path),
            base: range.start,
            node,
        }
    }
}

pub trait HasFields {
    const FIELDS: &'static [FieldDescriptor<'static>];
    fn fields() -> Vec<FieldDescriptorOwned>;
}
