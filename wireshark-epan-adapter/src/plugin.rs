use std::{
    collections::BTreeMap,
    os::raw::{c_int, c_char, c_void},
    cell::RefCell,
    ptr,
};
use crate::sys;
use super::dissector::{DissectorHelper, SuperDissectorData, PacketInfo, Tree, TreeMessage};

pub trait Dissector {
    fn prefs_update(&mut self, filenames: Vec<&str>) {
        let _ = filenames;
    }

    fn consume(
        &mut self,
        helper: &mut DissectorHelper,
        root: &mut Tree,
        packet_info: &PacketInfo,
    ) -> usize;
}

struct PluginPrivates {
    plugin: sys::proto_plugin,
    proto_handle: c_int,
    field_handles: Vec<c_int>,
    hf: Vec<sys::hf_register_info>,
    ett_handle: c_int,
    ett_info: *mut c_int,
    pref_filenames: Vec<*const c_char>,
    callback_registered: bool,
}

impl PluginPrivates {
    pub const EMPTY: Self = PluginPrivates {
        plugin: sys::proto_plugin {
            register_protoinfo: None,
            register_handoff: None,
        },
        proto_handle: -1,
        field_handles: vec![],
        hf: vec![],
        ett_handle: -1,
        ett_info: ptr::null_mut(),
        pref_filenames: vec![],
        callback_registered: false,
    };
}

pub struct Plugin<'a> {
    privates: RefCell<PluginPrivates>,
    name_descriptor: NameDescriptor<'a>,
    field_descriptors: Vec<FieldDescriptor<'a>>,
    filename_descriptors: Vec<PrefFilenameDescriptor<'a>>,
    dissector_descriptor: Option<DissectorDescriptor<'a>>,
}

pub struct NameDescriptor<'a> {
    pub name: &'a str,
    pub short_name: &'a str,
    pub filter_name: &'a str,
}

#[derive(Clone)]
pub enum FieldDescriptor<'a> {
    String { name: &'a str, abbrev: &'a str },
    Int64Dec { name: &'a str, abbrev: &'a str },
}

impl<'a> FieldDescriptor<'a> {
    pub fn abbrev(&self) -> &'a str {
        match self {
            &FieldDescriptor::String {
                name: _,
                abbrev: ref abbrev,
            } => abbrev.clone(),
            &FieldDescriptor::Int64Dec {
                name: _,
                abbrev: ref abbrev,
            } => abbrev.clone(),
        }
    }
}

pub struct PrefFilenameDescriptor<'a> {
    pub name: &'a str,
    pub title: &'a str,
    pub description: &'a str,
}

pub struct DissectorDescriptor<'a> {
    pub display_name: &'a str,
    pub short_name: &'a str,
    pub dissector: Box<dyn Dissector>,
}

impl<'a> Plugin<'a> {
    pub fn new(name_descriptor: NameDescriptor<'a>) -> Self {
        Plugin {
            privates: RefCell::new(PluginPrivates::EMPTY),
            name_descriptor: name_descriptor,
            field_descriptors: Vec::new(),
            filename_descriptors: Vec::new(),
            dissector_descriptor: None,
        }
    }

    pub fn register_message<M>(self) -> Self
    where
        M: TreeMessage,
    {
        let mut s = self;
        s.field_descriptors.extend_from_slice(M::FIELDS);
        s
    }

    pub fn add_field(self, field_descriptor: FieldDescriptor<'a>) -> Self {
        let mut s = self;
        s.field_descriptors.push(field_descriptor);
        s
    }

    pub fn set_pref_filename(self, filename_descriptor: PrefFilenameDescriptor<'a>) -> Self {
        let mut s = self;
        s.filename_descriptors.push(filename_descriptor);
        s
    }

    pub fn set_dissector(self, dissector_descriptor: DissectorDescriptor<'a>) -> Self {
        let mut s = self;
        s.dissector_descriptor = Some(dissector_descriptor);
        s
    }

    fn fields(&self) -> BTreeMap<String, i32> {
        use std::iter;

        let state = self.privates.borrow();

        // subfields names
        let it = self
            .field_descriptors
            .iter()
            .zip(state.field_handles.iter())
            .map(|(descriptor, field)| (descriptor.abbrev().to_owned(), field.clone()));

        // self name
        iter::once((
            self.name_descriptor.filter_name.to_owned(),
            state.proto_handle,
        ))
        .chain(it)
        .collect()
    }
}

impl Plugin<'static> {
    pub fn register(self) {
        static mut CONTEXT: Option<Plugin<'static>> = None;

        unsafe fn context() -> &'static Plugin<'static> {
            CONTEXT.as_ref().unwrap()
        }

        unsafe fn context_mut() -> &'static mut Plugin<'static> {
            CONTEXT.as_mut().unwrap()
        }

        unsafe fn dissector_mut() -> &'static mut Box<dyn Dissector> {
            &mut context_mut()
                .dissector_descriptor
                .as_mut()
                .unwrap()
                .dissector
        }

        unsafe extern "C" fn register_protoinfo() {
            let proto = sys::proto_register_protocol(
                context().name_descriptor.name.as_ptr() as _,
                context().name_descriptor.short_name.as_ptr() as _,
                context().name_descriptor.filter_name.as_ptr() as _,
            );
            let mut state = context().privates.borrow_mut();
            state.proto_handle = proto;

            let mut field_handles = {
                let len = context().field_descriptors.len();
                let mut v = Vec::new();
                v.resize(len, -1);
                v
            };
            state.hf = context()
                .field_descriptors
                .iter()
                .zip(field_handles.iter_mut())
                .map(|(descriptor, handle)| match descriptor {
                    &FieldDescriptor::String {
                        name: ref name,
                        abbrev: ref abbrev,
                    } => sys::hf_register_info {
                        p_id: handle,
                        hfinfo: sys::header_field_info {
                            name: name.as_ptr() as _,
                            abbrev: abbrev.as_ptr() as _,
                            type_: sys::ftenum_FT_STRING,
                            display: sys::field_display_e_BASE_NONE as _,
                            strings: ptr::null(),
                            bitmask: 0,
                            blurb: ptr::null(),
                            id: -1,
                            parent: 0,
                            ref_type: sys::hf_ref_type_HF_REF_TYPE_NONE,
                            same_name_prev_id: -1,
                            same_name_next: ptr::null_mut(),
                        },
                    },
                    &FieldDescriptor::Int64Dec {
                        name: ref name,
                        abbrev: ref abbrev,
                    } => sys::hf_register_info {
                        p_id: handle,
                        hfinfo: sys::header_field_info {
                            name: name.as_ptr() as _,
                            abbrev: abbrev.as_ptr() as _,
                            type_: sys::ftenum_FT_INT64,
                            display: sys::field_display_e_BASE_DEC as _,
                            strings: ptr::null(),
                            bitmask: 0,
                            blurb: ptr::null(),
                            id: -1,
                            parent: 0,
                            ref_type: sys::hf_ref_type_HF_REF_TYPE_NONE,
                            same_name_prev_id: -1,
                            same_name_next: ptr::null_mut(),
                        },
                    },
                })
                .collect();
            state.field_handles = field_handles;
            sys::proto_register_field_array(
                proto,
                state.hf.as_mut_ptr() as _,
                state.hf.len() as _,
            );

            state.ett_info = &mut state.ett_handle;
            sys::proto_register_subtree_array(&state.ett_info as _, 1);

            unsafe extern "C" fn preferences_update_cb() {
                use std::ffi::CStr;

                let state = context().privates.borrow();
                let d = dissector_mut();
                let filenames = state
                    .pref_filenames
                    .iter()
                    .map(|&p| CStr::from_ptr(p).to_str().unwrap())
                    .collect();
                d.prefs_update(filenames);
            }

            let filename_descriptors = &context().filename_descriptors;
            if !filename_descriptors.is_empty() {
                let prefs = sys::prefs_register_protocol(proto, Some(preferences_update_cb));
                state
                    .pref_filenames
                    .resize(filename_descriptors.len(), ptr::null());
                for (i, d) in filename_descriptors.iter().enumerate() {
                    sys::prefs_register_filename_preference(
                        prefs,
                        d.name.as_ptr() as _,
                        d.title.as_ptr() as _,
                        d.description.as_ptr() as _,
                        state.pref_filenames.get_mut(i).unwrap(),
                        0,
                    );
                }
            }
        }

        unsafe extern "C" fn wmem_cb(
            _allocator: *mut sys::wmem_allocator_t,
            ev: sys::wmem_cb_event_t,
            _data: *mut std::os::raw::c_void,
        ) -> sys::gboolean {
            match ev {
                sys::_wmem_cb_event_t_WMEM_CB_DESTROY_EVENT => (),
                _ => context_mut().dissector_descriptor = None,
            }

            0
        }

        unsafe extern "C" fn register_handoff() {
            unsafe extern "C" fn heur_dissector(
                tvb: *mut sys::tvbuff_t,
                pinfo: *mut sys::packet_info,
                tree: *mut sys::proto_tree,
                data: *mut c_void,
            ) -> sys::gboolean {
                {
                    let mut state = context().privates.borrow_mut();
                    if !state.callback_registered {
                        sys::wmem_register_callback(
                            sys::wmem_file_scope(),
                            Some(wmem_cb),
                            ptr::null_mut(),
                        );
                        state.callback_registered = true;
                    }    
                }

                let state = context().privates.borrow();
                let d = dissector_mut();
                let mut helper =
                    DissectorHelper::new(SuperDissectorData::Tcp(data as *mut sys::tcpinfo), tvb);
                let mut tree = Tree::root(context().fields(), state.ett_handle, tvb, tree);
                let packet_info = PacketInfo::new(pinfo);
                let processed_length = d.consume(&mut helper, &mut tree, &packet_info);
                processed_length as _
            }

            let state = context().privates.borrow();
            if let Some(ref d) = context().dissector_descriptor {
                let proto_handle = state.proto_handle;
                sys::heur_dissector_add(
                    "tcp\0".as_ptr() as _,
                    Some(heur_dissector),
                    d.display_name.as_ptr() as _,
                    d.short_name.as_ptr() as _,
                    proto_handle,
                    sys::heuristic_enable_e_HEURISTIC_ENABLE,
                );
            }
        }

        unsafe {
            CONTEXT = Some(self);
            let mut state = context().privates.borrow_mut();
            state.plugin = sys::proto_plugin {
                register_protoinfo: Some(register_protoinfo),
                register_handoff: Some(register_handoff),
            };
            sys::proto_register_plugin(&state.plugin);
        }
    }
}
