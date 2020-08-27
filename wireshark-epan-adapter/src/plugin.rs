use std::{
    collections::HashMap,
    os::raw::{c_int, c_char, c_void},
    cell::RefCell,
    ptr,
};
use crate::sys;
use super::dissector::{DissectorHelper, SuperDissectorData, PacketInfo, Tree, HasFields};

/// Should be implemented for dissector.
pub trait Dissector {
    /// The only preference supported is filename. 
    /// Called when the user choose some file.
    fn prefs_update(&mut self, filenames: Vec<&str>) {
        let _ = filenames;
    }

    /// Called when a new packet just arrive
    /// or when the user click on some packet in the interface.
    fn consume(
        &mut self,
        helper: &mut DissectorHelper,
        root: &mut Tree,
        packet_info: &PacketInfo,
    ) -> usize;

    /// Called when capturing session end.
    /// The dissector is not destroyed, it might be used in the next capturing session.
    fn cleanup(&mut self);
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
    dissector: Option<Box<dyn Dissector>>,
}

impl PluginPrivates {
    const EMPTY: Self = PluginPrivates {
        plugin: sys::proto_plugin {
            register_protoinfo: None,
            register_handoff: None,
        },
        proto_handle: -1,
        field_handles: Vec::new(),
        hf: Vec::new(),
        ett_handle: -1,
        ett_info: ptr::null_mut(),
        pref_filenames: Vec::new(),
        callback_registered: false,
        dissector: None,
    };
}

pub struct Plugin<'a> {
    privates: RefCell<PluginPrivates>,
    dissector_descriptor: DissectorDescriptor<'a>,
    name_descriptor: NameDescriptor<'a>,
    field_descriptors: &'a [&'a [FieldDescriptor<'a>]],
    field_descriptors_owned: Vec<FieldDescriptorOwned>,
    filename_descriptors: &'a [PrefFilenameDescriptor<'a>],
}

pub struct NameDescriptor<'a> {
    pub name: &'a str,
    pub short_name: &'a str,
    pub filter_name: &'a str,
}

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

trait Info {
    fn info(&self, handle: &mut c_int) -> sys::hf_register_info;
}

impl<'a> Info for FieldDescriptor<'a> {
    fn info(&self, handle: &mut c_int) -> sys::hf_register_info {
        match self {
            &FieldDescriptor::Nothing { name, abbrev } => sys::hf_register_info {
                p_id: handle,
                hfinfo: sys::header_field_info {
                    name: name.as_ptr() as _,
                    abbrev: abbrev.as_ptr() as _,
                    type_: sys::ftenum_FT_NONE,
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
            &FieldDescriptor::String { name, abbrev } => sys::hf_register_info {
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
            &FieldDescriptor::Int64Dec { name, abbrev } => sys::hf_register_info {
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
        }
    }
}

impl Info for FieldDescriptorOwned {
    fn info(&self, handle: &mut c_int) -> sys::hf_register_info {
        match self {
            &FieldDescriptorOwned::Nothing {
                ref name,
                ref abbrev,
                ..
            } => FieldDescriptor::Nothing { name, abbrev }.info(handle),
            &FieldDescriptorOwned::String {
                ref name,
                ref abbrev,
                ..
            } => FieldDescriptor::String { name, abbrev }.info(handle),
            &FieldDescriptorOwned::Int64Dec {
                ref name,
                ref abbrev,
                ..
            } => FieldDescriptor::Int64Dec { name, abbrev }.info(handle),
        }
    }
}

trait Abbrev {
    fn abbrev(&self) -> String;
}

impl<'a> Abbrev for FieldDescriptor<'a> {
    fn abbrev(&self) -> String {
        match self {
            &FieldDescriptor::Nothing { abbrev, .. } => abbrev.to_string(),
            &FieldDescriptor::String { abbrev, .. } => abbrev.to_string(),
            &FieldDescriptor::Int64Dec { abbrev, .. } => abbrev.to_string(),
        }
    }
}

impl Abbrev for FieldDescriptorOwned {
    fn abbrev(&self) -> String {
        match self {
            &FieldDescriptorOwned::Nothing { ref abbrev, .. } => abbrev.to_string(),
            &FieldDescriptorOwned::String { ref abbrev, .. } => abbrev.clone(),
            &FieldDescriptorOwned::Int64Dec { ref abbrev, .. } => abbrev.clone(),
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
}

impl<'a> Plugin<'a> {
    pub const fn new(
        dissector_descriptor: DissectorDescriptor<'a>,
        name_descriptor: NameDescriptor<'a>,
        field_descriptors: &'a [&'a [FieldDescriptor<'a>]],
        filename_descriptors: &'a [PrefFilenameDescriptor<'a>],
    ) -> Self {
        Plugin {
            privates: RefCell::new(PluginPrivates::EMPTY),
            dissector_descriptor,
            name_descriptor,
            field_descriptors,
            field_descriptors_owned: Vec::new(),
            filename_descriptors,
        }
    }

    pub fn register_type<T>(self) -> Self
    where
        T: HasFields,
    {
        let mut s = self;
        s.field_descriptors_owned
            .extend_from_slice(T::fields().as_slice());
        s.field_descriptors_owned
            .extend(T::FIELDS.iter().map(FieldDescriptor::to_owned));
        s
    }

    fn fields(&self) -> HashMap<String, i32> {
        use std::iter;

        let state = self.privates.borrow();

        // subfields names
        let it = self
            .field_descriptors
            .iter()
            .map(|x| x.iter())
            .flatten()
            .map(Abbrev::abbrev)
            .chain(self.field_descriptors_owned.iter().map(Abbrev::abbrev))
            .zip(state.field_handles.iter().cloned());

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
    /// The most important and dangerous function in the library.
    pub fn register(self, dissector: Box<dyn Dissector>) {
        thread_local! {
            static CONTEXT: RefCell<Option<Plugin<'static>>> = RefCell::new(None);
        }

        fn with_plugin<F, R>(f: F) -> R
        where
            F: FnOnce(&Plugin<'static>) -> R,
        {
            CONTEXT.with(|c| {
                let b = c.borrow();
                f(&b.as_ref().unwrap())
            })
        }

        extern "C" fn register_protoinfo() {
            with_plugin(|p| {
                let proto = unsafe {
                    sys::proto_register_protocol(
                        p.name_descriptor.name.as_ptr() as _,
                        p.name_descriptor.short_name.as_ptr() as _,
                        p.name_descriptor.filter_name.as_ptr() as _,
                    )
                };
                let mut state = p.privates.borrow_mut();
                state.proto_handle = proto;

                let mut field_handles = {
                    let len = p.field_descriptors.iter().map(|x| x.len()).sum::<usize>();
                    let len = len + p.field_descriptors_owned.len();
                    let mut v = Vec::new();
                    v.resize(len, -1);
                    v
                };
                state.hf = p
                    .field_descriptors
                    .iter()
                    .map(|x| x.iter())
                    .flatten()
                    .map(|x| x as &dyn Info)
                    .chain(p.field_descriptors_owned.iter().map(|x| x as &dyn Info))
                    .zip(field_handles.iter_mut())
                    .map(|(descriptor, handle)| descriptor.info(handle))
                    .collect();
                state.field_handles = field_handles;
                state.ett_info = &mut state.ett_handle;

                unsafe {
                    sys::proto_register_field_array(
                        proto,
                        state.hf.as_mut_ptr() as _,
                        state.hf.len() as _,
                    );
                    sys::proto_register_subtree_array(&state.ett_info as _, 1);
                }

                extern "C" fn preferences_update_cb() {
                    use std::ffi::CStr;

                    with_plugin(|p| {
                        let mut state = p.privates.borrow_mut();
                        let filenames = state
                            .pref_filenames
                            .iter()
                            .map(|&p| {
                                let s = unsafe { CStr::from_ptr(p) };
                                s.to_str().unwrap()
                            })
                            .collect();
                        state.dissector.as_mut().unwrap().prefs_update(filenames);
                    })
                }

                let filename_descriptors = &p.filename_descriptors;
                if !filename_descriptors.is_empty() {
                    state
                        .pref_filenames
                        .resize(filename_descriptors.len(), ptr::null());
                    let prefs =
                        unsafe { sys::prefs_register_protocol(proto, Some(preferences_update_cb)) };
                    for (i, d) in filename_descriptors.iter().enumerate() {
                        unsafe {
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
            })
        }

        extern "C" fn wmem_cb(
            _allocator: *mut sys::wmem_allocator_t,
            ev: sys::wmem_cb_event_t,
            _data: *mut std::os::raw::c_void,
        ) -> sys::gboolean {
            match ev {
                sys::_wmem_cb_event_t_WMEM_CB_DESTROY_EVENT => (),
                _ => with_plugin(|p| {
                    let mut state = p.privates.borrow_mut();
                    if let &mut Some(ref mut d) = &mut state.dissector {
                        d.cleanup();
                    }
                }),
            }

            0
        }

        extern "C" fn register_handoff() {
            extern "C" fn heur_dissector(
                tvb: *mut sys::tvbuff_t,
                pinfo: *mut sys::packet_info,
                tree: *mut sys::proto_tree,
                data: *mut c_void,
            ) -> sys::gboolean {
                with_plugin(|p| {
                    {
                        let mut state = p.privates.borrow_mut();
                        if !state.callback_registered {
                            unsafe {
                                sys::wmem_register_callback(
                                    sys::wmem_file_scope(),
                                    Some(wmem_cb),
                                    ptr::null_mut(),
                                );
                            }
                            state.callback_registered = true;
                        }
                    }

                    let fields = p.fields();
                    let mut helper = DissectorHelper::new(
                        SuperDissectorData::Tcp(data as *mut sys::tcpinfo),
                        tvb,
                    );
                    let mut tree = Tree::root(fields, p.privates.borrow().ett_handle, tvb, tree);
                    let packet_info = PacketInfo::new(pinfo);
                    let mut state = p.privates.borrow_mut();
                    let dissector = state.dissector.as_mut().unwrap();
                    let processed_length = dissector.consume(&mut helper, &mut tree, &packet_info);
                    processed_length as _
                })
            }

            with_plugin(|p| {
                let state = p.privates.borrow();
                let proto_handle = state.proto_handle;
                unsafe {
                    sys::heur_dissector_add(
                        "tcp\0".as_ptr() as _,
                        Some(heur_dissector),
                        p.dissector_descriptor.display_name.as_ptr() as _,
                        p.dissector_descriptor.short_name.as_ptr() as _,
                        proto_handle,
                        sys::heuristic_enable_e_HEURISTIC_ENABLE,
                    );
                }
            })
        }

        CONTEXT.with(|f| {
            {
                let mut context = f.borrow_mut();
                *context = Some(self);
            }
            let context = f.borrow();
            let mut state = context.as_ref().unwrap().privates.borrow_mut();
            state.plugin = sys::proto_plugin {
                register_protoinfo: Some(register_protoinfo),
                register_handoff: Some(register_handoff),
            };
            state.dissector = Some(dissector);
            unsafe {
                sys::proto_register_plugin(&state.plugin);
            }
        });
    }
}
