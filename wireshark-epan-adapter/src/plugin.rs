use std::{
    collections::BTreeMap,
    os::raw::{c_int, c_char, c_void},
    ptr,
};
use crate::sys;
use super::dissector::{DissectorHelper, SuperDissectorData, PacketInfo, Tree};

pub trait Dissector {
    fn prefs_update(&mut self, filenames: Vec<&str>) {
        let _ = filenames;
    }

    fn consume(&mut self, helper: &mut DissectorHelper, root: &mut Tree) -> usize;
}

pub(crate) struct Contexts {
    inner: BTreeMap<*mut sys::conversation, *mut ()>,
    clear: Box<dyn Fn(&mut Contexts)>,
}

impl Contexts {
    fn inner_mut<C>(&mut self) -> &mut BTreeMap<*mut sys::conversation, C> {
        use std::mem;

        unsafe { mem::transmute(&mut self.inner) }
    }

    pub fn new<C>() -> Self
    where
        C: 'static + Default,
    {
        use std::mem;

        Contexts {
            inner: unsafe { mem::transmute(BTreeMap::<*mut sys::conversation, C>::new()) },
            clear: Box::new(Contexts::clear::<C>),
        }
    }

    pub fn clear<C>(&mut self)
    where
        C: 'static + Default,
    {
        self.inner_mut::<C>().clear();
    }

    pub fn get_or_new<C>(&mut self, key: *mut sys::conversation) -> &mut C
    where
        C: 'static + Default,
    {
        self.inner_mut().entry(key).or_default()
    }
}

struct PluginPrivates<'a> {
    plugin: sys::proto_plugin,
    proto_handle: i32,
    hf: Vec<sys::hf_register_info>,
    ett: Vec<&'a mut c_int>,
    pref_filenames: Vec<*const c_char>,
}

impl<'a> PluginPrivates<'a> {
    pub fn empty() -> Self {
        PluginPrivates {
            plugin: sys::proto_plugin {
                register_protoinfo: None,
                register_handoff: None,
            },
            proto_handle: -1,
            hf: Vec::new(),
            ett: Vec::new(),
            pref_filenames: Vec::new(),
        }
    }
}

pub struct Plugin<'a> {
    privates: PluginPrivates<'a>,
    name_descriptor: NameDescriptor<'a>,
    field_descriptors: Vec<(i32, FieldDescriptor<'a>)>,
    ett: Vec<i32>,
    filename_descriptors: Vec<PrefFilenameDescriptor<'a>>,
    dissector_descriptor: Option<DissectorDescriptor<'a>>,
    contexts: Contexts,
}

pub struct NameDescriptor<'a> {
    pub name: &'a str,
    pub short_name: &'a str,
    pub filter_name: &'a str,
}

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
    pub fn new<C>(name_descriptor: NameDescriptor<'a>) -> Self
    where
        C: 'static + Default,
    {
        Plugin {
            privates: PluginPrivates::empty(),
            name_descriptor: name_descriptor,
            field_descriptors: Vec::new(),
            ett: Vec::new(),
            filename_descriptors: Vec::new(),
            dissector_descriptor: None,
            contexts: Contexts::new::<C>(),
        }
    }

    pub fn add_field(self, field_descriptor: FieldDescriptor<'a>) -> Self {
        let mut s = self;
        s.field_descriptors.push((-1, field_descriptor));
        s
    }

    pub fn set_ett_number(self, number: usize) -> Self {
        let mut s = self;
        s.ett.resize(number, -1);
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

        // subfields names
        let it = self
            .field_descriptors
            .iter()
            .map(|(field, descriptor)| (descriptor.abbrev().to_owned(), field.clone()));

        // self name
        iter::once((
            self.name_descriptor.filter_name.to_owned(),
            self.privates.proto_handle,
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
            context_mut().privates.proto_handle = proto;

            context_mut().privates.hf = context_mut()
                .field_descriptors
                .iter_mut()
                .map(|x| match x {
                    &mut (
                        ref mut field,
                        FieldDescriptor::String {
                            name: ref mut name,
                            abbrev: ref mut abbrev,
                        },
                    ) => sys::hf_register_info {
                        p_id: field,
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
                    &mut (
                        ref mut field,
                        FieldDescriptor::Int64Dec {
                            name: ref mut name,
                            abbrev: ref mut abbrev,
                        },
                    ) => sys::hf_register_info {
                        p_id: field,
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
            sys::proto_register_field_array(
                proto,
                context_mut().privates.hf.as_mut_ptr() as _,
                context().privates.hf.len() as _,
            );

            context_mut().privates.ett = context_mut().ett.iter_mut().collect();
            sys::proto_register_subtree_array(
                context_mut().privates.ett.as_mut_ptr() as _,
                context().privates.ett.len() as _,
            );

            unsafe extern "C" fn preferences_update_cb() {
                use std::ffi::CStr;

                let d = dissector_mut();
                let filenames = context()
                    .privates
                    .pref_filenames
                    .iter()
                    .map(|&p| CStr::from_ptr(p).to_str().unwrap())
                    .collect();
                d.prefs_update(filenames);
            }

            let filename_descriptors = &context().filename_descriptors;
            if !filename_descriptors.is_empty() {
                let prefs = sys::prefs_register_protocol(proto, Some(preferences_update_cb));
                context_mut()
                    .privates
                    .pref_filenames
                    .resize(filename_descriptors.len(), ptr::null());
                for (i, d) in filename_descriptors.iter().enumerate() {
                    sys::prefs_register_filename_preference(
                        prefs,
                        d.name.as_ptr() as _,
                        d.title.as_ptr() as _,
                        d.description.as_ptr() as _,
                        context_mut().privates.pref_filenames.get_mut(i).unwrap(),
                        0,
                    );
                }
            }
        }

        unsafe extern "C" fn wmem_cb(
            _allocator: *mut sys::wmem_allocator_t,
            ev: sys::wmem_cb_event_t,
            data: *mut std::os::raw::c_void,
        ) -> sys::gboolean {
            match ev {
                sys::_wmem_cb_event_t_WMEM_CB_DESTROY_EVENT => {
                    log::error!("BUG, should not call `wmem_cb` with WMEM_CB_DESTROY_EVENT")
                },
                _ => (),
            }

            let clear = &mut (&mut *(data as *mut Contexts)).clear;
            clear(&mut *(data as *mut Contexts));

            0
        }

        unsafe extern "C" fn register_handoff() {
            unsafe extern "C" fn heur_dissector(
                tvb: *mut sys::tvbuff_t,
                pinfo: *mut sys::packet_info,
                tree: *mut sys::proto_tree,
                data: *mut c_void,
            ) -> sys::gboolean {
                let d = dissector_mut();
                let mut helper = DissectorHelper::new(
                    SuperDissectorData::Tcp(data as *mut sys::tcpinfo),
                    PacketInfo::new(pinfo),
                    tvb,
                    &mut context_mut().contexts,
                );
                let mut tree = Tree::root(context().fields(), context().ett.clone(), tvb, tree);
                let processed_length = d.consume(&mut helper, &mut tree);
                processed_length as _
            }

            if let Some(ref d) = context().dissector_descriptor {
                let proto_handle = context().privates.proto_handle;
                sys::heur_dissector_add(
                    "tcp\0".as_ptr() as _,
                    Some(heur_dissector),
                    d.display_name.as_ptr() as _,
                    d.short_name.as_ptr() as _,
                    proto_handle,
                    sys::heuristic_enable_e_HEURISTIC_ENABLE,
                );
            }

            let user_data = &mut context_mut().contexts as *mut Contexts as _;
            sys::wmem_register_callback(sys::wmem_file_scope(), Some(wmem_cb), user_data);
        }

        unsafe {
            CONTEXT = Some(self);
            context_mut().privates.plugin = sys::proto_plugin {
                register_protoinfo: Some(register_protoinfo),
                register_handoff: Some(register_handoff),
            };
            sys::proto_register_plugin(&context().privates.plugin);
        }
    }
}
