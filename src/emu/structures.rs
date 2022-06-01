use crate::emu::maps::Maps;


////// PEB / TEB //////

#[derive(Debug)]
pub struct ListEntry {
    flink: u32,
    blink: u32,
}

impl ListEntry {
    pub fn load(addr:u64, maps:&Maps) -> ListEntry {
        ListEntry{
            flink: maps.read_dword(addr).unwrap(),
            blink: maps.read_dword(addr+4).unwrap(),
        }
    }

    pub fn print(&self) {
        println!("{:#x?}", self);
    }
}


#[derive(Debug)]
pub struct LdrDataTableEntry {
    reserved1: [u32;2], 
    in_memory_order_module_links: ListEntry, // +8
    reserved2: [u32;2], 
    dll_base: u32,        // +16 +0x10
    entry_point: u32,     // +20 +0x14
    reserved3: u32,
    full_dll_name: u32,   // ptr to string +28  +0x1c   
    reserved4: [u8;8],
    reserved5: [u32;3],
    checksum: u32,          // +52  +0x34
    reserved6: u32,
    time_date_stamp: u32,   // +60  +0x3c
}


impl LdrDataTableEntry {
    pub fn load(addr:u64, maps:&Maps) -> LdrDataTableEntry {
        LdrDataTableEntry {
            reserved1: [maps.read_dword(addr).unwrap(), maps.read_dword(addr + 4).unwrap()],
            in_memory_order_module_links: ListEntry::load(addr + 8, &maps),
            reserved2: [maps.read_dword(addr + 12).unwrap(), maps.read_dword(addr + 16).unwrap()],
            dll_base: maps.read_dword(addr + 20).unwrap(),
            entry_point: maps.read_dword(addr + 24).unwrap(),
            reserved3: maps.read_dword(addr + 28).unwrap(),
            full_dll_name: maps.read_dword(addr + 32).unwrap(),
            reserved4: [0;8],
            reserved5: [maps.read_dword(addr + 38).unwrap(), 
                            maps.read_dword(addr + 42).unwrap(), 
                            maps.read_dword(addr + 46).unwrap()],
            checksum: maps.read_dword(addr + 50).unwrap(),
            reserved6: maps.read_dword(addr + 54).unwrap(),
            time_date_stamp: maps.read_dword(addr + 58).unwrap(),
        }
    }

    pub fn print(&self) {
        println!("{:#x?}", self);
    }
}


#[derive(Debug)]
pub struct PebLdrData {
    length: u32,
    initializated: u32,
    sshandle: u32,
    in_load_order_module_list: ListEntry,              // +0x14
    in_memory_order_module_list:  ListEntry,           // +0x1c
    in_initialization_order_module_list: ListEntry,
    entry_in_progress:  ListEntry,
}

impl PebLdrData {
    pub fn load(addr:u64, maps:&Maps) -> PebLdrData {
        PebLdrData {
            length: maps.read_dword(addr).unwrap(),
            initializated: maps.read_dword(addr + 4).unwrap(),
            sshandle: maps.read_dword(addr + 8).unwrap(),
            in_load_order_module_list: ListEntry::load(addr + 12, &maps),
            in_memory_order_module_list: ListEntry::load(addr + 12 + 8, &maps),
            in_initialization_order_module_list: ListEntry::load(addr + 12 + 8 +8, &maps),
            entry_in_progress: ListEntry::load(addr + 12 + 8 + 8 + 8, &maps),
        }
    }

    pub fn print(&self) {
        println!("{:#x?}", self);
    }
}

#[derive(Debug)]
pub struct PEB {
    reserved1: [u8;2],
    being_debugged: u8, 
    reserved2: u8, 
    reserved3: [u32;2],
    ldr: u32,  // ptr to PEB_LDR_DATA  +0x0c
    process_parameters: u32, 
    reserved4: [u32;3],
    alt_thunk_list_ptr: u32,
    reserved5: u32,
    reserved6: u32,
    reserved7: u32,
    reserved8: u32,
    alt_thunk_list_ptr_32: u32, // +52 + 45*4 + 96
    reserved9: [u32;45],
    reserved10: [u8;96],
    post_process_init_routine: u32,
    reserved11: [u32;128],
    reserved12: u32,
    session_id: u32,
}

impl PEB {

    pub fn new(ldr:u32, process_parameters:u32, alt_thunk_list_ptr:u32, alt_thunk_list_ptr_32:u32, 
                 post_process_init_routine:u32, session_id:u32) -> PEB {

        PEB {
            reserved1: [0;2],
            being_debugged: 0,
            reserved2: 0,
            reserved3: [0;2],
            ldr: ldr,
            process_parameters: process_parameters,
            reserved4: [0;3],
            alt_thunk_list_ptr: alt_thunk_list_ptr,
            reserved5: 0,
            reserved6: 0,
            reserved7: 0,
            reserved8: 0,
            alt_thunk_list_ptr_32: alt_thunk_list_ptr_32,
            reserved9: [0;45],
            reserved10: [0;96],
            post_process_init_routine: post_process_init_routine,
            reserved11: [0;128],
            reserved12: 0,
            session_id: session_id,
        }
    }


    pub fn load(addr:u64, maps:&Maps) -> PEB {
        PEB {
            reserved1: [0;2],
            being_debugged: maps.read_byte(addr + 2).unwrap(),
            reserved2: maps.read_byte(addr + 3).unwrap(),
            reserved3: [maps.read_dword(addr + 4).unwrap(), maps.read_dword(addr + 8).unwrap()],
            ldr: maps.read_dword(addr + 12).unwrap(),
            process_parameters: maps.read_dword(addr + 16).unwrap(),
            reserved4: [maps.read_dword(addr + 20).unwrap(), 
                            maps.read_dword(addr + 24).unwrap(), 
                            maps.read_dword(addr + 28).unwrap()],
            alt_thunk_list_ptr: maps.read_dword(addr + 32).unwrap(),
            reserved5: maps.read_dword(addr + 36).unwrap(),
            reserved6: maps.read_dword(addr + 40).unwrap(),
            reserved7: maps.read_dword(addr + 44).unwrap(),
            reserved8: maps.read_dword(addr + 48).unwrap(),
            alt_thunk_list_ptr_32: maps.read_dword(addr + 52).unwrap(),
            reserved9: [0;45],
            reserved10: [0;96],
            post_process_init_routine: maps.read_dword(addr + 328).unwrap(),
            reserved11: [0;128],
            reserved12: maps.read_dword(addr + 840).unwrap(),
            session_id: maps.read_dword(addr + 844).unwrap(),
        }
    }

    pub fn print(&self) {
        println!("{:#x?}", self);
    }
}

// 64bits
// https://bytepointer.com/resources/tebpeb64.htm

#[derive(Debug)]
pub struct PEB64 {
    inheritet_addr_space: u8,
    read_img_file_exec_options: u8,
    being_debugged: u8,
    system_dependent_01: u8,
    dummy_align: u32, 
    mutant: u64, 
    image_base_addr: u64,
    ldr: u64,
    process_parameters: u64,
    subsystem_data: u64,
    process_heap: u64,
    fast_peb_lock: u64,
    system_dependent_02: u64, 
    system_dependent_03: u64,
    system_dependent_04: u64,
    kernel_callback_table: u64,
    system_reserved: u32,
    system_dependent_05: u32,
    system_dependent_06: u64,
    tls_expansion_counter: u64,
    tls_bitmap: u64,
    tls_bitmap_bits: [u32; 2],
    read_only_shared_memory_base: u64,
    system_dependent_07: u64,
    read_only_static_server_data: u64,
    ansi_code_page_data: u64,
    oem_code_page_data: u64,
    unicode_case_table_data: u64,
    number_of_processors: u32,
    nt_global_flag: u32,
    critical_section_timeout: u64,
    heap_segment_reserve: u64,
    heap_segment_commit: u64,
    heap_decommit_total_free_threshold: u64,
    heap_decommit_free_block_threshold: u64,
    number_of_heaps: u32,
    max_number_of_heaps: u32,
    process_heaps: u64,
    gdi_share_handle_table: u64,
    process_starter_helper: u64,
    gdi_dc_attribute_list: u64,
    loader_lock: u64,
    os_major_version: u32,
    os_minor_version: u32,
    os_build_number: u16,
    oscsd_version: u16,
    os_platform_id: u32,
    image_subsystem: u32,
    image_subsystem_major_version: u32,
    image_subsystem_minor_version: u64,
    active_process_afinity_mask: u64,
    gdi_handle_buffer: [u64; 30],
    post_process_init_routine: u64,
    tls_expansion_bitmap: u64,
    tls_expansion_bitmap_bits: [u32; 32],
    session_id: u64,
    app_compat_flags: u64,
    app_compat_flags_user: u64,
    p_shim_data: u64,
    app_compat_info: u64,
    csd_version: [u64; 2],
    activate_context_data: u64,
    process_assembly_storage_map: u64,
    system_default_activation_context_data: u64,
    system_assembly_storage_map: u64,
    minimum_stack_commit: u64
}


impl PEB64 {
    pub fn load(addr:u64, maps:&Maps) -> PEB64 {
        PEB64 {
            inheritet_addr_space: maps.read_byte(addr).unwrap(),
            read_img_file_exec_options: maps.read_byte(addr+0x1).unwrap(),
            being_debugged: maps.read_byte(addr+0x2).unwrap(),
            system_dependent_01: maps.read_byte(addr+0x3).unwrap(),
            dummy_align: 0,
            mutant: maps.read_qword(addr+0x8).unwrap(),
            image_base_addr:  maps.read_qword(addr+0x10).unwrap(),
            ldr: maps.read_qword(addr+0x18).unwrap(),
            process_parameters: maps.read_qword(addr+0x20).unwrap(),
            subsystem_data: maps.read_qword(addr+0x28).unwrap(),
            process_heap: maps.read_qword(addr+0x30).unwrap(),
            fast_peb_lock: maps.read_qword(addr+0x38).unwrap(),
            system_dependent_02: maps.read_qword(addr+0x40).unwrap(),
            system_dependent_03: maps.read_qword(addr+0x48).unwrap(),
            system_dependent_04: maps.read_qword(addr+0x50).unwrap(),
            kernel_callback_table: maps.read_qword(addr+0x58).unwrap(),
            system_reserved: maps.read_dword(addr+0x60).unwrap(),
            system_dependent_05: maps.read_dword(addr+0x64).unwrap(),
            system_dependent_06: maps.read_qword(addr+0x68).unwrap(),
            tls_expansion_counter: maps.read_qword(addr+0x70).unwrap(),
            tls_bitmap: maps.read_qword(addr+0x78).unwrap(),
            tls_bitmap_bits: [maps.read_dword(addr+0x80).unwrap(), maps.read_dword(addr+0x84).unwrap()],
            read_only_shared_memory_base: maps.read_qword(addr+0x88).unwrap(),
            system_dependent_07: maps.read_qword(addr+0x90).unwrap(),
            read_only_static_server_data: maps.read_qword(addr+0x98).unwrap(),
            ansi_code_page_data: maps.read_qword(addr+0xa0).unwrap(),
            oem_code_page_data: maps.read_qword(addr+0xa8).unwrap(),
            unicode_case_table_data: maps.read_qword(addr+0xb0).unwrap(),
            number_of_processors: maps.read_dword(addr+0xb8).unwrap(),
            nt_global_flag: maps.read_dword(addr+0xbc).unwrap(),
            critical_section_timeout: maps.read_qword(addr+0xc0).unwrap(),
            heap_segment_reserve: maps.read_qword(addr+0xc8).unwrap(),
            heap_segment_commit: maps.read_qword(addr+0xd0).unwrap(),
            heap_decommit_total_free_threshold: maps.read_qword(addr+0xd8).unwrap(),
            heap_decommit_free_block_threshold: maps.read_qword(addr+0xd8).unwrap(),
            number_of_heaps: maps.read_dword(addr+0xe8).unwrap(),
            max_number_of_heaps: maps.read_dword(addr+0xec).unwrap(),
            process_heaps: maps.read_qword(addr+0xf0).unwrap(),
            gdi_share_handle_table: maps.read_qword(addr+0xf8).unwrap(),
            process_starter_helper: maps.read_qword(addr+0x100).unwrap(),
            gdi_dc_attribute_list: maps.read_qword(addr+0x108).unwrap(),
            loader_lock: maps.read_qword(addr+0x110).unwrap(),
            os_major_version: maps.read_dword(addr+0x118).unwrap(),
            os_minor_version: maps.read_dword(addr+0x11c).unwrap(),
            os_build_number: maps.read_word(addr+0x120).unwrap(),
            oscsd_version: maps.read_word(addr+0x122).unwrap(),
            os_platform_id: maps.read_dword(addr+0x124).unwrap(),
            image_subsystem: maps.read_dword(addr+0x128).unwrap(),
            image_subsystem_major_version: maps.read_dword(addr+0x12c).unwrap(),
            image_subsystem_minor_version: maps.read_qword(addr+0x130).unwrap(),
            active_process_afinity_mask: maps.read_qword(addr+0x138).unwrap(),
            gdi_handle_buffer: [0; 30],
            post_process_init_routine: maps.read_qword(addr+0x230).unwrap(),
            tls_expansion_bitmap: maps.read_qword(addr+0x238).unwrap(),
            tls_expansion_bitmap_bits: [0; 32],
            session_id: maps.read_qword(addr+0x2c0).unwrap(),
            app_compat_flags: maps.read_qword(addr+0x2c8).unwrap(),
            app_compat_flags_user: maps.read_qword(addr+0x2d0).unwrap(),
            p_shim_data: maps.read_qword(addr+0x2d8).unwrap(),
            app_compat_info: maps.read_qword(addr+0x2e0).unwrap(),
            csd_version: [maps.read_qword(addr+0x2e8).unwrap(), maps.read_qword(addr+0x2f0).unwrap()],
            activate_context_data: maps.read_qword(addr+0x2f8).unwrap(),
            process_assembly_storage_map: maps.read_qword(addr+0x300).unwrap(),
            system_default_activation_context_data: maps.read_qword(addr+0x308).unwrap(),
            system_assembly_storage_map: maps.read_qword(addr+0x310).unwrap(),
            minimum_stack_commit: maps.read_qword(addr+0x318).unwrap()
        }   
    }

    pub fn print(&self) {
        println!("{:#x?}", self);
    }
}

#[derive(Debug)]
pub struct TEB64 {
    nt_tib: [u8; 56],
    environment_pointer: u64,
    process_id: u64,
    thread_id: u64,
    active_rpc_handle: u64,
    thread_local_storage_pointer: u64,
    process_environment_block: u64,        // PEB64
    last_error_value: u32,
    count_of_owned_critical_sections: u32,
    csr_client_thread: u64,
    win32_thread_info: u64,
    user32_reserved: [u32; 26],
    user_reserved: [u32; 6],
    wow32_reserved: u64,
    current_locale: u32,
    fp_software_status_register: u32,
    system_reserved1: [u64; 54],
    exception_code: u32,
    activation_context_stack_pointer: u64
}

impl TEB64 {
    pub fn load(addr:u64, maps:&Maps) -> TEB64 {
        TEB64{
            nt_tib: [0; 56],
            environment_pointer: maps.read_qword(addr + 0x38).unwrap(),
            process_id: maps.read_qword(addr + 0x40).unwrap(),
            thread_id: maps.read_qword(addr + 0x48).unwrap(),
            active_rpc_handle: maps.read_qword(addr + 0x50).unwrap(),
            thread_local_storage_pointer: maps.read_qword(addr + 0x58).unwrap(),
            process_environment_block: maps.read_qword(addr + 0x60).unwrap(),
            last_error_value: maps.read_dword(addr + 0x68).unwrap(),
            count_of_owned_critical_sections: maps.read_dword(addr + 0x6c).unwrap(),
            csr_client_thread: maps.read_qword(addr + 0x70).unwrap(),
            win32_thread_info: maps.read_qword(addr + 0x78).unwrap(),
            user32_reserved: [0; 26],
            user_reserved: [0; 6],
            wow32_reserved: maps.read_qword(addr + 0x100).unwrap(),
            current_locale: maps.read_dword(addr + 0x108).unwrap(),
            fp_software_status_register: maps.read_dword(addr + 0x10c).unwrap(),
            system_reserved1: [0; 54],
            exception_code: maps.read_dword(addr + 0x2c0).unwrap(),
            activation_context_stack_pointer: maps.read_qword(addr + 0x2c8).unwrap()
        }
    }

    pub fn print(&self) {
        println!("{:#x?}", self);
    }
}

#[derive(Debug)]
pub struct LdrDataTableEntry64 { 
    in_load_order_links: u64,  
    in_memory_order_links: u64,
    in_initialization_order_links: u64,
    dll_base: u64,
    entry_point: u64,
    size_of_image: u64,
    full_dll_name1: u64,
    full_dll_name2: u64,
    base_dll_name1: u64,
    base_dll_name2: u64,
    flags: u32,
    load_count: u16,
    tls_index: u16,
    hash_links: u64
}

impl LdrDataTableEntry64 {
    pub fn load(addr:u64, maps:&Maps) -> LdrDataTableEntry64 {
        LdrDataTableEntry64{
            in_load_order_links: maps.read_qword(addr).unwrap(),
            in_memory_order_links: maps.read_qword(addr + 0x10).unwrap(),
            in_initialization_order_links: maps.read_qword(addr + 0x20).unwrap(),
            dll_base: maps.read_qword(addr + 0x30).unwrap(),
            entry_point: maps.read_qword(addr + 0x38).unwrap(),
            size_of_image: maps.read_qword(addr + 0x40).unwrap(),
            full_dll_name1: maps.read_qword(addr + 0x48).unwrap(),
            full_dll_name2: maps.read_qword(addr + 0x50).unwrap(),
            base_dll_name1: maps.read_qword(addr + 0x58).unwrap(),
            base_dll_name2: maps.read_qword(addr + 0x60).unwrap(),
            flags: maps.read_dword(addr + 0x68).unwrap(),
            load_count: maps.read_word(addr + 0x6c).unwrap(),
            tls_index: maps.read_word(addr + 0x6e).unwrap(),
            hash_links: maps.read_qword(addr + 0x70).unwrap()
        }
    }

    pub fn print(&self) {
        println!("{:#x?}", self);
    }
}


#[derive(Debug)]
pub struct ImageExportDirectory {
    characteristics: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    name: u32,
    base: u32,
    number_of_functions: u32,
    number_of_names: u32,
    address_of_functions: u32,
    address_of_names: u32,
    address_of_ordinals: u32
}

impl ImageExportDirectory {
    pub fn load(addr:u64, maps:&Maps) -> ImageExportDirectory {
        ImageExportDirectory {
            characteristics: maps.read_dword(addr).unwrap(),
            time_date_stamp: maps.read_dword(addr+4).unwrap(),
            major_version: maps.read_word(addr+8).unwrap(),
            minor_version: maps.read_word(addr+10).unwrap(),
            name: maps.read_dword(addr+12).unwrap(),
            base: maps.read_dword(addr+16).unwrap(),
            number_of_functions: maps.read_dword(addr+20).unwrap(),
            number_of_names: maps.read_dword(addr+24).unwrap(),
            address_of_functions: maps.read_dword(addr+28).unwrap(),
            address_of_names: maps.read_dword(addr+32).unwrap(),
            address_of_ordinals: maps.read_dword(addr+36).unwrap()
        }
    }

    pub fn print(&self) {
        println!("{:#x?}", self);
    }

}



////// EXCEPTIONS //////


/*
ypedef struct _SCOPETABLE_ENTRY {
 DWORD EnclosingLevel;
 PVOID FilterFunc;
 PVOID HandlerFunc;
} SCOPETABLE_ENTRY, *PSCOPETABLE_ENTRY;
*/


#[derive(Debug)]
pub struct PScopeTableEntry {
    enclosing_level: u32,
    filter_func: u32,
    handler_func: u32,
}

impl PScopeTableEntry {
    pub fn load(addr:u64, maps:&Maps) -> PScopeTableEntry {
        PScopeTableEntry {
            enclosing_level: maps.read_dword(addr).unwrap(),
            filter_func: maps.read_dword(addr + 4).unwrap(),
            handler_func: maps.read_dword(addr + 8).unwrap(),
        }
    }

    pub fn size() -> u64 {
        return 12;
    }

    pub fn print(&self) {
        println!("{:#x?}", self);
    }
}



#[derive(Debug)]
pub struct CppEhRecord {
    old_esp: u32,
    exc_ptr: u32,
    next: u32, // ptr to _EH3_EXCEPTION_REGISTRATION
    exception_handler: u32, 
    scope_table: PScopeTableEntry,
    try_level: u32,
}

impl CppEhRecord {
    pub fn load(addr:u64, maps:&Maps) -> CppEhRecord {
        CppEhRecord{
            old_esp: maps.read_dword(addr).unwrap(),
            exc_ptr: maps.read_dword(addr + 4).unwrap(),
            next: maps.read_dword(addr + 8).unwrap(),
            exception_handler: maps.read_dword(addr + 12).unwrap(),
            scope_table: PScopeTableEntry::load(addr + 16, &maps),
            try_level: maps.read_dword(addr + 16 + PScopeTableEntry::size()).unwrap(),
        }
    }

    pub fn print(&self) {
        println!("{:#x?}", self);
    }
}


#[derive(Debug)]
pub struct ExceptionPointers {
    exception_record: u32,
    context_record: u32,
}

impl ExceptionPointers {
    pub fn load(addr:u64, maps:&Maps) -> ExceptionPointers {
        ExceptionPointers {
            exception_record: maps.read_dword(addr).unwrap(),
            context_record: maps.read_dword(addr + 4).unwrap(),
        }
    }

    pub fn size() -> u64 {
        return 8;
    }

    pub fn print(&self) {
        println!("{:#x?}", self);
    }
}

#[derive(Debug)]
pub struct Eh3ExceptionRegistration {
    next: u32,
    exception_handler: u32,
    scope_table: PScopeTableEntry,
    try_level: u32,
}

impl Eh3ExceptionRegistration {
    pub fn load(addr:u64, maps:&Maps) -> Eh3ExceptionRegistration {
        Eh3ExceptionRegistration {
            next: maps.read_dword(addr).unwrap(),
            exception_handler: maps.read_dword(addr + 4).unwrap(),
            scope_table: PScopeTableEntry::load(addr + 8, &maps),
            try_level: maps.read_dword(addr + 8 + PScopeTableEntry::size()).unwrap(),
        }
    }

    pub fn print(&self) {
        println!("{:#x?}", self);
    }
}

#[derive(Debug)]
pub struct MemoryBasicInformation {
    pub base_address: u32,
    pub allocation_base: u32,
    pub allocation_protect: u32,
    pub partition_id: u16,
    pub region_size: u32,
    pub state: u32,
    pub protect: u32,
    pub typ: u32,
}

impl MemoryBasicInformation {

    pub fn load(addr:u64, maps:&Maps) -> MemoryBasicInformation {
        MemoryBasicInformation {
            base_address: maps.read_dword(addr).unwrap(),
            allocation_base: maps.read_dword(addr + 4).unwrap(),
            allocation_protect: maps.read_dword(addr + 8).unwrap(),
            partition_id: maps.read_word(addr + 12).unwrap(),
            region_size: maps.read_dword(addr + 14).unwrap(),
            state: maps.read_dword(addr + 18).unwrap(),
            protect: maps.read_dword(addr + 22).unwrap(),
            typ: maps.read_dword(addr + 26).unwrap(),
        }
    }

    pub fn size() -> u64 {
        30
    }

    pub fn save(&self, addr:u64, maps:&mut Maps) {
       maps.write_dword(addr, self.base_address);
       maps.write_dword(addr + 4, self.allocation_base);
       maps.write_dword(addr + 8, self.allocation_protect);
       maps.write_word(addr + 12, self.partition_id);
       maps.write_dword(addr + 14, self.region_size);
       maps.write_dword(addr + 18, self.state);
       maps.write_dword(addr + 22, self.protect);
       maps.write_dword(addr + 26, self.typ);
    }

    pub fn print(&self) {
        println!("{:#x?}", self);
    }
}

