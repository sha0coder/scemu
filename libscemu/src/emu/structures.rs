use crate::emu::maps::mem64::Mem64;
use crate::emu::maps::Maps;

use chrono::prelude::*;

////// PEB / TEB //////

#[derive(Debug)]
pub struct ListEntry {
    flink: u32,
    blink: u32,
}

impl ListEntry {
    pub fn load(addr: u64, maps: &Maps) -> ListEntry {
        ListEntry {
            flink: maps.read_dword(addr).unwrap(),
            blink: maps.read_dword(addr + 4).unwrap(),
        }
    }

    pub fn print(&self) {
        println!("{:#x?}", self);
    }
}

#[derive(Debug)]
pub struct LdrDataTableEntry {
    pub reserved1: [u32; 2],
    pub in_memory_order_module_links: ListEntry, // +8
    pub reserved2: [u32; 2],
    pub dll_base: u32,    // +16 +0x10
    pub entry_point: u32, // +20 +0x14
    pub reserved3: u32,
    pub full_dll_name: u32, // ptr to string +28  +0x1c
    pub reserved4: [u8; 8],
    pub reserved5: [u32; 3],
    pub checksum: u32, // +52  +0x34
    pub reserved6: u32,
    pub time_date_stamp: u32, // +60  +0x3c
}

impl LdrDataTableEntry {
    pub fn size() -> usize {
        return 62;
    }

    pub fn load(addr: u64, maps: &Maps) -> LdrDataTableEntry {
        LdrDataTableEntry {
            reserved1: [
                maps.read_dword(addr).unwrap(),
                maps.read_dword(addr + 4).unwrap(),
            ],
            in_memory_order_module_links: ListEntry::load(addr + 8, &maps),
            reserved2: [
                maps.read_dword(addr + 12).unwrap(),
                maps.read_dword(addr + 16).unwrap(),
            ],
            dll_base: maps.read_dword(addr + 20).unwrap(),
            entry_point: maps.read_dword(addr + 24).unwrap(),
            reserved3: maps.read_dword(addr + 28).unwrap(),
            full_dll_name: maps.read_dword(addr + 32).unwrap(),
            reserved4: [0; 8],
            reserved5: [
                maps.read_dword(addr + 38).unwrap(),
                maps.read_dword(addr + 42).unwrap(),
                maps.read_dword(addr + 46).unwrap(),
            ],
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
    in_load_order_module_list: ListEntry,   // +0x14
    in_memory_order_module_list: ListEntry, // +0x1c
    in_initialization_order_module_list: ListEntry,
    entry_in_progress: ListEntry,
}

impl PebLdrData {
    pub fn load(addr: u64, maps: &Maps) -> PebLdrData {
        PebLdrData {
            length: maps.read_dword(addr).unwrap(),
            initializated: maps.read_dword(addr + 4).unwrap(),
            sshandle: maps.read_dword(addr + 8).unwrap(),
            in_load_order_module_list: ListEntry::load(addr + 12, &maps),
            in_memory_order_module_list: ListEntry::load(addr + 12 + 8, &maps),
            in_initialization_order_module_list: ListEntry::load(addr + 12 + 8 + 8, &maps),
            entry_in_progress: ListEntry::load(addr + 12 + 8 + 8 + 8, &maps),
        }
    }

    pub fn print(&self) {
        println!("{:#x?}", self);
    }
}

#[derive(Debug)]
pub struct OrdinalTable {
    pub func_name: String,
    pub ordinal_tbl_rva: u64,
    pub ordinal_tbl: u64,
    pub ordinal: u64,
    pub func_addr_tbl_rva: u64,
    pub func_addr_tbl: u64,
    pub func_rva: u64,
    pub func_va: u64,
}

impl OrdinalTable {
    pub fn new() -> OrdinalTable {
        OrdinalTable {
            func_name: String::new(),
            ordinal_tbl_rva: 0,
            ordinal_tbl: 0,
            ordinal: 0,
            func_addr_tbl_rva: 0,
            func_addr_tbl: 0,
            func_rva: 0,
            func_va: 0,
        }
    }
}

#[derive(Debug)]
pub struct TEB {
    reserved1: [u32; 12],
    peb: u32,
    reserved2: [u32; 399],
    reserved3: [u8; 1952],
    tls_slots: [u32; 64],
    reserved4: [u8; 8],
    reserved5: [u32; 26],
    reserved_for_ole: u32,
    reserved6: [u32; 4],
    tls_expansion_slots: u32,
}

impl TEB {
    pub fn load(addr: u64, maps: &Maps) -> TEB {
        TEB {
            reserved1: [0; 12],
            peb: maps.read_dword(addr + 48).unwrap(),
            reserved2: [0; 399],
            reserved3: [0; 1952],
            tls_slots: [0; 64], //TODO: read this
            reserved4: [0; 8],
            reserved5: [0; 26],
            reserved_for_ole: maps.read_dword(addr + 3968).unwrap(),
            reserved6: [0; 4],
            tls_expansion_slots: maps.read_dword(addr + 3988).unwrap(),
        }
    }

    pub fn print(&self) {
        println!("{:#x?}", self);
    }
}

#[derive(Debug)]
pub struct PEB {
    reserved1: [u8; 2],
    being_debugged: u8,
    reserved2: u8,
    reserved3: [u32; 2],
    ldr: u32, // ptr to PEB_LDR_DATA  +0x0c
    process_parameters: u32,
    reserved4: [u32; 3],
    alt_thunk_list_ptr: u32,
    reserved5: u32,
    reserved6: u32,
    reserved7: u32,
    reserved8: u32,
    alt_thunk_list_ptr_32: u32, // +52 + 45*4 + 96
    reserved9: [u32; 45],
    reserved10: [u8; 96],
    post_process_init_routine: u32,
    reserved11: [u32; 128],
    reserved12: u32,
    session_id: u32,
}

impl PEB {
    pub fn size() -> usize {
        return 848; // std::mem::size_of_val
    }

    pub fn new(
        ldr: u32,
        process_parameters: u32,
        alt_thunk_list_ptr: u32,
        reserved7: u32,
        alt_thunk_list_ptr_32: u32,
        post_process_init_routine: u32,
        session_id: u32,
    ) -> PEB {
        PEB {
            reserved1: [0; 2],
            being_debugged: 0,
            reserved2: 0,
            reserved3: [0; 2],
            ldr: ldr,
            process_parameters: process_parameters,
            reserved4: [0; 3],
            alt_thunk_list_ptr: alt_thunk_list_ptr,
            reserved5: 0,
            reserved6: 6,
            reserved7: reserved7,
            reserved8: 0,
            alt_thunk_list_ptr_32: alt_thunk_list_ptr_32,
            reserved9: [0; 45],
            reserved10: [0; 96],
            post_process_init_routine: post_process_init_routine,
            reserved11: [0; 128],
            reserved12: 0,
            session_id: session_id,
        }
    }

    pub fn load(addr: u64, maps: &Maps) -> PEB {
        PEB {
            reserved1: [0; 2],
            being_debugged: maps.read_byte(addr + 2).unwrap(),
            reserved2: maps.read_byte(addr + 3).unwrap(),
            reserved3: [
                maps.read_dword(addr + 4).unwrap(),
                maps.read_dword(addr + 8).unwrap(),
            ],
            ldr: maps.read_dword(addr + 12).unwrap(),
            process_parameters: maps.read_dword(addr + 16).unwrap(),
            reserved4: [
                maps.read_dword(addr + 20).unwrap(),
                maps.read_dword(addr + 24).unwrap(),
                maps.read_dword(addr + 28).unwrap(),
            ],
            alt_thunk_list_ptr: maps.read_dword(addr + 32).unwrap(),
            reserved5: maps.read_dword(addr + 36).unwrap(),
            reserved6: maps.read_dword(addr + 40).unwrap(),
            reserved7: maps.read_dword(addr + 44).unwrap(),
            reserved8: maps.read_dword(addr + 48).unwrap(),
            alt_thunk_list_ptr_32: maps.read_dword(addr + 52).unwrap(),
            reserved9: [0; 45],
            reserved10: [0; 96],
            post_process_init_routine: maps.read_dword(addr + 328).unwrap(),
            reserved11: [0; 128],
            reserved12: maps.read_dword(addr + 840).unwrap(),
            session_id: maps.read_dword(addr + 844).unwrap(),
        }
    }

    pub fn set_image_base(&mut self, image_base: u32) {
        self.reserved3[1] = image_base;
    }

    pub fn save(&self, mem: &mut Mem64) {
        let base = mem.get_base();
        mem.write_byte(base, self.reserved1[0]);
        mem.write_byte(base + 1, self.reserved1[1]);
        mem.write_byte(base + 2, self.being_debugged);
        mem.write_byte(base + 3, self.reserved2);
        mem.write_dword(base + 4, self.reserved3[0]);
        mem.write_dword(base + 8, self.reserved3[1]);
        mem.write_dword(base + 12, self.ldr);
        mem.write_dword(base + 16, self.process_parameters);
        mem.write_dword(base + 20, self.reserved4[0]);
        mem.write_dword(base + 24, self.reserved4[1]);
        mem.write_dword(base + 28, self.reserved4[2]);
        mem.write_dword(base + 32, self.alt_thunk_list_ptr);
        mem.write_dword(base + 36, self.reserved5);
        mem.write_dword(base + 40, self.reserved6);
        mem.write_dword(base + 44, self.reserved7);
        mem.write_dword(base + 48, self.reserved8);
        mem.write_dword(base + 52, self.alt_thunk_list_ptr_32);

        mem.write_dword(base + 328, self.post_process_init_routine);

        mem.write_dword(base + 840, self.reserved12);
        mem.write_dword(base + 844, self.session_id);
    }

    pub fn print(&self) {
        println!("{:#x?}", self);
    }
}

// 64bits
// https://bytepointer.com/resources/tebpeb64.htm   (from xp to win8)
// https://www.tssc.de/winint/Win10_19042_ntoskrnl/_PEB64.htm (win10)

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
    minimum_stack_commit: u64,
}

impl PEB64 {
    pub fn size() -> usize {
        return 800; // std::mem::size_of_val
    }

    pub fn new(image_base_addr: u64, ldr: u64, process_parameters: u64) -> PEB64 {
        PEB64 {
            inheritet_addr_space: 0x0,
            read_img_file_exec_options: 0x0,
            being_debugged: 0x0,
            system_dependent_01: 0x0,
            dummy_align: 0x0,
            mutant: 0xffffffffffffffff,
            image_base_addr: image_base_addr,
            ldr: ldr,
            process_parameters: process_parameters,
            subsystem_data: 0x0,
            process_heap: 0x520000,
            fast_peb_lock: 0x7710a900,
            system_dependent_02: 0x0,
            system_dependent_03: 0x0,
            system_dependent_04: 0x2,
            kernel_callback_table: 0x76f59500,
            system_reserved: 0x0,
            system_dependent_05: 0x0,
            system_dependent_06: 0x7feff2f0000,
            tls_expansion_counter: 0x0,
            tls_bitmap: 0x77102590,
            tls_bitmap_bits: [0x1fff, 0x0],
            read_only_shared_memory_base: 0x7efe0000,
            system_dependent_07: 0x0,
            read_only_static_server_data: 0x7efe0a90,
            ansi_code_page_data: 0x7fffffb0000,
            oem_code_page_data: 0x7fffffc0228,
            unicode_case_table_data: 0x7fffffd0650,
            number_of_processors: 0x1,
            nt_global_flag: 0x70,
            critical_section_timeout: 0xffffe86d079b8000,
            heap_segment_reserve: 0x100000,
            heap_segment_commit: 0x2000,
            heap_decommit_total_free_threshold: 0x10000,
            heap_decommit_free_block_threshold: 0x10000,
            number_of_heaps: 0x4,
            max_number_of_heaps: 0x10,
            process_heaps: 0x7710a6c0,
            gdi_share_handle_table: 0x920000,
            process_starter_helper: 0x0,
            gdi_dc_attribute_list: 0x14,
            loader_lock: 0x77107490,
            os_major_version: 0x6,
            os_minor_version: 0x1,
            os_build_number: 0x1db1,
            oscsd_version: 0x100,
            os_platform_id: 0x2,
            image_subsystem: 0x3,
            image_subsystem_major_version: 0x5,
            image_subsystem_minor_version: 0x2,
            active_process_afinity_mask: 0x1,
            gdi_handle_buffer: [
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            ],
            post_process_init_routine: 0x0,
            tls_expansion_bitmap: 0x77102580,
            tls_expansion_bitmap_bits: [
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            ],
            session_id: 0x1,
            app_compat_flags: 0x0,
            app_compat_flags_user: 0x0,
            p_shim_data: 0x0,
            app_compat_info: 0x0,
            csd_version: [0x1e001c, 0x7efe0afa],
            activate_context_data: 0x0,
            process_assembly_storage_map: 0x0,
            system_default_activation_context_data: 0x230000,
            system_assembly_storage_map: 0x0,
            minimum_stack_commit: 0x0,
        }
    }

    pub fn load(addr: u64, maps: &Maps) -> PEB64 {
        PEB64 {
            inheritet_addr_space: maps.read_byte(addr).unwrap(),
            read_img_file_exec_options: maps.read_byte(addr + 0x1).unwrap(),
            being_debugged: maps.read_byte(addr + 0x2).unwrap(),
            system_dependent_01: maps.read_byte(addr + 0x3).unwrap(),
            dummy_align: 0,
            mutant: maps.read_qword(addr + 0x8).unwrap(),
            image_base_addr: maps.read_qword(addr + 0x10).unwrap(),
            ldr: maps.read_qword(addr + 0x18).unwrap(),
            process_parameters: maps.read_qword(addr + 0x20).unwrap(),
            subsystem_data: maps.read_qword(addr + 0x28).unwrap(),
            process_heap: maps.read_qword(addr + 0x30).unwrap(),
            fast_peb_lock: maps.read_qword(addr + 0x38).unwrap(),
            system_dependent_02: maps.read_qword(addr + 0x40).unwrap(),
            system_dependent_03: maps.read_qword(addr + 0x48).unwrap(),
            system_dependent_04: maps.read_qword(addr + 0x50).unwrap(),
            kernel_callback_table: maps.read_qword(addr + 0x58).unwrap(),
            system_reserved: maps.read_dword(addr + 0x60).unwrap(),
            system_dependent_05: maps.read_dword(addr + 0x64).unwrap(),
            system_dependent_06: maps.read_qword(addr + 0x68).unwrap(),
            tls_expansion_counter: maps.read_qword(addr + 0x70).unwrap(),
            tls_bitmap: maps.read_qword(addr + 0x78).unwrap(),
            tls_bitmap_bits: [
                maps.read_dword(addr + 0x80).unwrap(),
                maps.read_dword(addr + 0x84).unwrap(),
            ],
            read_only_shared_memory_base: maps.read_qword(addr + 0x88).unwrap(),
            system_dependent_07: maps.read_qword(addr + 0x90).unwrap(),
            read_only_static_server_data: maps.read_qword(addr + 0x98).unwrap(),
            ansi_code_page_data: maps.read_qword(addr + 0xa0).unwrap(),
            oem_code_page_data: maps.read_qword(addr + 0xa8).unwrap(),
            unicode_case_table_data: maps.read_qword(addr + 0xb0).unwrap(),
            number_of_processors: maps.read_dword(addr + 0xb8).unwrap(),
            nt_global_flag: maps.read_dword(addr + 0xbc).unwrap(),
            critical_section_timeout: maps.read_qword(addr + 0xc0).unwrap(),
            heap_segment_reserve: maps.read_qword(addr + 0xc8).unwrap(),
            heap_segment_commit: maps.read_qword(addr + 0xd0).unwrap(),
            heap_decommit_total_free_threshold: maps.read_qword(addr + 0xd8).unwrap(),
            heap_decommit_free_block_threshold: maps.read_qword(addr + 0xd8).unwrap(),
            number_of_heaps: maps.read_dword(addr + 0xe8).unwrap(),
            max_number_of_heaps: maps.read_dword(addr + 0xec).unwrap(),
            process_heaps: maps.read_qword(addr + 0xf0).unwrap(),
            gdi_share_handle_table: maps.read_qword(addr + 0xf8).unwrap(),
            process_starter_helper: maps.read_qword(addr + 0x100).unwrap(),
            gdi_dc_attribute_list: maps.read_qword(addr + 0x108).unwrap(),
            loader_lock: maps.read_qword(addr + 0x110).unwrap(),
            os_major_version: maps.read_dword(addr + 0x118).unwrap(),
            os_minor_version: maps.read_dword(addr + 0x11c).unwrap(),
            os_build_number: maps.read_word(addr + 0x120).unwrap(),
            oscsd_version: maps.read_word(addr + 0x122).unwrap(),
            os_platform_id: maps.read_dword(addr + 0x124).unwrap(),
            image_subsystem: maps.read_dword(addr + 0x128).unwrap(),
            image_subsystem_major_version: maps.read_dword(addr + 0x12c).unwrap(),
            image_subsystem_minor_version: maps.read_qword(addr + 0x130).unwrap(),
            active_process_afinity_mask: maps.read_qword(addr + 0x138).unwrap(),
            gdi_handle_buffer: [0; 30],
            post_process_init_routine: maps.read_qword(addr + 0x230).unwrap(),
            tls_expansion_bitmap: maps.read_qword(addr + 0x238).unwrap(),
            tls_expansion_bitmap_bits: [0; 32],
            session_id: maps.read_qword(addr + 0x2c0).unwrap(),
            app_compat_flags: maps.read_qword(addr + 0x2c8).unwrap(),
            app_compat_flags_user: maps.read_qword(addr + 0x2d0).unwrap(),
            p_shim_data: maps.read_qword(addr + 0x2d8).unwrap(),
            app_compat_info: maps.read_qword(addr + 0x2e0).unwrap(),
            csd_version: [
                maps.read_qword(addr + 0x2e8).unwrap(),
                maps.read_qword(addr + 0x2f0).unwrap(),
            ],
            activate_context_data: maps.read_qword(addr + 0x2f8).unwrap(),
            process_assembly_storage_map: maps.read_qword(addr + 0x300).unwrap(),
            system_default_activation_context_data: maps.read_qword(addr + 0x308).unwrap(),
            system_assembly_storage_map: maps.read_qword(addr + 0x310).unwrap(),
            minimum_stack_commit: maps.read_qword(addr + 0x318).unwrap(),
        }
    }

    pub fn save(&self, mem: &mut Mem64) {
        let base = mem.get_base();
        mem.write_byte(base, self.inheritet_addr_space);
        mem.write_byte(base + 1, self.read_img_file_exec_options);
        mem.write_byte(base + 2, self.being_debugged);
        mem.write_byte(base + 3, self.system_dependent_01);
        mem.write_dword(base + 4, self.dummy_align);
        mem.write_qword(base + 8, self.mutant);
        mem.write_qword(base + 16, self.image_base_addr);
        mem.write_qword(base + 24, self.ldr);
        mem.write_qword(base + 32, self.process_parameters);
        mem.write_qword(base + 40, self.subsystem_data);
        mem.write_qword(base + 48, self.process_heap);
        mem.write_qword(base + 56, self.fast_peb_lock);
        mem.write_qword(base + 64, self.system_dependent_02);
        mem.write_qword(base + 72, self.system_dependent_03);
        mem.write_qword(base + 80, self.system_dependent_04);
        mem.write_qword(base + 88, self.kernel_callback_table);
        mem.write_dword(base + 96, self.system_reserved);
        mem.write_dword(base + 100, self.system_dependent_05);
        mem.write_qword(base + 104, self.system_dependent_06);
        mem.write_qword(base + 112, self.tls_expansion_counter);
        mem.write_qword(base + 120, self.tls_bitmap);
        mem.write_dword(base + 128, self.tls_bitmap_bits[0]);
        mem.write_dword(base + 132, self.tls_bitmap_bits[1]);
        mem.write_qword(base + 136, self.read_only_shared_memory_base);
        mem.write_qword(base + 144, self.system_dependent_07);
        mem.write_qword(base + 152, self.read_only_static_server_data);
        mem.write_qword(base + 160, self.ansi_code_page_data);
        mem.write_qword(base + 168, self.oem_code_page_data);
        mem.write_qword(base + 176, self.unicode_case_table_data);
        mem.write_dword(base + 184, self.number_of_processors);
        mem.write_dword(base + 188, self.nt_global_flag);
        mem.write_qword(base + 192, self.critical_section_timeout);
        mem.write_qword(base + 200, self.heap_segment_reserve);
        mem.write_qword(base + 208, self.heap_segment_commit);
        mem.write_qword(base + 216, self.heap_decommit_total_free_threshold);
        mem.write_qword(base + 224, self.heap_decommit_free_block_threshold);
        mem.write_dword(base + 232, self.number_of_heaps);
        mem.write_dword(base + 236, self.max_number_of_heaps);
        mem.write_qword(base + 240, self.process_heaps);
        mem.write_qword(base + 248, self.gdi_share_handle_table);
        mem.write_qword(base + 256, self.process_starter_helper);
        mem.write_qword(base + 264, self.gdi_dc_attribute_list);
        mem.write_qword(base + 272, self.loader_lock);
        mem.write_dword(base + 280, self.os_major_version);
        mem.write_dword(base + 284, self.os_minor_version);
        mem.write_word(base + 288, self.os_build_number);
        mem.write_word(base + 290, self.oscsd_version);
        mem.write_dword(base + 292, self.os_platform_id);
        mem.write_dword(base + 296, self.image_subsystem);
        mem.write_dword(base + 300, self.image_subsystem_major_version);
        mem.write_qword(base + 304, self.image_subsystem_minor_version);
        mem.write_qword(base + 312, self.active_process_afinity_mask);
        let mut idx = base + 312 + 8;
        for i in 0..30 {
            mem.write_qword(idx, self.gdi_handle_buffer[i as usize]);
            idx += 8;
        }
        mem.write_qword(idx, self.post_process_init_routine);
        mem.write_qword(idx + 8, self.tls_expansion_bitmap);
        idx += 8;
        for i in 0..32 {
            mem.write_dword(idx, self.tls_expansion_bitmap_bits[i]);
            idx += 4;
        }
        mem.write_qword(idx, self.session_id);
        mem.write_qword(idx + 8, self.app_compat_flags);
        mem.write_qword(idx + 16, self.app_compat_flags_user);
        mem.write_qword(idx + 24, self.p_shim_data);
        mem.write_qword(idx + 32, self.app_compat_info);
        mem.write_qword(idx + 40, self.csd_version[0]);
        mem.write_qword(idx + 48, self.csd_version[1]);
        mem.write_qword(idx + 56, self.activate_context_data);
        mem.write_qword(idx + 64, self.process_assembly_storage_map);
        mem.write_qword(idx + 72, self.system_default_activation_context_data);
        mem.write_qword(idx + 80, self.system_assembly_storage_map);
        mem.write_qword(idx + 88, self.minimum_stack_commit);
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
    process_environment_block: u64, // PEB64
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
    activation_context_stack_pointer: u64,
}

impl TEB64 {
    pub fn load(addr: u64, maps: &Maps) -> TEB64 {
        TEB64 {
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
            activation_context_stack_pointer: maps.read_qword(addr + 0x2c8).unwrap(),
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
    hash_links: u64,
}

impl LdrDataTableEntry64 {
    pub fn size() -> u64 {
        return 120;
    }

    pub fn load(addr: u64, maps: &Maps) -> LdrDataTableEntry64 {
        LdrDataTableEntry64 {
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
            hash_links: maps.read_qword(addr + 0x70).unwrap(),
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
    address_of_ordinals: u32,
}

impl ImageExportDirectory {
    pub fn load(addr: u64, maps: &Maps) -> ImageExportDirectory {
        ImageExportDirectory {
            characteristics: maps.read_dword(addr).unwrap(),
            time_date_stamp: maps.read_dword(addr + 4).unwrap(),
            major_version: maps.read_word(addr + 8).unwrap(),
            minor_version: maps.read_word(addr + 10).unwrap(),
            name: maps.read_dword(addr + 12).unwrap(),
            base: maps.read_dword(addr + 16).unwrap(),
            number_of_functions: maps.read_dword(addr + 20).unwrap(),
            number_of_names: maps.read_dword(addr + 24).unwrap(),
            address_of_functions: maps.read_dword(addr + 28).unwrap(),
            address_of_names: maps.read_dword(addr + 32).unwrap(),
            address_of_ordinals: maps.read_dword(addr + 36).unwrap(),
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
    pub fn load(addr: u64, maps: &Maps) -> PScopeTableEntry {
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
    pub fn load(addr: u64, maps: &Maps) -> CppEhRecord {
        CppEhRecord {
            old_esp: maps.read_dword(addr).unwrap(),
            exc_ptr: maps.read_dword(addr + 4).unwrap(),
            next: maps.read_dword(addr + 8).unwrap(),
            exception_handler: maps.read_dword(addr + 12).unwrap(),
            scope_table: PScopeTableEntry::load(addr + 16, &maps),
            try_level: maps
                .read_dword(addr + 16 + PScopeTableEntry::size())
                .unwrap(),
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
    pub fn load(addr: u64, maps: &Maps) -> ExceptionPointers {
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
    pub fn load(addr: u64, maps: &Maps) -> Eh3ExceptionRegistration {
        Eh3ExceptionRegistration {
            next: maps.read_dword(addr).unwrap(),
            exception_handler: maps.read_dword(addr + 4).unwrap(),
            scope_table: PScopeTableEntry::load(addr + 8, &maps),
            try_level: maps
                .read_dword(addr + 8 + PScopeTableEntry::size())
                .unwrap(),
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
    pub fn guess(addr: u64, maps: &mut Maps) -> MemoryBasicInformation {
        match maps.get_mem_by_addr(addr) {
            Some(mem) => MemoryBasicInformation {
                base_address: mem.get_base() as u32,
                allocation_base: mem.get_base() as u32,
                allocation_protect: 0xff,
                partition_id: 0,
                region_size: mem.size() as u32,
                state: 0,
                protect: 0xff,
                typ: 0,
            },
            None => MemoryBasicInformation {
                base_address: 0,
                allocation_base: 0,
                allocation_protect: 0xff,
                partition_id: 0,
                region_size: 0,
                state: 0,
                protect: 0xff,
                typ: 0,
            },
        }
    }

    pub fn load(addr: u64, maps: &Maps) -> MemoryBasicInformation {
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

    pub fn save(&self, addr: u64, maps: &mut Maps) {
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

// TLS

#[derive(Debug)]
pub struct TlsDirectory32 {
    tls_data_start: u32,
    tls_data_end: u32,
    tls_index: u32, // DS:[FS:[2Ch]] + tls_index *4
    tls_callbacks: u32,
    zero_fill_size: u32, // size = tls_data_end - tls_data_start + zero_fill_size
    characteristic: u32,
}

impl TlsDirectory32 {
    pub fn load(addr: u64, maps: &Maps) -> TlsDirectory32 {
        TlsDirectory32 {
            tls_data_start: maps.read_dword(addr).unwrap(),
            tls_data_end: maps.read_dword(addr + 4).unwrap(),
            tls_index: maps.read_dword(addr + 8).unwrap(),
            tls_callbacks: maps.read_dword(addr + 12).unwrap(),
            zero_fill_size: maps.read_dword(addr + 16).unwrap(),
            characteristic: maps.read_dword(addr + 20).unwrap(),
        }
    }

    pub fn print(&self) {
        println!("{:#x?}", self);
    }
}

#[derive(Debug)]
pub struct TlsDirectory64 {
    tls_data_start: u64,
    tls_data_end: u64,
    tls_index: u64, // DS:[FS:[2Ch]] + tls_index *4
    tls_callbacks: u64,
    zero_fill_size: u32, // size = tls_data_end - tls_data_start + zero_fill_size
    characteristic: u32,
}

impl TlsDirectory64 {
    pub fn load(addr: u64, maps: &Maps) -> TlsDirectory64 {
        TlsDirectory64 {
            tls_data_start: maps.read_qword(addr).unwrap(),
            tls_data_end: maps.read_qword(addr + 8).unwrap(),
            tls_index: maps.read_qword(addr + 16).unwrap(),
            tls_callbacks: maps.read_qword(addr + 24).unwrap(),
            zero_fill_size: maps.read_dword(addr + 32).unwrap(),
            characteristic: maps.read_dword(addr + 34).unwrap(),
        }
    }

    pub fn print(&self) {
        println!("{:#x?}", self);
    }
}

#[derive(Debug)]
pub struct ImageTlsCallback {
    // every tls callback has this structure
    dll_handle: u32,
    reason: u32,
    reserved: u32,
}

#[derive(Debug)]
pub struct OsVersionInfo {
    version_info_size: u32,
    major_version: u32,
    minor_version: u32,
    build_number: u32,
    platform_id: u32,
    version: [u8; 128],
}

impl OsVersionInfo {
    pub fn new() -> OsVersionInfo {
        let mut ovi = OsVersionInfo {
            version_info_size: 284,
            major_version: 10,
            minor_version: 0,
            build_number: 19042,
            platform_id: 2,
            version: [0; 128],
        };

        "Service Pack 0"
            .as_bytes()
            .iter()
            .enumerate()
            .for_each(|(i, &byte)| {
                ovi.version[i] = byte;
            });

        ovi
    }

    pub fn save(&self, addr: u64, maps: &mut Maps) {
        maps.write_dword(addr, self.version_info_size);
        maps.write_dword(addr + 4, self.major_version);
        maps.write_dword(addr + 8, self.minor_version);
        maps.write_dword(addr + 12, self.build_number);
        maps.write_dword(addr + 16, self.platform_id);
        maps.write_buffer(addr + 20, &self.version);
    }
}

#[derive(Debug)]
pub struct SystemTime {
    year: u16,
    month: u16,
    day_of_week: u16,
    day: u16,
    hour: u16,
    minute: u16,
    second: u16,
    millis: u16,
}

impl SystemTime {
    pub fn now() -> SystemTime {
        let now = Utc::now();
        let systime = SystemTime {
            year: now.year() as u16,
            month: now.month() as u16,
            day_of_week: now.weekday() as u16,
            day: now.day() as u16,
            hour: now.hour() as u16,
            minute: now.minute() as u16,
            second: now.second() as u16,
            millis: now.timestamp_millis() as u16,
        };

        return systime;
    }

    pub fn save(&self, addr: u64, maps: &mut Maps) {
        maps.write_word(addr, self.year);
        maps.write_word(addr + 2, self.month);
        maps.write_word(addr + 4, self.day_of_week);
        maps.write_word(addr + 6, self.day);
        maps.write_word(addr + 8, self.hour);
        maps.write_word(addr + 10, self.minute);
        maps.write_word(addr + 12, self.second);
        maps.write_word(addr + 14, self.millis);
    }
}

#[derive(Debug)]
pub struct StartupInfo32 {
    cb: u32,
    reserved: u32,
    desktop: u32,
    title: u32,
    x: u32,
    y: u32,
    x_size: u32,
    y_size: u32,
    x_count_chars: u32,
    y_count_chars: u32,
    fill_attribute: u32,
    flags: u32,
    show_window: u16,
    cb_reserved2: u16,
    lp_reserved2: u32,
    std_input: u32,
    std_output: u32,
    std_error: u32,
}

impl StartupInfo32 {
    pub fn new() -> StartupInfo32 {
        StartupInfo32 {
            cb: 68,
            reserved: 0,
            desktop: 0,
            title: 0,
            x: 10,
            y: 10,
            x_size: 300,
            y_size: 200,
            x_count_chars: 0,
            y_count_chars: 0,
            fill_attribute: 0,
            flags: 0,
            show_window: 1,
            cb_reserved2: 0,
            lp_reserved2: 0,
            std_input: 0,
            std_output: 0,
            std_error: 0,
        }
    }

    pub fn save(&self, addr: u64, maps: &mut Maps) {
        maps.write_dword(addr, self.cb);
        maps.write_dword(addr + 4, self.reserved);
        maps.write_dword(addr + 8, self.desktop);
        maps.write_dword(addr + 12, self.title);
        maps.write_dword(addr + 16, self.x);
        maps.write_dword(addr + 20, self.y);
        maps.write_dword(addr + 24, self.x_size);
        maps.write_dword(addr + 28, self.y_size);
        maps.write_dword(addr + 32, self.x_count_chars);
        maps.write_dword(addr + 36, self.y_count_chars);
        maps.write_dword(addr + 40, self.fill_attribute);
        maps.write_dword(addr + 44, self.flags);
        maps.write_word(addr + 48, self.show_window);
        maps.write_word(addr + 50, self.cb_reserved2);
        maps.write_dword(addr + 52, self.lp_reserved2);
        maps.write_dword(addr + 56, self.std_input);
        maps.write_dword(addr + 60, self.std_output);
        maps.write_dword(addr + 64, self.std_error);
    }
}

#[derive(Debug)]
pub struct StartupInfo64 {
    cb: u32,
    reserved: u64,
    desktop: u64,
    title: u64,
    x: u32,
    y: u32,
    x_size: u32,
    y_size: u32,
    x_count_chars: u32,
    y_count_chars: u32,
    fill_attribute: u32,
    flags: u32,
    show_window: u16,
    cb_reserved2: u16,
    lp_reserved2: u64,
    std_input: u32,
    std_output: u32,
    std_error: u32,
}

impl StartupInfo64 {
    pub fn new() -> StartupInfo64 {
        StartupInfo64 {
            cb: 84,
            reserved: 0,
            desktop: 0,
            title: 0,
            x: 10,
            y: 10,
            x_size: 300,
            y_size: 200,
            x_count_chars: 0,
            y_count_chars: 0,
            fill_attribute: 0,
            flags: 0,
            show_window: 1,
            cb_reserved2: 0,
            lp_reserved2: 0,
            std_input: 0,
            std_output: 0,
            std_error: 0,
        }
    }

    pub fn save(&self, addr: u64, maps: &mut Maps) {
        maps.write_dword(addr, self.cb);
        maps.write_qword(addr + 4, self.reserved);
        maps.write_qword(addr + 12, self.desktop);
        maps.write_qword(addr + 20, self.title);
        maps.write_dword(addr + 28, self.x);
        maps.write_dword(addr + 32, self.y);
        maps.write_dword(addr + 36, self.x_size);
        maps.write_dword(addr + 40, self.y_size);
        maps.write_dword(addr + 44, self.x_count_chars);
        maps.write_dword(addr + 48, self.y_count_chars);
        maps.write_dword(addr + 52, self.fill_attribute);
        maps.write_dword(addr + 56, self.flags);
        maps.write_word(addr + 60, self.show_window);
        maps.write_word(addr + 62, self.cb_reserved2);
        maps.write_qword(addr + 64, self.lp_reserved2);
        maps.write_dword(addr + 72, self.std_input);
        maps.write_dword(addr + 76, self.std_output);
        maps.write_dword(addr + 80, self.std_error);
    }
}

pub struct SystemInfo32 {
    oem_id: u32,
    processor_architecture: u32,
    reserved: u16,
    page_size: u32,
    min_app_addr: u32,
    max_app_addr: u32,
    active_processor_mask: u32,
    number_of_processors: u32,
    processor_type: u32,
    alloc_granularity: u32,
    processor_level: u16,
    processor_revision: u16,
}

impl SystemInfo32 {
    pub fn new() -> SystemInfo32 {
        SystemInfo32 {
            oem_id: 0x1337,
            processor_architecture: 9,
            reserved: 0,
            page_size: 4090,
            min_app_addr: 0,
            max_app_addr: 0,
            active_processor_mask: 1,
            number_of_processors: 4,
            processor_type: 586,
            alloc_granularity: 65536,
            processor_level: 5,
            processor_revision: 255,
        }
    }

    pub fn save(&mut self, addr: u64, maps: &mut Maps) {
        maps.write_dword(addr, self.oem_id);
        maps.write_dword(addr + 4, self.processor_architecture);
        maps.write_word(addr + 8, self.reserved);
        maps.write_dword(addr + 10, self.page_size);
        maps.write_dword(addr + 14, self.min_app_addr);
        maps.write_dword(addr + 18, self.max_app_addr);
        maps.write_dword(addr + 22, self.active_processor_mask);
        maps.write_dword(addr + 26, self.number_of_processors);
        maps.write_dword(addr + 30, self.processor_type);
        maps.write_dword(addr + 34, self.alloc_granularity);
        maps.write_word(addr + 38, self.processor_level);
        maps.write_word(addr + 40, self.processor_revision);
    }

    pub fn size(&self) -> usize {
        return 42;
    }
}

pub struct SystemInfo64 {
    oem_id: u32,
    processor_architecture: u32,
    reserved: u16,
    page_size: u32,
    min_app_addr: u64,
    max_app_addr: u64,
    active_processor_mask: u64,
    number_of_processors: u32,
    processor_type: u32,
    alloc_granularity: u32,
    processor_level: u16,
    processor_revision: u16,
}

impl SystemInfo64 {
    pub fn new() -> SystemInfo64 {
        SystemInfo64 {
            oem_id: 0x1337,
            processor_architecture: 9,
            reserved: 0,
            page_size: 4090,
            min_app_addr: 0,
            max_app_addr: 0,
            active_processor_mask: 1,
            number_of_processors: 4,
            processor_type: 586,
            alloc_granularity: 65536,
            processor_level: 5,
            processor_revision: 255,
        }
    }

    pub fn save(&mut self, addr: u64, maps: &mut Maps) {
        maps.write_dword(addr, self.oem_id);
        maps.write_dword(addr + 4, self.processor_architecture);
        maps.write_word(addr + 8, self.reserved);
        maps.write_dword(addr + 10, self.page_size);
        maps.write_qword(addr + 14, self.min_app_addr);
        maps.write_qword(addr + 22, self.max_app_addr);
        maps.write_qword(addr + 30, self.active_processor_mask);
        maps.write_dword(addr + 38, self.number_of_processors);
        maps.write_dword(addr + 42, self.processor_type);
        maps.write_dword(addr + 46, self.alloc_granularity);
        maps.write_word(addr + 50, self.processor_level);
        maps.write_word(addr + 52, self.processor_revision);
    }

    pub fn size(&self) -> usize {
        return 54;
    }
}
