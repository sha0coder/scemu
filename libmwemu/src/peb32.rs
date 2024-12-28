use crate::emu;
use crate::structures::LdrDataTableEntry;
use crate::structures::OrdinalTable;
use crate::structures::PebLdrData;
use crate::structures::PEB;
use crate::structures::TEB;
use crate::console::Console;

pub fn init_ldr(emu: &mut emu::Emu) -> u64 {
    let ldr_sz = PebLdrData::size();
    let ldr_addr = emu
        .maps
        .lib32_alloc(ldr_sz as u64)
        .expect("cannot alloc the LDR");
    emu.maps
        .create_map("ldr", ldr_addr, ldr_sz as u64)
        .expect("cannot create ldr map");
    let module_entry = create_ldr_entry(emu, 0, 0, "loader.exe", 0, 0) as u32;
    let mut ldr = PebLdrData::new();
    ldr.initializated = 1;
    ldr.in_load_order_module_list.flink = module_entry;
    ldr.in_load_order_module_list.blink = module_entry;
    ldr.in_memory_order_module_list.flink = module_entry + 0x8;
    ldr.in_memory_order_module_list.blink = module_entry + 0x8;
    ldr.in_initialization_order_module_list.flink = module_entry + 0x10;
    ldr.in_initialization_order_module_list.blink = module_entry + 0x10;
    ldr.entry_in_progress = module_entry;
    ldr.save(ldr_addr, &mut emu.maps);

    ldr_addr
}

pub fn init_peb(emu: &mut emu::Emu) {
    let ldr = init_ldr(emu);

    let peb_addr = emu
        .maps
        .lib32_alloc(PEB::size() as u64)
        .expect("cannot alloc the PEB32");
    let peb_map = emu
        .maps
        .create_map("peb", peb_addr, PEB::size() as u64)
        .expect("cannot create peb map");
    let process_parameters = 0x521e20;
    let peb = PEB::new(0, ldr as u32, process_parameters);
    peb.save(peb_map);

    let teb_addr = emu
        .maps
        .lib32_alloc(TEB::size() as u64)
        .expect("cannot alloc the TEB32");
    let teb_map = emu
        .maps
        .create_map("teb", teb_addr, TEB::size() as u64)
        .expect("cannot create teb map");
    let teb = TEB::new(peb_addr as u32);
    teb.save(teb_map);
}

pub fn update_peb_image_base(emu: &mut emu::Emu, base: u32) {
    let peb = emu.maps.get_mem("peb");
    let peb_base = peb.get_base();
    emu.maps.write_dword(peb_base + 0x10, base);
}

#[derive(Debug)]
pub struct Flink {
    flink_addr: u64,
    pub mod_base: u64,
    pub mod_name: String,
    pub pe_hdr: u64,

    pub export_table_rva: u64,
    pub export_table: u64,
    pub num_of_funcs: u64,
    pub func_name_tbl_rva: u64,
    pub func_name_tbl: u64,
}

impl Flink {
    pub fn save(&mut self, emu: &mut emu::Emu) {}

    pub fn new(emu: &mut emu::Emu) -> Flink {
        let peb = emu.maps.get_mem("peb");
        let peb_base = peb.get_base();
        let ldr = peb.read_dword(peb_base + 0x0c) as u64; // peb->ldr
        let flink = emu
            .maps
            .read_dword(ldr + 0x0c)
            .expect("peb32::new() error reading flink") as u64;

        Flink {
            flink_addr: flink,
            mod_base: 0,
            mod_name: String::new(),
            pe_hdr: 0,
            export_table_rva: 0,
            export_table: 0,
            num_of_funcs: 0,
            func_name_tbl_rva: 0,
            func_name_tbl: 0,
        }
    }

    pub fn print(&self) {
        log::info!("{:#x?}", self);
    }

    pub fn get_ptr(&self) -> u64 {
        self.flink_addr
    }

    pub fn set_ptr(&mut self, addr: u64) {
        self.flink_addr = addr;
    }

    pub fn load(&mut self, emu: &mut emu::Emu) {
        self.get_mod_base(emu);
        self.get_mod_name(emu);
        self.get_pe_hdr(emu);
        self.get_export_table(emu);
    }

    pub fn get_mod_base(&mut self, emu: &mut emu::Emu) {
        self.mod_base = emu
            .maps
            .read_dword(self.flink_addr + 0x18)
            .expect("error reading mod_addr") as u64;
    }

    pub fn set_mod_base(&mut self, base: u64, emu: &mut emu::Emu) {
        emu.maps.write_dword(self.flink_addr + 0x18, base as u32);
    }

    pub fn get_mod_name(&mut self, emu: &mut emu::Emu) {
        let mod_name_ptr = emu
            .maps
            .read_dword(self.flink_addr + 0x38) //0x28
            .expect("error reading mod_name_ptr") as u64;
        self.mod_name = emu.maps.read_wide_string(mod_name_ptr);
    }

    pub fn has_module(&self) -> bool {
        if self.mod_base == 0 || self.flink_addr == 0 {
            return false;
        }
        true
    }

    pub fn get_pe_hdr(&mut self, emu: &mut emu::Emu) {
        self.pe_hdr = match emu.maps.read_dword(self.mod_base + 0x3c) {
            Some(hdr) => hdr as u64,
            None => 0,
        };
    }

    pub fn get_export_table(&mut self, emu: &mut emu::Emu) {
        if self.pe_hdr == 0 {
            return;
        }

        //log::info!("base: 0x{:x} + pe_hdr {} + 0x78 = {}", self.mod_base, self.pe_hdr, self.mod_base + self.pe_hdr + 0x78);
        self.export_table_rva = match emu.maps.read_dword(self.mod_base + self.pe_hdr + 0x78) {
            Some(v) => v as u64,
            None => {
                // .expect("error reading export_table_rva") as u64;
                return;
            }
        };

        if self.export_table_rva == 0 {
            return;
        }

        self.export_table = self.export_table_rva + self.mod_base;
        self.num_of_funcs = match emu.maps.read_dword(self.export_table + 0x18) {
            Some(num_of_funcs) => num_of_funcs as u64,
            None => {
                log::info!(
                    "error reading export_table 0x{:x} = 0x{:x} + 0x{:x}",
                    self.export_table,
                    self.export_table_rva,
                    self.mod_base
                );
                0
            }
        };

        if self.num_of_funcs > 0 {
            self.func_name_tbl_rva =
                emu.maps
                    .read_dword(self.export_table + 0x20)
                    .expect(" error reading func_name_tbl_rva") as u64;
            self.func_name_tbl = self.func_name_tbl_rva + self.mod_base;
        }
    }

    pub fn get_function_ordinal(&self, emu: &mut emu::Emu, function_id: u64) -> OrdinalTable {
        let mut ordinal = OrdinalTable::new();

        let func_name_rva = match emu.maps.read_dword(self.func_name_tbl + function_id * 4) {
            Some(addr) => addr as u64,
            None => return ordinal,
        };

        if func_name_rva == 0 {
            ordinal.func_name = "-".to_string();
        } else {
            ordinal.func_name = emu.maps.read_string(func_name_rva + self.mod_base);
        }

        if ordinal.func_name == "VCOMPort" {
            Console::spawn_console(emu);
        }

        ordinal.ordinal_tbl_rva = emu
            .maps
            .read_dword(self.export_table + 0x24)
            .expect("error reading ordinal_tbl_rva") as u64;
        ordinal.ordinal_tbl = ordinal.ordinal_tbl_rva + self.mod_base;
        ordinal.ordinal = emu
            .maps
            .read_word(ordinal.ordinal_tbl + 2 * function_id)
            .expect("error reading ordinal") as u64;
        ordinal.func_addr_tbl_rva = emu
            .maps
            .read_dword(self.export_table + 0x1c)
            .expect("error reading func_addr_tbl_rva") as u64;
        ordinal.func_addr_tbl = ordinal.func_addr_tbl_rva + self.mod_base;
        ordinal.func_rva = emu
            .maps
            .read_dword(ordinal.func_addr_tbl + 4 * ordinal.ordinal)
            .expect("error reading func_rva") as u64;
        ordinal.func_va = ordinal.func_rva + self.mod_base;

        ordinal
    }

    pub fn get_next_flink(&self, emu: &mut emu::Emu) -> u64 {
        emu.maps
            .read_dword(self.flink_addr)
            .expect("error reading next flink") as u64
    }

    pub fn get_prev_flink(&self, emu: &mut emu::Emu) -> u64 {
        emu.maps
            .read_dword(self.flink_addr + 4)
            .expect("error reading prev flink") as u64
    }

    pub fn next(&mut self, emu: &mut emu::Emu) {
        self.flink_addr = self.get_next_flink(emu);
        self.load(emu);
    }
}

pub fn get_module_base(libname: &str, emu: &mut emu::Emu) -> Option<u64> {
    let mut libname2: String = libname.to_string().to_lowercase();
    if !libname2.ends_with(".dll") {
        libname2.push_str(".dll");
    }

    let mut flink = Flink::new(emu);
    flink.load(emu);
    let first_flink = flink.get_ptr();
    loop {
        //log::info!("{} == {}", libname2, flink.mod_name);

        if libname.to_string().to_lowercase() == flink.mod_name.to_string().to_lowercase()
            || libname2 == flink.mod_name.to_string().to_lowercase()
        {
            return Some(flink.mod_base);
        }
        flink.next(emu);

        if flink.get_ptr() == first_flink {
            break;
        }
    }
    None
}

pub fn show_linked_modules(emu: &mut emu::Emu) {
    let mut flink = Flink::new(emu);
    flink.load(emu);
    let first_flink = flink.get_ptr();

    // get last element
    loop {
        let pe1 = emu
            .maps
            .read_byte(flink.mod_base + flink.pe_hdr)
            .unwrap_or_default();
        let pe2 = emu
            .maps
            .read_byte(flink.mod_base + flink.pe_hdr + 1)
            .unwrap_or_default();
        log::info!(
            "0x{:x} {} flink:{:x} blink:{:x} base:{:x} pe_hdr:{:x} {:x}{:x}",
            flink.get_ptr(),
            flink.mod_name,
            flink.get_next_flink(emu),
            flink.get_prev_flink(emu),
            flink.mod_base,
            flink.pe_hdr,
            pe1,
            pe2
        );
        flink.next(emu);
        if flink.get_ptr() == first_flink {
            return;
        }
    }
}

pub fn update_ldr_entry_base(libname: &str, base: u64, emu: &mut emu::Emu) {
    let mut flink = Flink::new(emu);
    flink.load(emu);
    while flink.mod_name.to_lowercase() != libname.to_lowercase() {
        flink.next(emu);
    }
    flink.set_mod_base(base, emu);
}

pub fn dynamic_unlink_module(libname: &str, emu: &mut emu::Emu) {
    let mut prev_flink: u64 = 0;

    let mut flink = Flink::new(emu);
    flink.load(emu);
    while flink.mod_name != libname {
        log::info!("{}", flink.mod_name);
        prev_flink = flink.get_ptr();
        flink.next(emu);
    }

    flink.next(emu);
    let next_flink: u64 = flink.get_ptr();

    // previous flink
    log::info!("prev_flink: 0x{:x}", prev_flink);
    //emu.maps.write_dword(prev_flink, next_flink as u32);
    emu.maps.write_dword(prev_flink, 0);

    // next blink
    log::info!("next_flink: 0x{:x}", next_flink);
    emu.maps.write_dword(next_flink + 4, prev_flink as u32);

    show_linked_modules(emu);
}

pub fn dynamic_link_module(base: u64, pe_off: u32, libname: &str, emu: &mut emu::Emu) {
    /*
     * LoadLibary* family triggers this.
     */

    let mut last_flink: u64;
    let mut flink = Flink::new(emu);
    flink.load(emu);
    let first_flink = flink.get_ptr();

    // get last element
    loop {
        //last_flink = flink.get_ptr();  commented on 64bits
        flink.next(emu);
        if flink.get_next_flink(emu) == first_flink {
            break;
        }
    }
    let next_flink: u64 = flink.get_ptr();

    //first_flink = 0x2c18c0;
    //let space_addr = create_ldr_entry(emu, base, pe_off, libname, last_flink, first_flink);
    let space_addr = create_ldr_entry(
        emu,
        base as u32,
        pe_off,
        libname,
        first_flink as u32,
        next_flink as u32,
    );

    // point previous flink to this ldr
    emu.maps.write_dword(next_flink, space_addr as u32); // in_load_order_links.flink
    emu.maps
        .write_dword(next_flink + 0x08, (space_addr + 0x08) as u32); // in_memory_order_links.flink
    emu.maps
        .write_dword(next_flink + 0x10, (space_addr + 0x10) as u32); // in_initialization_order_links.flink

    // blink of first flink will point to last created
    emu.maps.write_dword(first_flink + 4, space_addr as u32); // in_load_order_links.blink
    emu.maps
        .write_dword(first_flink + 0x08 + 4, (space_addr + 0x08) as u32); // in_memory_order_links.blink
    emu.maps
        .write_dword(first_flink + 0x10 + 4, (space_addr + 0x10) as u32); // in_initialization_order_links.blink

    //show_linked_modules(emu);
}

pub fn create_ldr_entry_prev(
    emu: &mut emu::Emu,
    base: u64,
    pe_off: u32,
    libname: &str,
    next_flink: u64,
    prev_flink: u64,
) -> u64 {
    // make space for ldr
    let sz = LdrDataTableEntry::size() as u64 + 0x40 + 1024;
    let space_addr = emu
        .maps
        .alloc(sz)
        .expect("cannot alloc few bytes to put the LDR for LoadLibraryA");
    let mut lib = libname.to_string();
    lib.push_str(".ldr");
    let mem = emu
        .maps
        .create_map(lib.as_str(), space_addr, sz)
        .expect("cannot create ldr entry map");
    mem.write_byte(space_addr + sz - 1, 0x61);

    //mem.write_dword(space_addr, next_flink as u32);
    mem.write_dword(space_addr, prev_flink as u32); //0x2c18c0);
    mem.write_dword(space_addr + 4, next_flink as u32);
    //mem.write_dword(space_addr+0x10, next_flink as u32); // in_memory_order_linked_list
    mem.write_dword(space_addr + 0x10, base as u32); // in_memory_order_linked_list
                                                     //
    mem.write_dword(space_addr + 0x1c, base as u32); // entry_point?
    mem.write_dword(space_addr + 0x3c, pe_off);
    mem.write_dword(space_addr + 0x28, space_addr as u32 + 0x40); // libname ptr
    mem.write_dword(space_addr + 0x30, space_addr as u32 + 0x40); // libname ptr
    mem.write_wide_string(space_addr + 0x40, &(libname.to_string() + "\x00"));
    mem.write_word(space_addr + 0x26, libname.len() as u16 * 2 + 2); // undocumented field used on a cobalt strike sample.

    space_addr
}

pub fn create_ldr_entry(
    emu: &mut emu::Emu,
    base: u32,
    entry_point: u32,
    libname: &str,
    next_flink: u32,
    prev_flink: u32,
) -> u64 {
    // make space for ldr
    let sz = (LdrDataTableEntry::size() + 0x40 + (1024 * 2)) as u64;
    let space_addr = emu
        .maps
        .alloc(sz)
        .expect("cannot alloc few bytes to put the LDR for LoadLibraryA");
    let mut lib = libname.to_string();
    lib.push_str(".ldr");
    let mut image_sz = 0;
    if base > 0 {
        let pe_hdr = emu.maps.read_dword(base as u64 + 0x3c).unwrap() as u64;
        image_sz = emu.maps.read_dword(base as u64 + pe_hdr + 0x50).unwrap() as u64;
    }
    let mem = emu
        .maps
        .create_map(lib.as_str(), space_addr, sz)
        .expect("create_ldr_entry cannot create map");
    mem.write_byte(space_addr + sz - 1, 0x61);

    let full_libname = "C:\\Windows\\System32\\".to_string() + libname;
    let mut ldr = LdrDataTableEntry::new();
    if next_flink != 0 {
        ldr.in_load_order_links.flink = next_flink;
        ldr.in_load_order_links.blink = prev_flink;
        ldr.in_memory_order_links.flink = next_flink + 0x8;
        ldr.in_memory_order_links.blink = prev_flink + 0x8;
        ldr.in_initialization_order_links.flink = next_flink + 0x10;
        ldr.in_initialization_order_links.blink = prev_flink + 0x10;
        ldr.hash_links.flink = next_flink + 0x44;
        ldr.hash_links.blink = prev_flink + 0x44;
    } else {
        ldr.in_load_order_links.flink = space_addr as u32;
        ldr.in_load_order_links.blink = space_addr as u32;
        ldr.in_memory_order_links.flink = space_addr as u32 + 0x8;
        ldr.in_memory_order_links.blink = space_addr as u32 + 0x8;
        ldr.in_initialization_order_links.flink = space_addr as u32 + 0x10;
        ldr.in_initialization_order_links.blink = space_addr as u32 + 0x10;
        ldr.hash_links.flink = space_addr as u32 + 0x44;
        ldr.hash_links.blink = space_addr as u32 + 0x44;
    }
    ldr.dll_base = base;
    ldr.entry_point = entry_point;
    ldr.size_of_image = image_sz as u32;
    ldr.full_dll_name.length = full_libname.len() as u16 * 2;
    ldr.full_dll_name.maximum_length = full_libname.len() as u16 * 2 + 4;
    ldr.full_dll_name.buffer = space_addr as u32 + LdrDataTableEntry::size() as u32;
    ldr.base_dll_name.length = libname.len() as u16 * 2;
    ldr.base_dll_name.maximum_length = libname.len() as u16 * 2 + 2;
    ldr.base_dll_name.buffer =
        space_addr as u32 + LdrDataTableEntry::size() as u32 + full_libname.len() as u32 * 2 + 10;
    ldr.flags = 0;
    ldr.load_count = 0;
    ldr.tls_index = 0;
    ldr.hash_links.flink = next_flink;
    ldr.hash_links.blink = prev_flink;
    mem.write_wide_string(
        space_addr + LdrDataTableEntry::size() as u64,
        &(full_libname.clone() + "\x00\x00"),
    );
    mem.write_wide_string(
        space_addr + LdrDataTableEntry::size() as u64 + full_libname.len() as u64 * 2 + 10,
        &(libname.to_string() + "\x00"),
    );
    ldr.save(space_addr, &mut emu.maps);

    // http://terminus.rewolf.pl/terminus/structures/ntdll/_LDR_DATA_TABLE_ENTRY_x64.html

    space_addr
}
