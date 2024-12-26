use crate::emu;
use crate::emu::structures::LdrDataTableEntry64;
use crate::emu::structures::OrdinalTable;
use crate::emu::structures::PEB64;
use crate::emu::structures::TEB64;
use crate::emu::structures::PebLdrData64;

pub fn init_ldr(emu: &mut emu::Emu) -> u64 {
    let ldr_sz = PebLdrData64::size();
    let ldr_addr = emu.maps.lib64_alloc(ldr_sz as u64).expect("cannot alloc the LDR");
    emu.maps.create_map("ldr", ldr_addr, ldr_sz as u64).expect("cannot create ldr map");
    let module_entry = create_ldr_entry(emu, 0, 0, "loader.exe", 0, 0);
    let mut ldr = PebLdrData64::new();
    ldr.initializated = 1;
    ldr.in_load_order_module_list.flink = module_entry;
    ldr.in_load_order_module_list.blink = module_entry;
    ldr.in_memory_order_module_list.flink = module_entry+0x10;
    ldr.in_memory_order_module_list.blink = module_entry+0x10;
    ldr.in_initialization_order_module_list.flink = module_entry+0x20;
    ldr.in_initialization_order_module_list.blink = module_entry+0x20;
    ldr.entry_in_progress.flink = module_entry;
    ldr.entry_in_progress.blink = module_entry;
    ldr.save(ldr_addr, &mut emu.maps);

    return ldr_addr;
}

pub fn init_peb(emu: &mut emu::Emu) {
    let ldr = init_ldr(emu);

    let peb_addr = emu.maps.lib64_alloc(PEB64::size() as u64).expect("cannot alloc the PEB64");
    let mut peb_map = emu.maps.create_map("peb", peb_addr, PEB64::size() as u64).expect("cannot create peb map");
    let process_parameters = 0x521e20;
    let peb = PEB64::new(0, ldr, process_parameters);
    peb.save(&mut peb_map);
    emu.maps.write_byte(peb_addr + 2, 0); // not being_debugged

    let teb_addr = emu.maps.lib64_alloc(TEB64::size() as u64).expect("cannot alloc the TEB64");
    let mut teb_map = emu.maps.create_map("teb", teb_addr, TEB64::size() as u64).expect("cannot create teb map");
    let teb = TEB64::new(peb_addr);
    teb.save(&mut teb_map);

}

pub fn update_peb_image_base(emu: &mut emu::Emu, base: u64) {
    let peb = emu.maps.get_mem("peb");
    let peb_base = peb.get_base();
    emu.maps.write_qword(peb_base + 0x10, base);
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
    pub fn new(emu: &mut emu::Emu) -> Flink {
        let peb = emu.maps.get_mem("peb");
        let peb_base = peb.get_base();
        let ldr = peb.read_qword(peb_base + 0x18); // peb->ldr
        let flink = emu
            .maps
            .read_qword(ldr + 0x10)
            .expect("peb64::new() error reading flink");

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
        return self.flink_addr;
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
            .read_qword(self.flink_addr + 0x30)
            .expect("error reading mod_addr");
    }

    pub fn set_mod_base(&mut self, base: u64, emu: &mut emu::Emu) {
        self.mod_base = base;
        emu.maps.write_qword(self.flink_addr + 0x30, base);
    }

    pub fn get_mod_name(&mut self, emu: &mut emu::Emu) {
        let mod_name_ptr = emu
            .maps
            .read_qword(self.flink_addr + 0x60)
            .expect("error reading mod_name_ptr");
        self.mod_name = emu.maps.read_wide_string(mod_name_ptr);
    }

    pub fn has_module(&self) -> bool {
        if self.mod_base == 0 || self.flink_addr == 0 {
            return false;
        }
        return true;
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

        //log::info!("mod_base 0x{:x} pe_hdr 0x{:x}", self.mod_base, self.pe_hdr);

        self.export_table_rva = match emu
            .maps
            .read_dword(self.mod_base + self.pe_hdr + 0x88) {
            Some(rva) => rva as u64,
            None => 0,
        };

        if self.export_table_rva == 0 {
            return;
        }

        self.export_table = self.export_table_rva + self.mod_base;

        ////////
        /*
        emu.maps.print_maps();
        log::info!("rva: 0x{:x} = 0x{:x} + 0x{:x} + 0x88 -> 0x{:x}", 
            self.mod_base+self.pe_hdr+0x88,
            self.mod_base,
            self.pe_hdr,
            self.export_table_rva);
        log::info!("export_table: 0x{:x} = 0x{:x} + 0x{:x}",
            self.export_table,
            self.mod_base,
            self.export_table_rva);
        log::info!("num_of_funcs [0x{:x} + 0x18] = [0x{:x}]", 
            self.export_table,
            self.export_table+0x18);
        */


        self.num_of_funcs = emu
            .maps
            .read_dword(self.export_table + 0x18)
            .expect("error reading the num_of_funcs") as u64;
        self.func_name_tbl_rva = emu
            .maps
            .read_dword(self.export_table + 0x20)
            .expect(" error reading func_name_tbl_rva") as u64;
        self.func_name_tbl = self.func_name_tbl_rva + self.mod_base;
    }

    pub fn get_function_ordinal(&self, emu: &mut emu::Emu, function_id: u64) -> OrdinalTable {
        let mut ordinal = OrdinalTable::new();
        let func_name_rva = emu
            .maps
            .read_dword(self.func_name_tbl + function_id * 4)
            .expect("error reading func_rva") as u64;
        ordinal.func_name = emu.maps.read_string(func_name_rva + self.mod_base);
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
        return emu
            .maps
            .read_qword(self.flink_addr)
            .expect("error reading next flink") as u64;
    }

    pub fn get_prev_flink(&self, emu: &mut emu::Emu) -> u64 {
        return emu
            .maps
            .read_qword(self.flink_addr + 8)
            .expect("error reading prev flink") as u64;
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
    return None;
}

pub fn show_linked_modules(emu: &mut emu::Emu) {
    let mut flink = Flink::new(emu);
    flink.load(emu);
    let first_flink = flink.get_ptr();

    // get last element
    loop {
        let pe1 = match emu.maps.read_byte(flink.mod_base + flink.pe_hdr) {
            Some(b) => b,
            None => 0,
        };
        let pe2 = match emu.maps.read_byte(flink.mod_base + flink.pe_hdr + 1) {
            Some(b) => b,
            None => 0,
        };
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
    let next_flink: u64;

    let mut flink = Flink::new(emu);
    flink.load(emu);
    while flink.mod_name != libname {
        log::info!("{}", flink.mod_name);
        prev_flink = flink.get_ptr();
        flink.next(emu);
    }

    flink.next(emu);
    next_flink = flink.get_ptr();

    // previous flink
    log::info!("prev_flink: 0x{:x}", prev_flink);
    //emu.maps.write_qword(prev_flink, next_flink);
    emu.maps.write_qword(prev_flink, 0);

    // next blink
    log::info!("next_flink: 0x{:x}", next_flink);
    emu.maps.write_qword(next_flink + 4, prev_flink);

    show_linked_modules(emu);
}

pub fn dynamic_link_module(base: u64, pe_off: u32, libname: &str, emu: &mut emu::Emu) {
    /*
     * LoadLibary* family triggers this.
     */
    //log::info!("************ dynamic_link_module {}", libname);
    let mut last_flink: u64;
    let mut flink = Flink::new(emu);
    flink.load(emu);
    let first_flink = flink.get_ptr();

    // get last element
    loop {
        //last_flink = flink.get_ptr();
        flink.next(emu);
        if flink.get_next_flink(emu) == first_flink {
            break;
        }
    }
    let next_flink: u64 = flink.get_ptr();

    //log::info!("last: {} {:x}", flink.mod_name, next_flink);

    //let space_addr = create_ldr_entry(emu, base, pe_off, libname, last_flink, first_flink);
    let space_addr = create_ldr_entry(emu, base, pe_off.into(), libname, first_flink, next_flink /*first_flink*/);
    //TODO: pe_off is entry point

    // point previous flink to this ldr
    //let repl1 = emu.maps.read_qword(next_flink).unwrap();
    emu.maps.write_qword(next_flink, space_addr); // in_load_order_links.flink
    emu.maps.write_qword(next_flink+0x10, space_addr+0x10); // in_memory_order_links.flink
    emu.maps.write_qword(next_flink+0x20, space_addr+0x20); // in_initialization_order_links.flink

    // blink of first flink will point to last created
    emu.maps.write_qword(first_flink + 8, space_addr); // in_load_order_links.blink
    emu.maps.write_qword(first_flink+0x10+8, space_addr+0x10); // in_memory_order_links.blink
    emu.maps.write_qword(first_flink+0x20+8, space_addr+0x20); // in_initialization_order_links.blink


    //show_linked_modules(emu);
}

pub fn create_ldr_entry(
    emu: &mut emu::Emu,
    base: u64,
    entry_point: u64,
    libname: &str,
    next_flink: u64,
    prev_flink: u64,
) -> u64 {
    // make space for ldr
    let sz = LdrDataTableEntry64::size() + 0x40 + (1024*2);
    let space_addr = emu
        .maps
        .alloc(sz)
        .expect("cannot alloc few bytes to put the LDR for LoadLibraryA");
    let mut lib = libname.to_string();
    lib.push_str(".ldr");
    let mut image_sz = 0;
    if base > 0 {
        let pe_hdr = emu.maps.read_dword(base as u64 + 0x3c).unwrap() as u64;
        image_sz = emu.maps.read_qword(base as u64 + pe_hdr + 0x50).unwrap() as u64;
    }
    let mem = emu.maps.create_map(lib.as_str(), space_addr, sz).expect("cannot create ldr entry map");
    mem.write_byte(space_addr + sz - 1, 0x61);

    //let full_libname = "\"C:\\Windows\\System32\\".to_string() + &libname.to_string() + "\"\x00";
    let full_libname = "C:\\Windows\\System32\\".to_string() + &libname.to_string();

    let mut ldr = LdrDataTableEntry64::new();
    if next_flink != 0 {
        ldr.in_load_order_links.flink = next_flink;
        ldr.in_load_order_links.blink = prev_flink;
        ldr.in_memory_order_links.flink = next_flink+0x10;
        ldr.in_memory_order_links.blink = prev_flink+0x10;
        ldr.in_initialization_order_links.flink = next_flink+0x20;
        ldr.in_initialization_order_links.blink = prev_flink+0x20;
        ldr.hash_links.flink = next_flink+0x7f;
        ldr.hash_links.blink = prev_flink+0x7f;
    } else {
        ldr.in_load_order_links.flink = space_addr;
        ldr.in_load_order_links.blink = space_addr;
        ldr.in_memory_order_links.flink = space_addr+0x10;
        ldr.in_memory_order_links.blink = space_addr+0x10;
        ldr.in_initialization_order_links.flink = space_addr+0x20;
        ldr.in_initialization_order_links.blink = space_addr+0x20;
        ldr.hash_links.flink = space_addr+0x7f;
        ldr.hash_links.blink = space_addr+0x7f;
    }
    ldr.dll_base = base;
    ldr.entry_point = entry_point;
    ldr.size_of_image = image_sz;
    ldr.full_dll_name.length = full_libname.len() as u16 * 2;
    ldr.full_dll_name.maximum_length = full_libname.len() as u16 * 2 + 4;
    ldr.full_dll_name.buffer = space_addr + LdrDataTableEntry64::size();
    ldr.base_dll_name.length = libname.len() as u16 * 2;
    ldr.base_dll_name.maximum_length = libname.len() as u16 * 2 + 2;
    ldr.base_dll_name.buffer = space_addr + LdrDataTableEntry64::size() + full_libname.len() as u64 * 2 + 10;
    ldr.flags = 0;
    ldr.load_count = 0;
    ldr.tls_index = 0;
    ldr.hash_links.flink = next_flink;
    ldr.hash_links.blink = prev_flink;
    mem.write_wide_string(space_addr + LdrDataTableEntry64::size(), &(full_libname.clone() + "\x00\x00"));
    mem.write_wide_string(space_addr + LdrDataTableEntry64::size() + full_libname.len() as u64 * 2 +10, &(libname.to_string() + "\x00"));
    ldr.save(space_addr, &mut emu.maps);

    // http://terminus.rewolf.pl/terminus/structures/ntdll/_LDR_DATA_TABLE_ENTRY_x64.html

    space_addr
}
