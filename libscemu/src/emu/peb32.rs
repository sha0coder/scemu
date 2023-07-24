use crate::emu;
use crate::emu::structures::LdrDataTableEntry;
use crate::emu::structures::OrdinalTable;
use crate::emu::structures::PEB;

pub fn init_peb(emu: &mut emu::Emu, first_entry: u64, bin_base: u32) -> u64 {
    let peb_addr = 0x7ffdf000;
    let mut peb_map = emu.maps.create_map("peb");
    peb_map.set_base(peb_addr); //TODO: use allocator
    peb_map.set_size(PEB::size() as u64);

    let ldr = 0x77647880; // ntdll_data for now
    let process_parameters = 0x2c1118; // reserved map for now
    let alt_thunk_list_ptr = 0;
    let reserved7 = 0x773cd568;
    let alt_thunk_list_ptr_32 = 0;
    let post_process_init_routine = 0;
    let session_id = 0;

    let peb = PEB::new(
        ldr as u32,
        process_parameters,
        alt_thunk_list_ptr,
        reserved7,
        alt_thunk_list_ptr_32,
        post_process_init_routine,
        session_id,
    );
    peb.save(&mut peb_map);

    //emu.maps.write_dword(ldr + 24, first_entry as u32);
    emu.maps.write_dword(ldr + 0x14, first_entry as u32);

    if bin_base > 0 {
        let ntdll_data = emu.maps.read_dword(peb_addr + 0xc).unwrap();
        let reserved = emu.maps.read_dword(ntdll_data as u64 + 0xc).unwrap();
        emu.maps.write_dword(reserved as u64 + 0x18, bin_base);
    }
    //let dll_base = emu.maps.read_dword(reserved as u64 + 0x18).unwrap();
    //println!("dll_base: 0x{:x}", dll_base);
    //assert!(1==2);
    //

    // xloader checks the flink + 0x30 of every lib looking for the module name which really it's
    // on flink + 0x28
    let mut flink = Flink::new(emu);
    flink.load(emu);
    let first_flink = flink.get_ptr();
    loop {
        let libname_ptr = emu.maps.read_dword(flink.get_ptr() + 0x28).unwrap();
        let libname = emu.maps.read_wide_string(libname_ptr as u64);
        emu.maps
            .write_dword(flink.get_ptr() + 0x30, libname_ptr as u32);

        flink.next(emu);
        if flink.get_ptr() == first_flink {
            break;
        }
    }

    peb_addr
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
        let ldr = peb.read_dword(peb_base + 0x0c) as u64;
        let flink = emu
            .maps
            .read_dword(ldr + 0x14)
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
        println!("{:#x?}", self);
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
            .read_dword(self.flink_addr + 0x10)
            .expect("error reading mod_addr") as u64;
    }

    pub fn get_mod_name(&mut self, emu: &mut emu::Emu) {
        let mod_name_ptr = emu
            .maps
            .read_dword(self.flink_addr + 0x28) //0x28
            .expect("error reading mod_name_ptr") as u64;
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

        //println!("base: 0x{:x} + pe_hdr {} + 0x78 = {}", self.mod_base, self.pe_hdr, self.mod_base + self.pe_hdr + 0x78);
        self.export_table_rva = emu
            .maps
            .read_dword(self.mod_base + self.pe_hdr + 0x78)
            .expect("error reading export_table_rva") as u64;

        if self.export_table_rva == 0 {
            return;
        }

        self.export_table = self.export_table_rva + self.mod_base;
        self.num_of_funcs = match emu.maps.read_dword(self.export_table + 0x18) {
            Some(num_of_funcs) => num_of_funcs as u64,
            None => {
                println!(
                    "error reading export_table 0x{:x} = 0x{:x} + 0x{:x}",
                    self.export_table, self.export_table_rva, self.mod_base
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
        //.expect("error reading func_rva") as u64;

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
            .read_dword(self.flink_addr)
            .expect("error reading next flink") as u64;
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
        //println!("{} == {}", libname2, flink.mod_name);

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
        println!(
            "0x{:x} {} flink:{:x} base:{:x} pe_hdr:{:x} {:x}{:x}",
            flink.get_ptr(),
            flink.mod_name,
            flink.get_next_flink(emu),
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

pub fn dynamic_unlink_module(libname: &str, emu: &mut emu::Emu) {
    let mut prev_flink: u64 = 0;
    let next_flink: u64;

    let mut flink = Flink::new(emu);
    flink.load(emu);
    while flink.mod_name != libname {
        println!("{}", flink.mod_name);
        prev_flink = flink.get_ptr();
        flink.next(emu);
    }

    flink.next(emu);
    next_flink = flink.get_ptr();

    // previous flink
    println!("prev_flink: 0x{:x}", prev_flink);
    //emu.maps.write_dword(prev_flink, next_flink as u32);
    emu.maps.write_dword(prev_flink, 0);

    // next blink
    println!("next_flink: 0x{:x}", next_flink);
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
        last_flink = flink.get_ptr();
        flink.next(emu);
        if flink.get_next_flink(emu) == first_flink {
            break;
        }
    }
    let next_flink: u64 = flink.get_ptr();

    //first_flink = 0x2c18c0;
    let space_addr = create_ldr_entry(emu, base, pe_off, libname, last_flink, first_flink);

    // point previous flink to this ldr
    emu.maps.write_dword(last_flink, space_addr as u32);

    // point next blink to this ldr
    emu.maps.write_dword(next_flink + 4, space_addr as u32);
}

pub fn create_ldr_entry(
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
    let mem = emu.maps.create_map(lib.as_str());
    mem.set_base(space_addr);
    mem.set_size(sz);
    mem.write_byte(space_addr + sz - 1, 0x61);

    // craft an ldr
    /*
    println!("space_addr: 0x{:x}" , space_addr);
    println!("+0 next_flink: 0x{:x}" , next_flink as u32);
    println!("+4 next_flink: 0x{:x}" , last_flink as u32);
    println!("+1c base:  0x{:x}" , base as u32);
    println!("+3c pe_off: 0x{:x}" , pe_off);
    println!("+28 libname_ptr: 0x{:x}" , space_addr as u32 + 0x3d);
    */

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
