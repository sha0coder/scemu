use crate::emu;
use crate::emu::structures::PEB;
use crate::emu::structures::LdrDataTableEntry;

pub fn init_peb(emu:&mut emu::Emu) {
    let mut peb_map = emu.maps.create_map("peb");
    peb_map.set_base(0x7ffdf000); //TODO: use allocator
    peb_map.set_size(PEB::size() as u64);

    let ldr = 0x77647880; // ntdll_data for now
    let process_parameters = 0x2c1118;  // reserved map for now
    let alt_thunk_list_ptr = 0;
    let reserved7 = 0x773cd568;
    let alt_thunk_list_ptr_32 = 0;
    let post_process_init_routine = 0;
    let session_id = 0; 

    let peb = PEB::new(ldr, process_parameters, alt_thunk_list_ptr, reserved7, alt_thunk_list_ptr_32, post_process_init_routine, session_id);
    peb.save(&mut peb_map);
}

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
            func_va: 0
        }
    }
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
    pub func_name_tbl: u64
}

impl Flink {
    pub fn new(emu: &mut emu::Emu) -> Flink {
        let peb = emu.maps.get_mem("peb");
        let peb_base = peb.get_base();
        let ldr = peb.read_dword(peb_base + 0x0c) as u64;
        let flink = emu.maps.read_dword(ldr + 0x14)
            .expect("peb32::get_flink() error reading flink") as u64;

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
        self.mod_base = emu.maps.read_dword(self.flink_addr + 0x10)
            .expect("error reading mod_addr") as u64;
    }

    pub fn get_mod_name(&mut self, emu: &mut emu::Emu) {
        let mod_name_ptr = emu.maps.read_dword(self.flink_addr + 0x28)
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
            None => {
                0
            },
        };
    }

    pub fn get_export_table(&mut self, emu: &mut emu::Emu) {
        if self.pe_hdr == 0 {
            return;
        }
        self.export_table_rva = emu.maps.read_dword(self.mod_base + self.pe_hdr + 0x78)
            .expect("error reading export_table_rva") as u64;

        if self.export_table_rva == 0 {
            return
        }

        self.export_table = self.export_table_rva + self.mod_base;
        self.num_of_funcs = emu.maps.read_dword(self.export_table + 0x18)
            .expect("error reading the num_of_funcs") as u64;
        self.func_name_tbl_rva = emu.maps.read_dword(self.export_table + 0x20)
            .expect(" error reading func_name_tbl_rva") as u64;
        self.func_name_tbl = self.func_name_tbl_rva + self.mod_base;
    }

    pub fn get_function_ordinal(&self, emu: &mut emu::Emu, function_id: u64) -> OrdinalTable {
        let mut ordinal = OrdinalTable::new();
        let func_name_rva = emu.maps.read_dword(self.func_name_tbl + function_id * 4)
            .expect("error reading func_rva") as u64;
        ordinal.func_name = emu.maps.read_string(func_name_rva + self.mod_base);
        ordinal.ordinal_tbl_rva = emu.maps.read_dword(self.export_table + 0x24)
            .expect("error reading ordinal_tbl_rva") as u64;
        ordinal.ordinal_tbl = ordinal.ordinal_tbl_rva + self.mod_base;
        ordinal.ordinal = emu.maps.read_word(ordinal.ordinal_tbl + 2 * function_id)
            .expect("error reading ordinal") as u64;
        ordinal.func_addr_tbl_rva = emu.maps.read_dword(self.export_table + 0x1c)
            .expect("error reading func_addr_tbl_rva") as u64;
        ordinal.func_addr_tbl = ordinal.func_addr_tbl_rva + self.mod_base;
        ordinal.func_rva = emu.maps.read_dword(ordinal.func_addr_tbl + 4 * ordinal.ordinal)
            .expect("error reading func_rva") as u64;
        ordinal.func_va = ordinal.func_rva + self.mod_base;


        ordinal
    }

    pub fn next(&mut self, emu: &mut emu::Emu) {
        self.flink_addr = emu.maps.read_dword(self.flink_addr).expect("error reading next flink") as u64;
        self.load(emu);
    }
}

pub fn get_base(libname: &str, emu: &mut emu::Emu) -> Option<u64> {   
    let mut flink = Flink::new(emu);
    flink.load(emu);
    while flink.mod_base != 0 {
        //println!("{} == {}", libname, flink.mod_name);
        if libname.to_string().to_lowercase() == flink.mod_name.to_string().to_lowercase() {
            return Some(flink.mod_base);
        }
        flink.next(emu);
    }
    return None;
}


pub fn show_linked_modules(emu: &mut emu::Emu) {
    let mut flink = Flink::new(emu);
    flink.load(emu);

    // get last element
    while flink.mod_base != 0 { 
        let pe1 = match emu.maps.read_byte(flink.mod_base + flink.pe_hdr) {
            Some(b) => b,
            None => 0,
        };
        let pe2 = match emu.maps.read_byte(flink.mod_base + flink.pe_hdr+1) {
            Some(b) => b,
            None => 0,
        };
        println!("mod:{} flink:{:x} base:{:x} pe_hdr:{:x} {:x}{:x}", flink.mod_name, flink.get_ptr(), flink.mod_base, flink.pe_hdr, pe1, pe2);
        flink.next(emu);
    }
}


pub fn add_module(base: u64, pe_off: u32, libname: &str, emu: &mut emu::Emu) {
    let mut last_flink:u64 = 0;
    let mut flink = Flink::new(emu);
    flink.load(emu);

    // get last element
    while flink.mod_base != 0 { 
        last_flink = flink.get_ptr();
        flink.next(emu);
    }
    let next_flink:u64 = flink.get_ptr();

    // make space for ldr
    let sz = LdrDataTableEntry::size() as u64 +40;
    let space_addr = emu.maps.alloc(sz).expect("cannot alloc few bytes to put the LDR for LoadLibraryA");
    let mut lib = libname.to_string();
    lib.push_str(".ldr");
    let mem = emu.maps.create_map(lib.as_str());
    mem.set_base(space_addr);
    mem.set_size(sz);

    // write ldr
    mem.write_dword(space_addr, next_flink as u32);
    mem.write_dword(space_addr+4, last_flink as u32);
    mem.write_dword(space_addr+0x10, base as u32);
    mem.write_dword(space_addr+0x3c, pe_off);
    mem.write_dword(space_addr+0x28, space_addr as u32 + 0x3d); // libname ptr
    mem.write_wide_string(space_addr+0x3d, libname);

    // point previous flink to this ldr
    emu.maps.write_dword(last_flink, space_addr as u32);

    // point next blink to this ldr
    emu.maps.write_dword(next_flink+4, space_addr as u32);
}

