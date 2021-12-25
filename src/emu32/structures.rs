use crate::emu32::maps::Maps;


////// PEB / TEB //////

#[derive(Debug)]
pub struct ListEntry {
    flink: u32,
    blink: u32,
}

impl ListEntry {
    pub fn load(addr:u32, maps:&Maps) -> ListEntry {
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
    pub fn load(addr:u32, maps:&Maps) -> LdrDataTableEntry {
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
    pub fn load(addr:u32, maps:&Maps) -> PebLdrData {
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
    pub fn load(addr:u32, maps:&Maps) -> PEB {
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
    pub fn load(addr:u32, maps:&Maps) -> PScopeTableEntry {
        PScopeTableEntry {
            enclosing_level: maps.read_dword(addr).unwrap(),
            filter_func: maps.read_dword(addr + 4).unwrap(),
            handler_func: maps.read_dword(addr + 8).unwrap(),
        }
    }

    pub fn size() -> u32 {
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
    pub fn load(addr:u32, maps:&Maps) -> CppEhRecord {
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
    pub fn load(addr:u32, maps:&Maps) -> ExceptionPointers {
        ExceptionPointers {
            exception_record: maps.read_dword(addr).unwrap(),
            context_record: maps.read_dword(addr + 4).unwrap(),
        }
    }

    pub fn size() -> u32 {
        return 8;
    }

    pub fn print(&self) {
        println!("{:#x?}", self);
    }
}