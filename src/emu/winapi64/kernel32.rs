use crate::emu;
/*use crate::emu::winapi32::helper;
use crate::emu::context32;
use crate::emu::constants;
use crate::emu::console;

use lazy_static::lazy_static; 
use std::sync::Mutex;*/

// a in RCX, b in RDX, c in R8, d in R9, f then e pushed on stack

pub fn gateway(addr:u64, emu:&mut emu::Emu) {
    match addr {
        0x76dc7070 => LoadLibraryA(emu),
        0x76dd3690 => GetProcAddress(emu),
        _ => panic!("calling unimplemented kernel32 API 0x{:x}", addr),
    }
}



pub fn LoadLibraryA(emu:&mut emu::Emu) {
    let dllptr = emu.regs.rcx;
    let dll = emu.maps.read_string(dllptr);

    match dll.to_lowercase().as_str() {
        "ntdll"|"ntdll.dll" => emu.regs.rax = emu.maps.get_mem("ntdll_pe").get_base(),
        "ws2_32"|"ws2_32.dll" => emu.regs.rax = emu.maps.get_mem("ws2_32_pe").get_base(),
        "wininet"|"wininet.dll" => emu.regs.rax = emu.maps.get_mem("wininet_pe").get_base(),
        "advapi32"|"advapi32.dll" => emu.regs.rax = emu.maps.get_mem("advapi32_pe").get_base(),
        "kernel32"|"kernel32.dll" => emu.regs.rax = emu.maps.get_mem("kernel32_pe").get_base(),
        _ => unimplemented!("/!\\ kernel32!LoadLibraryA: lib not found {}", dll),
    }

    println!("{}** {} kernel32!LoadLibraryA  '{}' =0x{:x} {}", emu.colors.light_red, emu.pos, dll, emu.regs.rax, emu.colors.nc);
}

fn GetProcAddress(emu:&mut emu::Emu) {
    let hndl = emu.regs.rcx;
    let func_ptr = emu.regs.rdx;

    let func = emu.maps.read_string(func_ptr).to_lowercase();

    println!("looking for '{}'", func);

    // https://github.com/ssherei/asm/blob/master/get_api.asm

    let peb = emu.maps.get_mem("peb");
    let peb_base = peb.get_base();
    let ldr = peb.read_qword(peb_base + 0x18);
    let mut flink = emu.maps.read_qword(ldr + 0x10).expect("kernel32!GetProcAddress error reading flink");
    println!("flink: 0x{:x}", flink);

    loop { // walk modules

        let mod_name_ptr = emu.maps.read_qword(flink + 0x30).expect("kernel32!GetProcAddress error reading mod_name_ptr");
        let mod_base = emu.maps.read_qword(flink + 0x58).expect("kernel32!GetProcAddress error reading mod_addr");
        let mod_name = emu.maps.read_wide_string(mod_name_ptr);

        println!("mod_name: {}", mod_name);

        let pe_hdr = match emu.maps.read_dword(mod_base + 0x3c) { //.expect("kernel32!GetProcAddress error reading pe_hdr");
            Some(hdr) => hdr as u64,
            None => { emu.regs.rax = 0; return; }
        };
        let export_table_rva = emu.maps.read_dword(mod_base + pe_hdr + 0x78).expect("kernel32!GetProcAddress error reading export_table_rva") as u64;
        if export_table_rva == 0 {
            flink = emu.maps.read_dword(flink).expect("kernel32!GetProcAddress error reading next flink") as u64;
            continue;
        }

        let export_table = export_table_rva + mod_base;
        let mut num_of_funcs = emu.maps.read_dword(export_table + 0x18).expect("kernel32!GetProcAddress error reading the num_of_funcs") as u64;

        let func_name_tbl_rva = emu.maps.read_dword(export_table + 0x20).expect("kernel32!GetProcAddress  error reading func_name_tbl_rva") as u64;
        let func_name_tbl = func_name_tbl_rva + mod_base;

        if num_of_funcs == 0 {
            flink = emu.maps.read_dword(flink).expect("kernel32!GetProcAddress error reading next flink") as u64;
            continue;
        }

        loop { // walk functions
                
            num_of_funcs -= 1;
            let func_name_rva = emu.maps.read_dword(func_name_tbl + num_of_funcs * 4).expect("kernel32!GetProcAddress error reading func_rva") as u64;
            let func_name_va = func_name_rva + mod_base;
            let func_name = emu.maps.read_string(func_name_va).to_lowercase();

            println!("func_name: {}", func_name);
            
            if func_name == func { 
                let ordinal_tbl_rva = emu.maps.read_dword(export_table + 0x24).expect("kernel32!GetProcAddress error reading ordinal_tbl_rva") as u64;
                let ordinal_tbl = ordinal_tbl_rva + mod_base;
                let ordinal = emu.maps.read_word(ordinal_tbl + 2 * num_of_funcs).expect("kernel32!GetProcAddress error reading ordinal") as u64;
                let func_addr_tbl_rva = emu.maps.read_dword(export_table + 0x1c).expect("kernel32!GetProcAddress  error reading func_addr_tbl_rva") as u64;
                let func_addr_tbl = func_addr_tbl_rva + mod_base;
                
                let func_rva = emu.maps.read_dword(func_addr_tbl + 4 * ordinal).expect("kernel32!GetProcAddress error reading func_rva") as u64;
                let func_va = func_rva + mod_base;

                emu.regs.rax = func_va;

                println!("{}** {} kernel32!GetProcAddress  `{}!{}` =0x{:x} {}", emu.colors.light_red, emu.pos, mod_name, func_name, emu.regs.get_eax() as u32, emu.colors.nc);
                return;
            }

            if num_of_funcs == 0 {
                break;
            }
        }

        flink = emu.maps.read_dword(flink).expect("kernel32!GetProcAddress error reading next flink") as u64;
    } 
}

