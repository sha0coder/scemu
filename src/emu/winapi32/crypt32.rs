use crate::emu;
use crate::emu::winapi32::kernel32;
/*
use crate::emu::winapi32::helper;
use crate::emu::context32;                                                                                               
use crate::emu::constants;                                                                                               
use crate::emu::console;                                                                                                 
*/                                                                                                                       
                                                                                                                         
pub fn gateway(addr:u32, emu:&mut emu::Emu) {                                                                            
    match addr {
        0x719b1540 => PkiInitializeCriticalSection(emu),
        _ => panic!("calling unimplemented kernel32 API 0x{:x} {}", addr, kernel32::guess_api_name(emu, addr)),
    }
}

pub fn PkiInitializeCriticalSection(emu:&mut emu::Emu) {
    let addr = emu.maps.read_dword(emu.regs.get_esp()).expect("crypt32!PkiInitializeCriticalSection error getting flags param");
    let flags = emu.maps.read_dword(emu.regs.get_esp()+4).expect("crypt32!PkiInitializeCriticalSection error getting addr param");

    println!("{}** {} crypt32!Pki_InitializeCriticalSection flags: {:x} addr: 0x{:x} {}", emu.colors.light_red, emu.pos, 
             flags, addr, emu.colors.nc);

    for _ in 0..2 {
        emu.stack_pop32(false);
    }
    emu.regs.rax = 1;

}

