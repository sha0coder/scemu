use crate::emu::winapi32::kernel32;
use crate::emu;


pub fn gateway(addr:u32, emu:&mut emu::Emu)  {
    match addr {
        0x79004ddb => _CorExeMain(emu),

        _ => panic!("calling unimplemented mscoree API 0x{:x} {}", addr, kernel32::guess_api_name(emu, addr))
    }
}

pub fn _CorExeMain(emu:&mut emu::Emu) {
    println!("{}** {} mscoree!_CorExeMain {}", emu.colors.light_red, emu.pos, emu.colors.nc);
    emu.regs.rax = 1;
    unimplemented!();
}


