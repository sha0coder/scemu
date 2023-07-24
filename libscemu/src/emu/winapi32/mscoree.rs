use crate::emu;
use crate::emu::winapi32::kernel32;

pub fn gateway(addr: u32, emu: &mut emu::Emu) -> String {
    match addr {
        0x79004ddb => _CorExeMain(emu),

        _ => {
            let apiname = kernel32::guess_api_name(emu, addr);
            println!("calling unimplemented mscoree API 0x{:x} {}", addr, apiname);
            return apiname;
        }
    }

    return String::new();
}

pub fn _CorExeMain(emu: &mut emu::Emu) {
    println!(
        "{}** {} mscoree!_CorExeMain {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );
    emu.regs.rax = 1;
    unimplemented!();
}
