use crate::emu32;

pub fn gateway(addr:u32, emu:&mut emu32::Emu32) {
    match addr {
        0x7740ea11 => MessageBoxA(emu),
        _ => panic!("calling unknown user32 API 0x{:x}", addr)
    }
}

fn MessageBoxA(emu:&mut emu32::Emu32) {
    let titleptr = emu.maps.read_dword(emu.regs.esp+8).expect("user32_MessageBoxA: error reading title");
    let msgptr = emu.maps.read_dword(emu.regs.esp+4).expect("user32_MessageBoxA: error reading message");
    let msg = emu.maps.read_string(msgptr);
    let title = emu.maps.read_string(titleptr);

    let colors = emu32::colors::Colors::new();
    println!("{}** user32_MessageBoxA {} {} {}", colors.light_red, title, msg, colors.nc);

    emu.regs.eax = 0;
    for _ in 0..4 {
        emu.stack_pop(false);
    }
}