use crate::emu;
use crate::emu::winapi32::kernel32;

pub fn gateway(addr: u32, emu: &mut emu::Emu) -> String {
    match addr {
        0x7740ea11 => MessageBoxA(emu),
        0x773c01a9 => GetDesktopWindow(emu),
        0x773d426d => wsprintfW(emu),
        _ => {
            let apiname = kernel32::guess_api_name(emu, addr);
            println!("calling unimplemented user32 API 0x{:x} {}", addr, apiname);
            return apiname;
        }
    }

    return String::new();
}

fn MessageBoxA(emu: &mut emu::Emu) {
    let titleptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("user32_MessageBoxA: error reading title") as u64;
    let msgptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("user32_MessageBoxA: error reading message") as u64;
    let msg = emu.maps.read_string(msgptr);
    let title = emu.maps.read_string(titleptr);

    println!(
        "{}** {} user32!MessageBoxA {} {} {}",
        emu.colors.light_red, emu.pos, title, msg, emu.colors.nc
    );

    emu.regs.rax = 0;
    for _ in 0..4 {
        emu.stack_pop32(false);
    }
}

fn GetDesktopWindow(emu: &mut emu::Emu) {
    println!(
        "{}** {} user32!GetDesktopWindow {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );
    //emu.regs.rax = 0x11223344; // current window handle
    emu.regs.rax = 0; // no windows handler is more stealthy
}

fn wsprintfW(emu: &mut emu::Emu) {}
