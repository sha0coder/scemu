use crate::emu;

pub fn gateway(addr: u64, emu: &mut emu::Emu) -> String {
    match addr {
        0x7740ea11 => MessageBoxA(emu),
        0x773c01a9 => GetDesktopWindow(emu),

        _ => {
            let apiname = emu::winapi64::kernel32::guess_api_name(emu, addr);
            println!("calling unimplemented user32 API 0x{:x} {}", addr, apiname);
            return apiname;
        }
    }
    return String::new();
}

fn MessageBoxA(emu: &mut emu::Emu) {
    let titleptr = emu.regs.rcx;
    let msgptr = emu.regs.rdx;
    let msg = emu.maps.read_string(msgptr);
    let title = emu.maps.read_string(titleptr);

    println!(
        "{}** {} user32!MessageBoxA {} {} {}",
        emu.colors.light_red, emu.pos, title, msg, emu.colors.nc
    );

    emu.regs.rax = 0;
}

fn GetDesktopWindow(emu: &mut emu::Emu) {
    println!(
        "{}** {} user32!GetDesktopWindow {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );
    //emu.regs.rax = 0x11223344; // current window handle
    emu.regs.rax = 0; // no windows handler is more stealthy
}
