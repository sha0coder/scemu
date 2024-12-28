use crate::emu;
use crate::winapi64;
pub fn gateway(addr: u64, emu: &mut emu::Emu) -> String {
    let apiname = winapi64::kernel32::guess_api_name(emu, addr);
    match apiname.as_str() {
        "MessageBoxA" => MessageBoxA(emu),
        "GetDesktopWindow" => GetDesktopWindow(emu),

        _ => {
            log::info!("calling unimplemented user32 API 0x{:x} {}", addr, apiname);
            return apiname;
        }
    }
    String::new()
}

fn MessageBoxA(emu: &mut emu::Emu) {
    let titleptr = emu.regs.rcx;
    let msgptr = emu.regs.rdx;
    let msg = emu.maps.read_string(msgptr);
    let title = emu.maps.read_string(titleptr);

    log::info!(
        "{}** {} user32!MessageBoxA {} {} {}",
        emu.colors.light_red,
        emu.pos,
        title,
        msg,
        emu.colors.nc
    );

    emu.regs.rax = 0;
}

fn GetDesktopWindow(emu: &mut emu::Emu) {
    log::info!(
        "{}** {} user32!GetDesktopWindow {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );
    //emu.regs.rax = 0x11223344; // current window handle
    emu.regs.rax = 0; // no windows handler is more stealthy
}
