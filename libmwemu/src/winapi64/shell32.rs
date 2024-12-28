use crate::emu;
use crate::winapi64;

pub fn gateway(addr: u64, emu: &mut emu::Emu) -> String {
    let apiname = winapi64::kernel32::guess_api_name(emu, addr);
    match apiname.as_str() {
        "RealShellExecuteA" => RealShellExecuteA(emu),
        _ => {
            log::warn!("calling unimplemented shell32 API 0x{:x} {}", addr, apiname);
            return apiname;
        }
    }
    String::new()
}

fn RealShellExecuteA(emu: &mut emu::Emu) {
    let handle = emu.regs.rcx;
    let operation = emu.regs.rdx;
    let file_ptr = emu.regs.r8;
    let params_ptr = emu.regs.r9;
    let dir = emu
        .maps
        .read_qword(emu.regs.rsp)
        .expect("cannot read parameter");
    let bShowWindow = emu
        .maps
        .read_qword(emu.regs.rsp + 8)
        .expect("cannot read parameter");

    let file = emu.maps.read_string(file_ptr);
    let params = emu.maps.read_string(params_ptr);

    log::info!(
        "{}** {} shell32!RealShellExecuteA {} {} {}",
        emu.colors.light_red,
        emu.pos,
        file,
        params,
        emu.colors.nc
    );

    emu.regs.rax = 34;
}
