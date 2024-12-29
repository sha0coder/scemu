use crate::emu;
use crate::winapi64;
use crate::serialization;

pub fn gateway(addr: u64, emu: &mut emu::Emu) -> String {
    let api = winapi64::kernel32::guess_api_name(emu, addr);
    match api.as_str() {
        "RealShellExecuteA" => RealShellExecuteA(emu),
        _ => {
            if emu.cfg.skip_unimplemented == false {
                if emu.cfg.dump_on_exit && emu.cfg.dump_filename.is_some() {
                    serialization::Serialization::dump_to_file(&emu, emu.cfg.dump_filename.as_ref().unwrap());
                }

                unimplemented!("atemmpt to call unimplemented API 0x{:x} {}", addr, api);
            }
            log::warn!("calling unimplemented API 0x{:x} {}", addr, api);
            return api;
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
