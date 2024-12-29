use crate::emu;
use crate::winapi64;
use crate::serialization;
//use crate::constants;
//use crate::winapi32::helper;

pub fn gateway(addr: u64, emu: &mut emu::Emu) -> String {
    let api = winapi64::kernel32::guess_api_name(emu, addr);
    match api.as_str() {
        "PathIsContentTypeW" => PathIsContentTypeW(emu),
        "PathFindSuffixArrayA" => PathFindSuffixArrayA(emu),

        _ => {
            if emu.cfg.skip_unimplemented == false {
                if emu.cfg.dump_on_exit && emu.cfg.dump_filename.is_some() {
                    serialization::Serialization::dump_to_file(&emu, emu.cfg.dump_filename.as_ref().unwrap());
                }

                unimplemented!("calling unimplemented API 0x{:x} {}", addr, api);
            }
            log::warn!("calling unimplemented API 0x{:x} {}", addr, api);
            return api;
        }
    }

    String::new()
}

pub fn PathIsContentTypeW(emu: &mut emu::Emu) {
    let path = emu.maps.read_wide_string(emu.regs.rcx);
    let content_type = emu.maps.read_wide_string(emu.regs.rdx);

    log::info!(
        "{}** {} shlwapi!PathIsContentTypeW path: {} content-type: {} {}",
        emu.colors.light_red,
        emu.pos,
        path,
        content_type,
        emu.colors.nc
    );

    emu.regs.rax = 1;
}

pub fn PathFindSuffixArrayA(emu: &mut emu::Emu) {
    let path = emu.maps.read_string(emu.regs.rcx);
    let suffixes = emu.maps.read_string(emu.regs.rdx);

    log::info!(
        "{}** {} shlwapi!PathFindSuffixArrayA path: {} suffixes: {} {}",
        emu.colors.light_red,
        emu.pos,
        path,
        suffixes,
        emu.colors.nc
    );

    emu.regs.rax = emu.regs.rdx;
}
