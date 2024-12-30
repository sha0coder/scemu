use crate::emu;
use crate::serialization;
use crate::winapi64;

pub fn gateway(addr: u64, emu: &mut emu::Emu) -> String {
    let api = winapi64::kernel32::guess_api_name(emu, addr);
    match api.as_str() {
        "IsAppThemed" => IsAppThemed(emu),
        "IsThemeActive" => IsThemeActive(emu),
        "GetThemeAppProperties" => GetThemeAppProperties(emu),
        _ => {
            if emu.cfg.skip_unimplemented == false {
                if emu.cfg.dump_on_exit && emu.cfg.dump_filename.is_some() {
                    serialization::Serialization::dump_to_file(&emu, emu.cfg.dump_filename.as_ref().unwrap());
                }

                unimplemented!("atemmpt to call unimplemented API 0x{:x} {}", addr, api);
            }
            log::warn!("calling unimplemented API 0x{:x} {} at 0x{:x}", addr, api, emu.regs.rip);
            return api;
        }
    }
    String::new()
}

fn IsAppThemed(emu: &mut emu::Emu) {
    log_red!(emu, "** {} uxtheme!IsAppThemed", emu.pos);
    emu.regs.rax = 1;
}

fn IsThemeActive(emu: &mut emu::Emu) {
    log_red!(emu, "** {} uxtheme!IsThemeActive", emu.pos);
    emu.regs.rax = 1;
}

fn GetThemeAppProperties(emu: &mut emu::Emu) {
    log_red!(emu, "** {} uxtheme!GetThemeAppProperties", emu.pos);
    emu.regs.rax = 1;
}


