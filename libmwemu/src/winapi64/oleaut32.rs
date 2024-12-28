use crate::emu;
use crate::winapi64::kernel32;

pub fn gateway(addr: u64, emu: &mut emu::Emu) -> String {
    let api = kernel32::guess_api_name(emu, addr);
    match api.as_str() {
        //"FindActCtxSectionStringW" => FindActCtxSectionStringW(emu),
        _ => {
            if emu.cfg.skip_unimplemented == false {
                unimplemented!("calling unimplemented kernel32 API 0x{:x} {}", addr, api);
            }
            log::warn!("calling unimplemented kernel32 API 0x{:x} {}", addr, api);
            return api;
        }
    }

    //String::new()
}