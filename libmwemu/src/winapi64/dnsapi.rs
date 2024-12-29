use crate::emu;
use crate::winapi64;

pub fn gateway(addr: u64, emu: &mut emu::Emu) -> String {
    let api = winapi64::kernel32::guess_api_name(emu, addr);
    match api.as_str() {
        _ => {
            if emu.cfg.skip_unimplemented == false {
                unimplemented!("calling unimplemented API 0x{:x} {}", addr, api);
            }
            log::warn!("calling unimplemented API 0x{:x} {}", addr, api);
            return api;
        }
    }
}
