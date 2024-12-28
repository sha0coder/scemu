use crate::emu;
use crate::winapi32::kernel32;
//use crate::winapi32::helper;
//use crate::endpoint;

pub fn gateway(addr: u32, emu: &mut emu::Emu) -> String {
    let api = kernel32::guess_api_name(emu, addr);
    api.as_str();
    {
        log::info!("calling unimplemented shlwapi API 0x{:x} {}", addr, api);
        return api;
    }
}
