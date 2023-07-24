use crate::emu;
use crate::emu::winapi32::kernel32;
//use crate::emu::winapi32::helper;
//use crate::emu::endpoint;

pub fn gateway(addr: u32, emu: &mut emu::Emu) -> String {
    match addr {
        _ => {
            let apiname = kernel32::guess_api_name(emu, addr);
            println!("calling unimplemented shlwapi API 0x{:x} {}", addr, apiname);
            return apiname;
        }
    }
}
