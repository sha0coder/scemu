use crate::emu;
use crate::winapi64;

pub fn gateway(addr: u64, emu: &mut emu::Emu) -> String {
    let apiname = winapi64::kernel32::guess_api_name(emu, addr);
    apiname.as_str();
    {
        log::warn!(
            "calling unimplemented comctl32 API 0x{:x} {}",
            addr,
            apiname
        );
        return apiname;
    }

    // return String::new();
}
