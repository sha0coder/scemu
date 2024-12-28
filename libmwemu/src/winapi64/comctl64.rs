use crate::emu::Emu;

pub fn gateway(addr: u64, emu: &mut emu::Emu) -> String {
    let apiname = emu::winapi64::kernel32::guess_api_name(emu, addr);
    apiname.as_str();
    {
        log::info!(
            "calling unimplemented comctl32 API 0x{:x} {}",
            addr,
            apiname
        );
        return apiname;
    }

    // return String::new();
}
