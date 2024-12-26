use crate::emu;

pub fn gateway(addr: u64, emu: &mut emu::Emu) -> String {
    let apiname = emu::winapi64::kernel32::guess_api_name(emu, addr);
    match apiname.as_str() {
        /*"StartServiceCtrlDispatcherA" => StartServiceCtrlDispatcherA(emu),
        "StartServiceCtrlDispatcherW" => StartServiceCtrlDispatcherW(emu),*/
        _ => {
            log::info!("calling unimplemented winhttp API 0x{:x} {}", addr, apiname);
            return apiname;
        }
    }
}
