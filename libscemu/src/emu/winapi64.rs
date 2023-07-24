mod advapi32;
mod dnsapi;
pub mod kernel32;
mod ntdll;
mod user32;
mod winhttp;
mod wininet;
mod ws2_32;

use crate::emu;

pub fn gateway(addr: u64, name: String, emu: &mut emu::Emu) {
    let unimplemented_api = match name.as_str() {
        "kernel32_text" => kernel32::gateway(addr, emu),
        "kernel32_rdata" => kernel32::gateway(addr, emu),
        "ntdll_text" => ntdll::gateway(addr, emu),
        "user32_text" => user32::gateway(addr, emu),
        "ws2_32_text" => ws2_32::gateway(addr, emu),
        "wininet_text" => wininet::gateway(addr, emu),
        "advapi32_text" => advapi32::gateway(addr, emu),
        "winhttp_text" => winhttp::gateway(addr, emu),
        "dnsapi_text" => dnsapi::gateway(addr, emu),
        _ => panic!("/!\\ trying to execute on {} at 0x{:x}", name, addr),
    };

    if unimplemented_api.len() > 0 {
        if emu.cfg.skip_unimplemented {
            let params = emu.banzai.get_params(&unimplemented_api);
            println!("{} {} parameters", unimplemented_api, params);

            if params > 4 {
                for _ in 4..params {
                    emu.stack_pop64(false);
                }
            }
            emu.regs.rax = 1;
        } else {
            panic!("function is not in emulation list.");
        }
    }
}
