mod advapi32;
mod comctl32;
mod comctl64;
mod dnsapi;
pub mod kernel32;
mod kernelbase;
mod ntdll;
mod shell32;
mod shlwapi;
mod user32;
mod winhttp;
mod wininet;
mod ws2_32;
mod oleaut32;
mod uxtheme;
mod gdi32;
mod ole32;

use crate::emu;

pub fn gateway(addr: u64, name: String, emu: &mut emu::Emu) {
    match name.as_str() {
        "kernel32.text" => kernel32::gateway(addr, emu),
        "kernel32.rdata" => kernel32::gateway(addr, emu),
        "ntdll.text" => ntdll::gateway(addr, emu),
        "user32.text" => user32::gateway(addr, emu),
        "ws2_32.text" => ws2_32::gateway(addr, emu),
        "wininet.text" => wininet::gateway(addr, emu),
        "advapi32.text" => advapi32::gateway(addr, emu),
        "winhttp.text" => winhttp::gateway(addr, emu),
        "dnsapi.text" => dnsapi::gateway(addr, emu),
        "comctl32.text" => comctl32::gateway(addr, emu),
        "comctl64.text" => comctl64::gateway(addr, emu),
        "shell32.text" => shell32::gateway(addr, emu),
        "shlwapi.text" => shlwapi::gateway(addr, emu),
        "kernelbase.text" => kernelbase::gateway(addr, emu),
        "oleaut32.text" => oleaut32::gateway(addr, emu),
        "uxtheme.text" => uxtheme::gateway(addr, emu),
        "gdi32.text" => gdi32::gateway(addr, emu),
        "ole32.text" => ole32::gateway(addr, emu),
        "not_loaded" => {
            // TODO: banzai check?
            emu.pe64.as_ref().unwrap().import_addr_to_name(addr)
        },
        _ => panic!("/!\\ trying to execute on {} at 0x{:x}", name, addr),
    };
}
