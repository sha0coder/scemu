mod kernel32;
mod ntdll;
mod user32;
mod wininet;
mod ws2_32;
mod advapi32;
mod crypt32;
pub mod helper;

use crate::emu;


pub fn gateway(addr:u32, name:String, emu:&mut emu::Emu) { //name:String, maps:&emu32::maps::Maps, regs:&emu32::regs32::Regs32) {
    emu.regs.sanitize32();
    match name.as_str() {
        "kernel32_text" => kernel32::gateway(addr, emu),
        "ntdll_text" => ntdll::gateway(addr, emu),
        "user32_text" => user32::gateway(addr, emu),
        "ws2_32_text" => ws2_32::gateway(addr, emu),
        "wininet_text" => wininet::gateway(addr, emu),
        "advapi32_text" => advapi32::gateway(addr, emu),
        "crypt32.text" => crypt32::gateway(addr, emu),
        _ => panic!("/!\\ trying to execute on {} at 0x{:x}", name, addr),
    }
}
