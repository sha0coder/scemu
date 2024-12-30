use crate::emu;
use crate::serialization;
use crate::winapi32::kernel32;
/*
use crate::winapi32::helper;
use crate::context32;
use crate::constants;
use crate::console;
*/

pub fn gateway(addr: u32, emu: &mut emu::Emu) -> String {
    let api = kernel32::guess_api_name(emu, addr);
    match api.as_str() {
        "PkiInitializeCriticalSection" => PkiInitializeCriticalSection(emu),
        "CryptStringToBinaryA" => CryptStringToBinaryA(emu),

        _ => {
            if emu.cfg.skip_unimplemented == false {
                if emu.cfg.dump_on_exit && emu.cfg.dump_filename.is_some() {
                    serialization::Serialization::dump_to_file(&emu, emu.cfg.dump_filename.as_ref().unwrap());
                }

                unimplemented!("atemmpt to call unimplemented API 0x{:x} {}", addr, api);
            }
            log::warn!("calling unimplemented API 0x{:x} {} at 0x{:x}", addr, api, emu.regs.rip);
            return api;
        }
    }

    String::new()
}

fn PkiInitializeCriticalSection(emu: &mut emu::Emu) {
    let addr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("crypt32!PkiInitializeCriticalSection error getting flags param");
    let flags = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("crypt32!PkiInitializeCriticalSection error getting addr param");

    log::info!(
        "{}** {} crypt32!Pki_InitializeCriticalSection flags: {:x} addr: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        flags,
        addr,
        emu.colors.nc
    );

    for _ in 0..2 {
        emu.stack_pop32(false);
    }
    emu.regs.rax = 1;
}

fn CryptStringToBinaryA(emu: &mut emu::Emu) {
    let string = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("crypt32!CryptStringToBinaryA error getting flags param");
    let num_chars = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("crypt32!PCryptStringToBinaryA error getting addr param");
    let flags = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("crypt32!CryptStringToBinaryA error getting flags param");
    let ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("crypt32!PCryptStringToBinaryA error getting addr param");
    let inout_sz = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("crypt32!CryptStringToBinaryA error getting flags param");
    let skip = emu
        .maps
        .read_dword(emu.regs.get_esp() + 20)
        .expect("crypt32!PCryptStringToBinaryA error getting addr param");
    let out_flags = emu
        .maps
        .read_dword(emu.regs.get_esp() + 24)
        .expect("crypt32!CryptStringToBinaryA error getting flags param");

    let dflags = match flags {
        0x00000000 => "CRYPT_STRING_BASE64HEADER",
        0x00000001 => "CRYPT_STRING_BASE64",
        0x00000002 => "CRYPT_STRING_BINARY",
        0x00000003 => "CRYPT_STRING_BASE64REQUESTHEADER",
        0x00000004 => "CRYPT_STRING_HEX",
        0x00000005 => "CRYPT_STRING_HEXASCII",
        0x00000006 => "CRYPT_STRING_BASE64_ANY",
        0x00000007 => "CRYPT_STRING_ANY",
        0x00000008 => "CRYPT_STRING_HEX_ANY",
        0x00000009 => "CRYPT_STRING_BASE64X509CRLHEADER",
        0x0000000a => "CRYPT_STRING_HEXADDR",
        0x0000000b => "CRYPT_STRING_HEXASCIIADDR",
        0x0000000c => "CRYPT_STRING_HEXRAW",
        0x20000000 => "CRYPT_STRING_STRICT",
        _ => "incorrect flag",
    };

    log::info!(
        "{}** {} crypt32!CryptStringToBinaryA str: 0x{:x} len: {} ptr: {} len: {} {}{}",
        emu.colors.light_red,
        emu.pos,
        string,
        num_chars,
        ptr,
        inout_sz,
        dflags,
        emu.colors.nc
    );

    for _ in 0..7 {
        emu.stack_pop32(false);
    }
    emu.regs.rax = 1;
}
