use crate::emu;
use crate::winapi64;
use crate::serialization;
//use crate::constants;
//use crate::winapi32::helper;

pub fn gateway(addr: u64, emu: &mut emu::Emu) -> String {
    let api = winapi64::kernel32::guess_api_name(emu, addr);
    match api.as_str() {
        "PathCombineA" => PathCombineA(emu),
        "IsCharAlphaNumericA" => IsCharAlphaNumericA(emu),
        "GetTokenInformation" => GetTokenInformation(emu),

        _ => {
            if emu.cfg.skip_unimplemented == false {
                if emu.cfg.dump_on_exit && emu.cfg.dump_filename.is_some() {
                    serialization::Serialization::dump_to_file(&emu, emu.cfg.dump_filename.as_ref().unwrap());
                }

                unimplemented!("calling unimplemented API 0x{:x} {}", addr, api);
            }
            log::warn!("calling unimplemented API 0x{:x} {}", addr, api);
            return api;
        }
    }

    String::new()
}

pub fn PathCombineA(emu: &mut emu::Emu) {
    let dst: u64 = emu.regs.rcx;
    let path1 = emu.maps.read_string(emu.regs.rdx);
    let path2 = emu.maps.read_string(emu.regs.r8);

    log::info!(
        "{}** {} kernelbase!PathCombineA path1: {} path2: {} {}",
        emu.colors.light_red,
        emu.pos,
        path1,
        path2,
        emu.colors.nc
    );

    if dst != 0 && !path1.is_empty() && !path2.is_empty() {
        emu.maps.write_string(dst, &format!("{}\\{}", path1, path2));
    }

    emu.regs.rax = dst;
}

pub fn IsCharAlphaNumericA(emu: &mut emu::Emu) {
    let c = emu.regs.rcx as u8 as char;

    log::info!(
        "{}** {} kernelbase!IsCharAlphaNumericA char: {} {}",
        emu.colors.light_red,
        emu.pos,
        c,
        emu.colors.nc
    );

    emu.regs.rax = if c.is_ascii_alphanumeric() { 1 } else { 0 };
}

pub fn GetTokenInformation(emu: &mut emu::Emu) {
    let token_handle = emu.regs.rdx;
    let token_information_class = emu.regs.rcx;
    let token_information = emu.regs.r8;
    let token_information_length = emu.regs.r9;
    let return_length = emu.maps.read_qword(emu.regs.rsp);

    log::info!(
        "{}** {} kernelbase!GetTokenInformation token_information_class: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        token_information_class,
        emu.colors.nc
    );

    emu.regs.rax = 1;
}
