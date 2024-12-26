use crate::emu;
//use crate::emu::constants::*;
//use crate::emu::winapi32::helper;
use crate::emu::winapi32::kernel32;

pub fn gateway(addr: u32, emu: &mut emu::Emu) -> String {
    let api = kernel32::guess_api_name(emu, addr);
    match api.as_str() {
        "__register_frame_info" => __register_frame_info(emu),
        "__deregister_frame_info" => __deregister_frame_info(emu),


        _ => {
            log::info!("calling unimplemented libgcc API 0x{:x} {}", addr, api);
            return api;
        }
    }

    return String::new();
}


fn __register_frame_info(emu: &mut emu::Emu) {
    let p1 =
        emu.maps
            .read_dword(emu.regs.get_esp())
            .expect("advapi32!__register_frame_info error reading param");
    let p2 =
        emu.maps
            .read_dword(emu.regs.get_esp()+4)
            .expect("advapi32!__register_frame_info error reading param");

    log::info!(
        "{}** {} libgcc!__register_frame_info {:x} {:x} {}",
        emu.colors.light_red, emu.pos, p1, p2, emu.colors.nc
    );

    let mem = match emu.maps.get_mem_by_addr(0x40E198) {
        Some(m) => m,
        None => {
            emu.maps.create_map("glob1", 0x40E198, 100).expect("cannot create glob1 map")
        }
    };

    mem.write_dword(0x40E198, 0x6e940000);
            

    for _ in 0..2 {
        emu.stack_pop32(false);
    }
    emu.regs.rax = 1;
}


fn __deregister_frame_info(emu: &mut emu::Emu) {
    let p1 =
        emu.maps
            .read_dword(emu.regs.get_esp())
            .expect("advapi32!__deregister_frame_info error reading param");

    log::info!(
        "{}** {} libgcc!__deregister_frame_info {:x} {}",
        emu.colors.light_red, emu.pos, p1, emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.regs.rax = 1;
}