use crate::emu;
use crate::serialization;
use crate::winapi32::kernel32;
//use crate::winapi32::helper;

pub fn gateway(addr: u32, emu: &mut emu::Emu) -> String {
    let api = kernel32::guess_api_name(emu, addr);
    match api.as_str() {
        "SysAllocStringLen" => SysAllocStringLen(emu),
        "SysFreeString" => SysFreeString(emu),

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

fn SysAllocStringLen(emu: &mut emu::Emu) {
    let str_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("oleaut32!SysAllocStringLen cannot read str_ptr") as u64;
    let mut size = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("oleaut32!SysAllocStringLen cannot read size") as u64;

    if size == 0xffffffff {
        size = 1024;
    }
    size += 1; // null byte
    size += 8; // metadata

    let base = emu
        .maps
        .alloc(size + 8)
        .expect("oleaut32!SysAllocStringLen out of memory");
    let name = format!("alloc_{:x}", base + 8);
    emu.maps.create_map(&name, base, size);
    emu.maps.memcpy(base + 8, str_ptr, size as usize - 1);

    log::info!(
        "{}** {} oleaut32!SysAllocStringLen  ={} {} {}",
        emu.colors.light_red,
        emu.pos,
        name,
        size - 8,
        emu.colors.nc
    );

    for _ in 0..2 {
        emu.stack_pop32(false);
    }

    emu.regs.rax = base + 8;
}

fn SysFreeString(emu: &mut emu::Emu) {
    let str_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("oleaut32!SysFreeString cannot read host_port") as u64;

    log::info!(
        "{}** {} oleaut32!SysFreeString  0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        str_ptr,
        emu.colors.nc
    );

    //emu.maps.free(&format!("alloc_{:x}", str_ptr));

    emu.stack_pop32(false);
}
