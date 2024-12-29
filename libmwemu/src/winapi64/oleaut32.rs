use crate::emu;
use crate::serialization;
use crate::winapi64::kernel32;
//use crate::winapi32::helper;

pub fn gateway(addr: u64, emu: &mut emu::Emu) -> String {
    let api = kernel32::guess_api_name(emu, addr);
    match api.as_str() {
        "SysAllocStringLen" => SysAllocStringLen(emu),
        "SysFreeString" => SysFreeString(emu),

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

fn SysAllocStringLen(emu: &mut emu::Emu) {
    let str_ptr = emu.regs.rcx;
    let mut size = emu.regs.rdx;

    log::info!(
        "{}** {} oleaut32!SysAllocStringLen str_ptr: 0x{:x} size: {}",
        emu.colors.light_red,
        emu.pos,
        str_ptr,
        size
    );

    if size == 0xffffffff {
        size = 1024;
    }
    size += 1; // null byte
    size += 8; // metadata

    let base = emu.maps.alloc(size + 100).expect("oleaut32!SysAllocStringLen out of memory");
    let name = format!("alloc_{:x}", base);
    emu.maps.create_map(&name, base, size + 100);
    emu.maps.memcpy(base + 8, str_ptr, size as usize - 1);

    log::info!(
        "{}** {} oleaut32!SysAllocStringLen  ={} {} {}",
        emu.colors.light_red,
        emu.pos,
        name,
        size - 8,
        emu.colors.nc
    );

    emu.regs.rax = base + 8;
}

fn SysFreeString(emu: &mut emu::Emu) {
    let str_ptr = emu.regs.rcx;

    log::info!(
        "{}** {} oleaut32!SysFreeString  0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        str_ptr,
        emu.colors.nc
    );

    //emu.maps.free(&format!("alloc_{:x}", str_ptr));
}
