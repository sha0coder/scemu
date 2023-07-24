use crate::emu::winapi32::kernel32;
//use crate::emu::winapi32::helper;
use crate::emu;

pub fn gateway(addr: u32, emu: &mut emu::Emu) -> String {
    match addr {
        0x764745d2 => SysAllocStringLen(emu),
        0x76473e59 => SysFreeString(emu),

        _ => {
            let apiname = kernel32::guess_api_name(emu, addr);
            println!(
                "calling unimplemented oleaut32 API 0x{:x} {}",
                addr, apiname
            );
            return apiname;
        }
    }

    return String::new();
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
    let alloc = emu.maps.create_map(&name);
    alloc.set_base(base);
    alloc.set_size(size);

    emu.maps.memcpy(base + 8, str_ptr, size as usize - 1);

    println!(
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

    println!(
        "{}** {} oleaut32!SysFreeString  0x{:x} {}",
        emu.colors.light_red, emu.pos, str_ptr, emu.colors.nc
    );

    //emu.maps.free(&format!("alloc_{:x}", str_ptr));

    emu.stack_pop32(false);
}
