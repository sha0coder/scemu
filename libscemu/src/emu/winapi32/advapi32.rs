use crate::emu;
use crate::emu::constants::*;
use crate::emu::winapi32::helper;
use crate::emu::winapi32::kernel32;

pub fn gateway(addr: u32, emu: &mut emu::Emu) -> String {
    match addr {
        0x77733553 => StartServiceCtrlDispatcherA(emu),
        0x776fa965 => StartServiceCtrlDispatcherW(emu),
        0x776f91dd => CryptAcquireContextA(emu),

        _ => {
            let apiname = kernel32::guess_api_name(emu, addr);
            println!(
                "calling unimplemented advapi32 API 0x{:x} {}",
                addr, apiname
            );
            return apiname;
        }
    }

    return String::new();
}

fn StartServiceCtrlDispatcherA(emu: &mut emu::Emu) {
    let service_table_entry_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("advapi32!StartServiceCtrlDispatcherA error reading service_table_entry pointer");
    /*
    let service_name = emu.maps.read_dword(service_table_entry_ptr as u64)
        .expect("advapi32!StartServiceCtrlDispatcherA error reading service_name");
    let service_name = emu.maps.read_dword((service_table_entry_ptr+4) as u64)
        .expect("advapi32!StartServiceCtrlDispatcherA error reading service_name");*/

    println!(
        "{}** {} advapi321!StartServiceCtrlDispatcherA {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.regs.set_eax(1);
}

fn StartServiceCtrlDispatcherW(emu: &mut emu::Emu) {
    let service_table_entry_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("advapi32!StartServiceCtrlDispatcherW error reading service_table_entry pointer");

    println!(
        "{}** {} advapi321!StartServiceCtrlDispatcherW {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.regs.set_eax(1);
}

fn CryptAcquireContextA(emu: &mut emu::Emu) {
    let out_handle =
        emu.maps
            .read_dword(emu.regs.get_esp())
            .expect("advapi32!CryptAcquireContextA error reading handle pointer") as u64;
    let container = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("advapi32!CryptAcquireContextA error reading container");
    let provider = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("advapi32!CryptAcquireContextA error reading provider");
    let prov_type = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("advapi32!CryptAcquireContextA error reading prov_type");
    let flags = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("advapi32!CryptAcquireContextA error reading flags");

    let uri = "cryptctx://".to_string();
    let hndl = helper::handler_create(&uri) as u32;
    emu.maps.write_dword(out_handle, hndl);

    let mut sflags = String::new();
    if flags & CRYPT_VERIFYCONTEXT == CRYPT_VERIFYCONTEXT {
        sflags.push_str("CRYPT_VERIFYCONTEXT ");
    }
    if flags & CRYPT_NEWKEYSET == CRYPT_NEWKEYSET {
        sflags.push_str("CRYPT_NEWKEYSET ");
    }
    if flags & CRYPT_DELETEKEYSET == CRYPT_DELETEKEYSET {
        sflags.push_str("CRYPT_DELETEKEYSET ");
    }
    if flags & CRYPT_MACHINE_KEYSET == CRYPT_MACHINE_KEYSET {
        sflags.push_str("CRYPT_MACHINE_KEYSET ");
    }
    if flags & CRYPT_SILENT == CRYPT_SILENT {
        sflags.push_str("CRYPT_SILENT ");
    }
    if flags & CRYPT_DEFAULT_CONTAINER_OPTIONAL == CRYPT_DEFAULT_CONTAINER_OPTIONAL {
        sflags.push_str("CRYPT_DEFAULT_CONTAINER_OPTIONAL ");
    }

    println!(
        "{}** {} advapi321!CryptAcquireContextA =0x{:x} type: {} flags: `{}` {}",
        emu.colors.light_red, emu.pos, hndl, prov_type, &sflags, emu.colors.nc
    );

    for _ in 0..5 {
        emu.stack_pop32(false);
    }
    emu.regs.rax = 1;
}
