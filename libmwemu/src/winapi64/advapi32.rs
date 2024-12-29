use crate::emu;
use crate::constants;
use crate::serialization;
use crate::winapi64;
use crate::winapi32::helper;

pub fn gateway(addr: u64, emu: &mut emu::Emu) -> String {
    let api = winapi64::kernel32::guess_api_name(emu, addr);
    match api.as_str() {
        "StartServiceCtrlDispatcherA" => StartServiceCtrlDispatcherA(emu),
        "StartServiceCtrlDispatcherW" => StartServiceCtrlDispatcherW(emu),
        "RegOpenKeyExA" => RegOpenKeyExA(emu),
        "RegQueryValueExA" => RegQueryValueExA(emu),
        "RegCloseKey" => RegCloseKey(emu),

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

fn StartServiceCtrlDispatcherA(emu: &mut emu::Emu) {
    let service_table_entry_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("advapi32!StartServiceCtrlDispatcherA error reading service_table_entry pointer");

    let service_name = emu
        .maps
        .read_dword(service_table_entry_ptr as u64)
        .expect("advapi32!StartServiceCtrlDispatcherA error reading service_name");
    let service_name = emu
        .maps
        .read_dword((service_table_entry_ptr + 4) as u64)
        .expect("advapi32!StartServiceCtrlDispatcherA error reading service_name");

    emu.regs.set_eax(1);
}

fn StartServiceCtrlDispatcherW(emu: &mut emu::Emu) {
    let service_table_entry_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("advapi32!StartServiceCtrlDispatcherW error reading service_table_entry pointer");

    emu.regs.set_eax(1);
}

fn RegOpenKeyExA(emu: &mut emu::Emu) {
    let hkey = emu.regs.rcx;
    let subkey_ptr = emu.regs.rdx;
    let opts = emu.regs.r8;
    let result = emu.regs.r9;

    let subkey = emu.maps.read_string(subkey_ptr);

    log::info!(
        "{}** {} advapi32!RegOpenKeyExA {} {}",
        emu.colors.light_red,
        emu.pos,
        subkey,
        emu.colors.nc
    );

    emu.maps
        .write_qword(result, helper::handler_create(&subkey));
    emu.regs.rax = constants::ERROR_SUCCESS;
}

fn RegCloseKey(emu: &mut emu::Emu) {
    let hkey = emu.regs.rcx;

    log::info!(
        "{}** {} advapi32!RegCloseKey {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    helper::handler_close(hkey);

    emu.regs.rax = constants::ERROR_SUCCESS;
}

fn RegQueryValueExA(emu: &mut emu::Emu) {
    let hkey = emu.regs.rcx;
    let value_ptr = emu.regs.rdx;
    let reserved = emu.regs.r8;
    let typ_out = emu.regs.r9;
    let data_out = emu
        .maps
        .read_qword(emu.regs.rsp)
        .expect("error reading api aparam");
    let datasz_out = emu
        .maps
        .read_qword(emu.regs.rsp + 8)
        .expect("error reading api param");

    let mut value = String::new();
    if value_ptr > 0 {
        value = emu.maps.read_string(value_ptr);
    }

    log::info!(
        "{}** {} advapi32!RegQueryValueExA {} {}",
        emu.colors.light_red,
        emu.pos,
        value,
        emu.colors.nc
    );

    if data_out > 0 {
        emu.maps.write_string(data_out, "some_random_reg_contents");
    }
    if datasz_out > 0 {
        emu.maps.write_qword(datasz_out, 24);
    }
    emu.regs.rax = constants::ERROR_SUCCESS;
}
