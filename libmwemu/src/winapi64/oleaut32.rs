use crate::emu;
use crate::serialization;
use crate::winapi64::kernel32;
//use crate::winapi32::helper;

pub fn gateway(addr: u64, emu: &mut emu::Emu) -> String {
    let api = kernel32::guess_api_name(emu, addr);
    match api.as_str() {
        "SysAllocStringLen" => SysAllocStringLen(emu),
        "SysReAllocStringLen" => SysReAllocStringLen(emu),
        "SysFreeString" => SysFreeString(emu),
        "VariantClear" => VariantClear(emu),

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

/*
INT SysReAllocStringLen(
  [in, out]      BSTR          *pbstr,
  [in, optional] const OLECHAR *psz,
  [in]           unsigned int  len
);
*/
fn SysReAllocStringLen(emu: &mut emu::Emu) {
    let pbstr_ptr = emu.regs.rcx;
    let psz = emu.regs.rdx;
    let len = emu.regs.r8;

    log::info!(
        "{}** {} oleaut32!SysReAllocStringLen pbstr_ptr: 0x{:x} psz: 0x{:x} len: {}",
        emu.colors.light_red,
        emu.pos,
        pbstr_ptr,
        psz,
        len
    );

    // Check if pbstr_ptr is NULL
    if pbstr_ptr == 0 {
        emu.regs.rax = 0; // Return FALSE
        return;
    }

    let size = (len + 1) * 2; // Size in bytes (UTF-16 characters + null terminator)
    let total_size = size + 8; // Add metadata size

    // Allocate new memory
    let new_base = emu.maps.alloc(total_size + 100).expect("oleaut32!SysReAllocStringLen out of memory");

    // Create new memory map
    let name = format!("alloc_{:x}", new_base);
    emu.maps.create_map(&name, new_base, total_size + 100);

    // Copy data from psz if it's not NULL
    if psz != 0 {
        emu.maps.memcpy(new_base + 8, psz, len as usize * 2);
    }

    // Free old string (reading old BSTR pointer from pbstr_ptr)
    let old_bstr = emu.maps.read_qword(pbstr_ptr).unwrap_or(0);
    if old_bstr != 0 {
        // Optional: Free the old allocation if needed
        // emu.maps.free(&format!("alloc_{:x}", old_bstr - 8));
    }

    // Update the BSTR pointer
    emu.maps.write_qword(pbstr_ptr, new_base + 8);

    log::info!(
        "{}** {} oleaut32!SysReAllocStringLen allocated new string at 0x{:x} size: {} {}",
        emu.colors.light_red,
        emu.pos,
        new_base + 8,
        size,
        emu.colors.nc
    );

    emu.regs.rax = 1; // Return TRUE for success
}

/*
HRESULT VariantClear(
  [in, out] VARIANTARG *pvarg
);
*/
fn VariantClear(emu: &mut emu::Emu) {
    let pvarg = emu.regs.rcx;

    log::info!(
        "{}** {} oleaut32!VariantClear pvarg: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        pvarg,
        emu.colors.nc
    );

    // TODO: do something

    emu.regs.rax = 0; // S_OK
}