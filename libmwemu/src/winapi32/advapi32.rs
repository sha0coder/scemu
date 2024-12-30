use crate::emu;
use crate::constants::*;
use crate::serialization;
use crate::winapi32::helper;
use crate::winapi32::kernel32;
use md5;

pub fn gateway(addr: u32, emu: &mut emu::Emu) -> String {
    let api = kernel32::guess_api_name(emu, addr);
    match api.as_str() {
        "StartServiceCtrlDispatcherA" => StartServiceCtrlDispatcherA(emu),
        "StartServiceCtrlDispatcherW" => StartServiceCtrlDispatcherW(emu),
        "LookupPrivilegeValueW" => LookupPrivilegeValueW(emu),
        "CryptAcquireContextA" => CryptAcquireContextA(emu),
        "CryptAcquireContextW" => CryptAcquireContextW(emu),
        "CryptEncrypt" => CryptEncrypt(emu),
        "CryptDecrypt" => CryptDecrypt(emu),
        "CryptCreateHash" => CryptCreateHash(emu),
        "CryptGenKey" => CryptGenKey(emu),
        "CryptGetHashParam" => CryptGetHashParam(emu),
        "CryptGetKeyParam" => CryptGetKeyParam(emu),
        "CryptImportKey" => CryptImportKey(emu),
        "CryptSignHashA" => CryptSignHashA(emu),
        "CryptSignHashW" => CryptSignHashW(emu),
        "CryptReleaseContext" => CryptReleaseContext(emu),
        "CryptHashData" => CryptHashData(emu),
        "CryptDeriveKey" => CryptDeriveKey(emu),

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

    log::info!(
        "{}** {} advapi321!StartServiceCtrlDispatcherA {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.regs.set_eax(1);
}

fn StartServiceCtrlDispatcherW(emu: &mut emu::Emu) {
    let service_table_entry_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("advapi32!StartServiceCtrlDispatcherW error reading service_table_entry pointer");

    log::info!(
        "{}** {} advapi321!StartServiceCtrlDispatcherW {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.regs.set_eax(1);
}

///// CRYPTO API /////

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

    log::info!(
        "{}** {} advapi321!CryptAcquireContextA =0x{:x} type: {} flags: `{}` {}",
        emu.colors.light_red,
        emu.pos,
        hndl,
        prov_type,
        &sflags,
        emu.colors.nc
    );

    for _ in 0..5 {
        emu.stack_pop32(false);
    }
    emu.regs.rax = 1;
}

fn CryptAcquireContextW(emu: &mut emu::Emu) {
    let out_handle =
        emu.maps
            .read_dword(emu.regs.get_esp())
            .expect("advapi32!CryptAcquireContextW error reading handle pointer") as u64;
    let container = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("advapi32!CryptAcquireContextW error reading container");
    let provider = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("advapi32!CryptAcquireContextW error reading provider");
    let prov_type = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("advapi32!CryptAcquireContextW error reading prov_type");
    let flags = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("advapi32!CryptAcquireContextW error reading flags");

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

    log::info!(
        "{}** {} advapi321!CryptAcquireContextW =0x{:x} type: {} flags: `{}` {}",
        emu.colors.light_red,
        emu.pos,
        hndl,
        prov_type,
        &sflags,
        emu.colors.nc
    );

    for _ in 0..5 {
        emu.stack_pop32(false);
    }
    emu.regs.rax = 1;
}

fn LookupPrivilegeValueW(emu: &mut emu::Emu) {
    let ptr_sysname = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("advapi32!LookupPrivilegeValueW error reading param") as u64;
    let ptr_name = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("advapi32!LookupPrivilegeValueW error reading param") as u64;
    let ptr_uid = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("advapi32!LookupPrivilegeValueW error reading param") as u64;

    let sysname = emu.maps.read_wide_string(ptr_sysname);
    let name = emu.maps.read_wide_string(ptr_name);
    emu.maps.write_dword(ptr_uid, 123);

    log::info!(
        "{}** {} advapi321!LookupPrivilegeValueW `{}` `{}` {}",
        emu.colors.light_red,
        emu.pos,
        sysname,
        name,
        emu.colors.nc
    );

    for _ in 0..3 {
        emu.stack_pop32(false);
    }
    emu.regs.rax = 1;
}

fn CryptEncrypt(emu: &mut emu::Emu) {
    let hkey = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("advapi32!CryptEncrypt error reading param") as u64;
    let hhash = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("advapi32!CryptEncrypt error reading param") as u64;
    let bfinal = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("advapi32!CryptEncrypt error reading param") as u64;
    let flags = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("advapi32!CryptEncrypt error reading param") as u64;
    let data_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("advapi32!CryptEncrypt error reading param") as u64;
    let data_len_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 20)
        .expect("advapi32!CryptEncrypt error reading param") as u64;
    let buff_len = emu
        .maps
        .read_dword(emu.regs.get_esp() + 24)
        .expect("advapi32!CryptEncrypt error reading param") as u64;

    log::info!(
        "{}** {} advapi32!CryptEncrypt  {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    for _ in 0..7 {
        emu.stack_pop32(false);
    }

    emu.regs.rax = 1;
}

fn CryptDecrypt(emu: &mut emu::Emu) {
    let hkey = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("advapi32!CryptDecrypt error reading param") as u64;
    let hhash = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("advapi32!CryptDecrypt error reading param") as u64;
    let bfinal = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("advapi32!CryptDecrypt error reading param") as u64;
    let flags = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("advapi32!CryptDecrypt error reading param") as u64;
    let data_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("advapi32!CryptDecrypt error reading param") as u64;
    let data_len_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 20)
        .expect("advapi32!CryptDecrypt error reading param") as u64;
    let buff_len = emu
        .maps
        .read_dword(emu.regs.get_esp() + 24)
        .expect("advapi32!CryptDecrypt error reading param") as u64;

    log::info!(
        "{}** {} advapi32!CryptDecrypt  {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    for _ in 0..7 {
        emu.stack_pop32(false);
    }

    emu.regs.rax = 1;
}

fn CryptReleaseContext(emu: &mut emu::Emu) {
    let hndl = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("advapi32!CryptReleaseContext error reading param") as u64;
    let flags = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("advapi32!CryptReleaseContext error reading param") as u64;

    log::info!(
        "{}** {} advapi32!CryptReleaseContext  {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    helper::handler_close(hndl);

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.regs.rax = 1;
}

fn CryptCreateHash(emu: &mut emu::Emu) {
    let hprov = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("advapi32!CryptCreateHash error reading param");
    let algid = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("advapi32!CryptCreateHash error reading param");
    let hkey = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("advapi32!CryptCreateHash error reading param");
    let flags = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("advapi32!CryptCreateHash error reading param");
    let hash_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("advapi32!CryptCreateHash error reading param") as u64;

    log::info!(
        "{}** {} advapi32!CryptCreateHash {} {}",
        emu.colors.light_red,
        emu.pos,
        get_cryptoalgorithm_name(algid),
        emu.colors.nc
    );

    let hndl = helper::handler_create(get_cryptoalgorithm_name(algid));
    assert!(hndl < 0x00000001_00000000);
    emu.maps.write_dword(hash_ptr, hndl as u32);

    for _ in 0..5 {
        emu.stack_pop32(false);
    }
    emu.regs.rax = 1;
}

fn CryptGenKey(emu: &mut emu::Emu) {
    let hprov = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("advapi32!CryptGenKey error reading param");
    let algid = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("advapi32!CryptGenKey error reading param");
    let flags = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("advapi32!CryptGenKey error reading param");
    let hkey_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("advapi32!CryptGenKey error reading param");

    log::info!(
        "{}** {} advapi32!CryptGenKey {} {}",
        emu.colors.light_red,
        emu.pos,
        get_cryptoalgorithm_name(algid),
        emu.colors.nc
    );

    for _ in 0..4 {
        emu.stack_pop32(false);
    }
    emu.regs.rax = 1;
}

fn CryptGetHashParam(emu: &mut emu::Emu) {
    let hhash = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("advapi32!CryptGetHashParam error reading param") as u64;
    let param = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("advapi32!CryptGetHashParam error reading param") as u64;
    let data_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("advapi32!CryptGetHashParam error reading param") as u64;
    let len_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("advapi32!CryptGetHashParam error reading param") as u64;
    let flags = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("advapi32!CryptGetHashParam error reading param") as u64;

    log::info!(
        "{}** {} advapi32!CryptGetHashParam {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    for _ in 0..5 {
        emu.stack_pop32(false);
    }
    emu.regs.rax = 1;
}

fn CryptGetKeyParam(emu: &mut emu::Emu) {
    let hhash = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("advapi32!CryptGetKeyParam error reading param") as u64;
    let param = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("advapi32!CryptGetKeyParam error reading param") as u64;
    let data_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("advapi32!CryptGetKeyParam error reading param") as u64;
    let len_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("advapi32!CryptGetKeyParam error reading param") as u64;
    let flags = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("advapi32!CryptGetKeyParam error reading param") as u64;

    log::info!(
        "{}** {} advapi32!CryptGetKeyParam {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    for _ in 0..5 {
        emu.stack_pop32(false);
    }
    emu.regs.rax = 1;
}

fn CryptImportKey(emu: &mut emu::Emu) {
    let hprov = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("advapi32!CryptImportKey error reading param") as u64;
    let data_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("advapi32!CryptImportKey error reading param") as u64;
    let data_len = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("advapi32!CryptImportKey error reading param") as u64;
    let hpubkey = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("advapi32!CryptImportKey error reading param") as u64;
    let flags = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("advapi32!CryptImportKey error reading param") as u64;
    let hkey_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("advapi32!CryptImportKey error reading param") as u64;

    log::info!(
        "{}** {} advapi32!CryptImportKey {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    for _ in 0..6 {
        emu.stack_pop32(false);
    }
    emu.regs.rax = 1;
}

fn CryptSignHashA(emu: &mut emu::Emu) {
    let hhash = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("advapi32!CryptSignHashA error reading param") as u64;
    let key_spec = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("advapi32!CryptSignHashA error reading param") as u64;
    let desc_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("advapi32!CryptSignHashA error reading param") as u64;
    let flags = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("advapi32!CryptSignHashA error reading param") as u64;
    let sig_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("advapi32!CryptSignHashA error reading param") as u64;
    let sig_len_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("advapi32!CryptSignHashA error reading param") as u64;

    log::info!(
        "{}** {} advapi32!CryptSignHashA {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    for _ in 0..6 {
        emu.stack_pop32(false);
    }
    emu.regs.rax = 1;
}

fn CryptSignHashW(emu: &mut emu::Emu) {
    let hhash = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("advapi32!CryptSignHashW error reading param") as u64;
    let key_spec = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("advapi32!CryptSignHashW error reading param") as u64;
    let desc_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("advapi32!CryptSignHashW error reading param") as u64;
    let flags = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("advapi32!CryptSignHashW error reading param") as u64;
    let sig_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("advapi32!CryptSignHashW error reading param") as u64;
    let sig_len_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("advapi32!CryptSignHashW error reading param") as u64;

    log::info!(
        "{}** {} advapi32!CryptSignHashW {}",
        emu.colors.light_red,
        emu.pos,
        emu.colors.nc
    );

    for _ in 0..6 {
        emu.stack_pop32(false);
    }
    emu.regs.rax = 1;
}

fn CryptHashData(emu: &mut emu::Emu) {
    let hhash = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("advapi32!CryptHashData error on param") as u64;
    let data_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("advapi32!CryptHashData error on param") as u64;
    let data_len = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("advapi32!CryptHashData error on param") as usize;
    let flags = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("advapi32!CryptHashData error on param");

    let data = emu.maps.read_bytes(data_ptr, data_len);

    let mut hex_hash = "".to_string();
    let algo = helper::handler_get_uri(hhash);
    if algo == "CALG_MD5" {
        let digest: md5::Digest = md5::compute(data);
        let hash_bytes = digest.0;
        hex_hash = format!("{:x}", digest);
        helper::handler_put_bytes(hhash, &hash_bytes);
    } else {
        helper::handler_put_bytes(hhash, b"deadcafebabe");
    }

    log::info!(
        "{}** {} advapi32!CryptHashData {} {}",
        emu.colors.light_red,
        emu.pos,
        hex_hash,
        emu.colors.nc
    );

    for _ in 0..4 {
        emu.stack_pop32(false);
    }
    emu.regs.rax = 1;
}

fn CryptDeriveKey(emu: &mut emu::Emu) {
    let hprov = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("advapi32!CryptDeriveKey error on param") as u64;
    let algid = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("advapi32!CryptDeriveKey error on param");
    let data = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("advapi32!CryptDeriveKey error on param") as usize;
    let flags = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("advapi32!CryptDeriveKey error on param") as usize;
    let hkey_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("advapi32!CryptDeriveKey error on param") as u64;

    let alg = get_cryptoalgorithm_name(algid);
    let mut alg_len = get_crypto_key_len(algid);

    let handle = helper::handler_create(alg);
    if alg_len == 0 {
        alg_len = (flags >> 16) & 0xffff;
    }
    helper::handler_put_bytes(handle, &vec![0x41u8; alg_len]);

    log::info!(
        "{}** {} advapi32!CryptDeriveKey {} {}",
        emu.colors.light_red,
        emu.pos,
        alg,
        emu.colors.nc
    );

    for _ in 0..5 {
        emu.stack_pop32(false);
    }
    emu.regs.rax = 1;
}
