use crate::emu;
use crate::constants;
use crate::serialization;
//use crate::endpoint;
use crate::winapi32::helper;
use crate::winapi32::kernel32;

use lazy_static::lazy_static;
use std::sync::Mutex;

pub fn gateway(addr: u32, emu: &mut emu::Emu) -> String {
    let api = kernel32::guess_api_name(emu, addr);
    match api.as_str() {
        "InternetOpenA" => InternetOpenA(emu),
        "InternetOpenW" => InternetOpenW(emu),
        "InternetConnectA" => InternetConnectA(emu),
        "InternetConnectW" => InternetConnectW(emu),
        "HttpOpenRequestA" => HttpOpenRequestA(emu),
        "HttpOpenRequestW" => HttpOpenRequestW(emu),
        "InternetSetOptionA" => InternetSetOptionA(emu),
        "InternetSetOptionW" => InternetSetOptionW(emu),
        "HttpSendRequestA" => HttpSendRequestA(emu),
        "HttpSendRequestW" => HttpSendRequestW(emu),
        "InternetReadFile" => InternetReadFile(emu),
        "InternetErrorDlg" => InternetErrorDlg(emu),
        "HttpQueryInfoA" => HttpQueryInfoA(emu),
        "InternetCloseHandle" => InternetCloseHandle(emu),
        "InternetCrackUrlA" => InternetCrackUrlA(emu),
        "InternetCrackUrlW" => InternetCrackUrlW(emu),
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

lazy_static! {
    static ref COUNT_RECEIVE: Mutex<u32> = Mutex::new(0);
}

pub fn InternetOpenA(emu: &mut emu::Emu) {
    let uagent_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("wininet!InternetOpenA  cannot read uagent_ptr") as u64;
    let access = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("wininet!InternetOpenA  cannot read access") as u64;
    let proxy_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("wininet!InternetOpenA  cannot read proxy_ptr") as u64;
    let proxybypass_ptr =
        emu.maps
            .read_dword(emu.regs.get_esp() + 12)
            .expect("wininet!InternetOpenA  cannot read proxybypass_ptr") as u64;
    let flags = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("wininet!InternetOpenA  cannot read flags");

    let mut uagent = "".to_string();
    let mut proxy = "".to_string();
    let mut proxy_bypass = "".to_string();

    if uagent_ptr != 0 {
        uagent = emu.maps.read_string(uagent_ptr);
    }
    if proxy_ptr != 0 {
        proxy = emu.maps.read_string(proxy_ptr);
    }
    if proxybypass_ptr != 0 {
        proxy_bypass = emu.maps.read_string(proxybypass_ptr);
    }

    log::info!(
        "{}** {} wininet!InternetOpenA uagent: {} proxy: {} {} {}",
        emu.colors.light_red,
        emu.pos,
        uagent,
        proxy,
        proxy_bypass,
        emu.colors.nc
    );

    for _ in 0..5 {
        emu.stack_pop32(false);
    }

    /*
    if emu.cfg.endpoint {
        // endpoint mode
        if uagent_ptr != 0 && uagent != "" {
            endpoint::http_set_headers("User-Agent", &uagent);
        }
    }*/

    let uri = format!("uagent://{}", uagent);
    emu.regs.rax = helper::handler_create(&uri);
}

pub fn InternetOpenW(emu: &mut emu::Emu) {
    let uagent_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("wininet!InternetOpenW  cannot read uagent_ptr") as u64;
    let access = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("wininet!InternetOpenW  cannot read access") as u64;
    let proxy_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("wininet!InternetOpenW  cannot read proxy_ptr") as u64;
    let proxybypass_ptr =
        emu.maps
            .read_dword(emu.regs.get_esp() + 12)
            .expect("wininet!InternetOpenW  cannot read proxybypass_ptr") as u64;
    let flags = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("wininet!InternetOpenW  cannot read flags");

    let mut uagent = "".to_string();
    let mut proxy = "".to_string();
    let mut proxy_bypass = "".to_string();

    if uagent_ptr != 0 {
        uagent = emu.maps.read_wide_string(uagent_ptr);
    }
    if proxy_ptr != 0 {
        proxy = emu.maps.read_wide_string(proxy_ptr);
    }
    if proxybypass_ptr != 0 {
        proxy_bypass = emu.maps.read_wide_string(proxybypass_ptr);
    }

    log::info!(
        "{}** {} wininet!InternetOpenW uagent: {} proxy: {} {} {}",
        emu.colors.light_red,
        emu.pos,
        uagent,
        proxy,
        proxy_bypass,
        emu.colors.nc
    );

    for _ in 0..5 {
        emu.stack_pop32(false);
    }

    if emu.cfg.endpoint {
        // endpoint mode
        /*
        if uagent_ptr != 0 && uagent != "" {
            endpoint::http_set_headers("User-Agent", &uagent.replace("\x00", ""));
        }*/
    }

    emu.regs.rax = helper::handler_create("InternetOpenW"); // internet handle
}

pub fn InternetConnectA(emu: &mut emu::Emu) {
    let internet_hndl = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("wininet!InternetConnectA cannot read hndl") as u64;
    let server_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("wininet!InternetConnectA cannot read server_ptr") as u64;
    let port = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("wininet!InternetConnectA cannot read port");
    let login_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("wininet!InternetConnectA cannot read login_ptr") as u64;
    let passw_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("wininet!InternetConnectA cannot read passw_ptr") as u64;
    let service = emu
        .maps
        .read_dword(emu.regs.get_esp() + 20)
        .expect("wininet!InternetConnectA cannot read service");
    let flags = emu
        .maps
        .read_dword(emu.regs.get_esp() + 24)
        .expect("wininet!InternetConnectA cannot read flags");
    let ctx = emu
        .maps
        .read_dword(emu.regs.get_esp() + 28)
        .expect("wininet!InternetConnectA cannot read ctx");

    let mut server = "".to_string();
    let mut login = "".to_string();
    let mut passw = "".to_string();

    if server_ptr != 0 {
        server = emu.maps.read_string(server_ptr);
    }
    if login_ptr != 0 {
        login = emu.maps.read_string(login_ptr);
    }
    if passw_ptr != 0 {
        passw = emu.maps.read_string(passw_ptr);
    }

    log::info!(
        "{}** {} wininet!InternetConnectA host: {} port: {} login: {} passw: {} {}",
        emu.colors.light_red,
        emu.pos,
        server,
        port,
        login,
        passw,
        emu.colors.nc
    );

    if !helper::handler_exist(internet_hndl) {
        log::info!("\tinvalid handle.");
    }

    /*
    if emu.cfg.endpoint {
        endpoint::http_set_serverport(&server, port as u16);
    }*/

    for _ in 0..8 {
        emu.stack_pop32(false);
    }

    let uri = format!("InternetConnectA://{}", server);
    emu.regs.rax = helper::handler_create(&uri); // connect handle
}

pub fn InternetConnectW(emu: &mut emu::Emu) {
    let internet_hndl = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("wininet!InternetConnectW cannot read hndl") as u64;
    let server_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("wininet!InternetConnectW cannot read server_ptr") as u64;
    let port = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("wininet!InternetConnectW cannot read port");
    let login_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("wininet!InternetConnectW cannot read login_ptr") as u64;
    let passw_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("wininet!InternetConnectW cannot read passw_ptr") as u64;
    let service = emu
        .maps
        .read_dword(emu.regs.get_esp() + 20)
        .expect("wininet!InternetConnectW cannot read service");
    let flags = emu
        .maps
        .read_dword(emu.regs.get_esp() + 24)
        .expect("wininet!InternetConnectW cannot read flags");
    let ctx = emu
        .maps
        .read_dword(emu.regs.get_esp() + 28)
        .expect("wininet!InternetConnectW cannot read ctx");

    let mut server = "".to_string();
    let mut login = "".to_string();
    let mut passw = "".to_string();

    if server_ptr != 0 {
        server = emu.maps.read_wide_string(server_ptr);
    }
    if login_ptr != 0 {
        login = emu.maps.read_wide_string(login_ptr);
    }
    if passw_ptr != 0 {
        passw = emu.maps.read_wide_string(passw_ptr);
    }

    log::info!(
        "{}** {} wininet!InternetConnectW host: {} port: {} login: {} passw: {} {}",
        emu.colors.light_red,
        emu.pos,
        server,
        port,
        login,
        passw,
        emu.colors.nc
    );

    if !helper::handler_exist(internet_hndl) {
        log::info!("\tinvalid handle.");
    }

    /*
    if emu.cfg.endpoint {
        endpoint::http_set_serverport(&server.replace("\x00", ""), port as u16);
    }*/

    for _ in 0..8 {
        emu.stack_pop32(false);
    }

    let uri = format!("InternetConnectW://{}:{}", server, port);
    emu.regs.rax = helper::handler_create(&uri); // connect handle
}

fn HttpOpenRequestA(emu: &mut emu::Emu) {
    let conn_hndl = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("wininet!HttpOpenRequestA cannot read hndl") as u64;
    let method_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("wininet!HttpOpenRequestA cannot read method_ptr") as u64;
    let path_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("wininet!HttpOpenRequestA cannot read path_ptr") as u64;
    let version_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("wininet!HttpOpenRequestA cannot read version_ptr") as u64;
    let referrer_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("wininet!HttpOpenRequestA cannot read referrer_ptr") as u64;
    let access_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 20)
        .expect("wininet!HttpOpenRequestA cannot read access_ptr") as u64;
    let flags = emu
        .maps
        .read_dword(emu.regs.get_esp() + 24)
        .expect("wininet!HttpOpenRequestA cannot read flags") as u64;
    let ctx = emu
        .maps
        .read_dword(emu.regs.get_esp() + 28)
        .expect("wininet!HttpOpenRequestA cannot read ctx");

    let mut method = "".to_string();
    let mut path = "".to_string();
    let mut version = "".to_string();
    let mut referrer = "".to_string();
    let mut access = "".to_string();

    if method_ptr != 0 {
        method = emu.maps.read_string(method_ptr);
    }
    if path_ptr != 0 {
        path = emu.maps.read_string(path_ptr);
    }
    if version_ptr != 0 {
        version = emu.maps.read_string(version_ptr);
    }
    if referrer_ptr != 0 {
        referrer = emu.maps.read_string(referrer_ptr);
    }
    if access_ptr != 0 {
        access = emu.maps.read_string(access_ptr);
    }

    log::info!(
        "{}** {} wininet!HttpOpenRequestA method: {} path: {} ver: {} ref: {} access: {} {}",
        emu.colors.light_red,
        emu.pos,
        method,
        path,
        version,
        referrer,
        access,
        emu.colors.nc
    );

    if !helper::handler_exist(conn_hndl) {
        log::info!("\tinvalid handle.");
    }

    if flags & constants::INTERNET_FLAG_SECURE == 1 {
        log::info!("\tssl communication.");
    }

    /*
    if emu.cfg.endpoint {
        endpoint::http_set_path(&path);
        if flags & constants::INTERNET_FLAG_SECURE == 1 {
            endpoint::http_set_ssl();
        }

        if method_ptr != 0 {
            if method == "" {
                endpoint::http_set_method("get");
            } else {
                endpoint::http_set_method(&method);
            }
        } else {
            endpoint::http_set_method("get");
        }
    }*/

    for _ in 0..8 {
        emu.stack_pop32(false);
    }

    let uri = format!("HttpOpenRequestA://{}", path);
    emu.regs.rax = helper::handler_create(&uri); // request handle
}

fn HttpOpenRequestW(emu: &mut emu::Emu) {
    let conn_hndl = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("wininet!HttpOpenRequestW cannot read hndl") as u64;
    let method_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("wininet!HttpOpenRequestW cannot read method_ptr") as u64;
    let path_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("wininet!HttpOpenRequestW cannot read path_ptr") as u64;
    let version_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("wininet!HttpOpenRequestW cannot read version_ptr") as u64;
    let referrer_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("wininet!HttpOpenRequestW cannot read referrer_ptr") as u64;
    let access_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 20)
        .expect("wininet!HttpOpenRequestW cannot read access_ptr") as u64;
    let flags = emu
        .maps
        .read_dword(emu.regs.get_esp() + 24)
        .expect("wininet!HttpOpenRequestW cannot read flags") as u64;
    let ctx = emu
        .maps
        .read_dword(emu.regs.get_esp() + 28)
        .expect("wininet!HttpOpenRequestW cannot read ctx");

    let mut method = "".to_string();
    let mut path = "".to_string();
    let mut version = "".to_string();
    let mut referrer = "".to_string();
    let mut access = "".to_string();
    if method_ptr != 0 {
        method = emu.maps.read_wide_string(method_ptr);
    }
    if path_ptr != 0 {
        path = emu.maps.read_wide_string(path_ptr);
    }
    if version_ptr != 0 {
        version = emu.maps.read_wide_string(version_ptr);
    }
    if referrer_ptr != 0 {
        referrer = emu.maps.read_wide_string(referrer_ptr);
    }
    if access_ptr != 0 {
        access = emu.maps.read_wide_string(access_ptr);
    }

    log::info!(
        "{}** {} wininet!HttpOpenRequestW method: {} path: {} ver: {} ref: {} access: {} {}",
        emu.colors.light_red,
        emu.pos,
        method,
        path,
        version,
        referrer,
        access,
        emu.colors.nc
    );

    if !helper::handler_exist(conn_hndl) {
        log::info!("\tinvalid handle.");
    }

    /*
    if emu.cfg.endpoint {
        endpoint::http_set_path(&path);
        if flags & constants::INTERNET_FLAG_SECURE == 1 {
            endpoint::http_set_ssl();
        }

        if method_ptr != 0 {
            if method.len() < 3 {
                endpoint::http_set_method("get");
            } else {
                endpoint::http_set_method(&method.replace("\x00", ""));
            }
        } else {
            endpoint::http_set_method("get");
        }
    }*/

    for _ in 0..8 {
        emu.stack_pop32(false);
    }

    let uri = format!("HttpOpenRequestW://{}", path);
    emu.regs.rax = helper::handler_create(&uri); // request handle
}

fn InternetSetOptionA(emu: &mut emu::Emu) {
    let inet_hndl = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("wininet!InternetSetOptionA cannot read inet_hndl") as u64;
    let option = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("wininet!InternetSetOptionA cannot read option");
    let buffer = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("wininet!InternetSetOptionA cannot read buffer") as u64;
    let len = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("wininet!InternetSetOptionA cannot read len");

    let mut buffer_content = "".to_string();
    if buffer != 0 {
        buffer_content = emu.maps.read_string_of_bytes(buffer, len as usize);
    }
    let sbuff = emu.maps.read_string(buffer);

    log::info!(
        "{}** {} wininet!InternetSetOptionA option: 0x{:x} buff: {{{}}} {} {}",
        emu.colors.light_red,
        emu.pos,
        option,
        buffer_content,
        sbuff,
        emu.colors.nc
    );

    if !helper::handler_exist(inet_hndl) {
        log::info!("\tinvalid handle.");
    }

    for _ in 0..4 {
        emu.stack_pop32(false);
    }

    emu.regs.rax = 1; // true
}

fn InternetSetOptionW(emu: &mut emu::Emu) {
    let inet_hndl = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("wininet!InternetSetOptionW cannot read inet_hndl") as u64;
    let option = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("wininet!InternetSetOptionW cannot read option");
    let buffer = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("wininet!InternetSetOptionW cannot read buffer") as u64;
    let len = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("wininet!InternetSetOptionW cannot read len");

    let mut buffer_content = "".to_string();
    if buffer != 0 {
        buffer_content = emu.maps.read_string_of_bytes(buffer, len as usize);
    }
    let sbuff = emu.maps.read_wide_string(buffer);

    log::info!(
        "{}** {} wininet!InternetSetOptionW option: 0x{:x} buff: {{{}}} {} {}",
        emu.colors.light_red,
        emu.pos,
        option,
        buffer_content,
        sbuff,
        emu.colors.nc
    );

    if !helper::handler_exist(inet_hndl) {
        log::info!("\tinvalid handle.");
    }

    for _ in 0..4 {
        emu.stack_pop32(false);
    }

    emu.regs.rax = 1; // true
}

fn HttpSendRequestA(emu: &mut emu::Emu) {
    let req_hndl = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("wininet!HttpSendRequestA cannot read req_hndl") as u64;
    let hdrs_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("wininet!HttpSendRequestA cannot read hdrs_ptr") as u64;
    let hdrs_len = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("wininet!HttpSendRequestA cannot read hdrs_len") as u64;
    let opt_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("wininet!HttpSendRequestA cannot read opt_ptr") as u64;
    let opt_len = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("wininet!HttpSendRequestA cannot read opt_len");

    let hdrs = emu.maps.read_string(hdrs_ptr);
    let opt = emu.maps.read_string(opt_ptr);

    log::info!(
        "{}** {} wininet!HttpSendRequestA hdrs: {} opt: {} {}",
        emu.colors.light_red,
        emu.pos,
        hdrs,
        opt,
        emu.colors.nc
    );

    if !helper::handler_exist(req_hndl) {
        log::info!("\tinvalid handle.");
    }

    /*
    if emu.cfg.endpoint {
        endpoint::http_set_headers_str(&hdrs);
        endpoint::http_send_request();
    }*/

    for _ in 0..5 {
        emu.stack_pop32(false);
    }

    emu.regs.rax = 1; // true
}

fn HttpSendRequestW(emu: &mut emu::Emu) {
    let req_hndl = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("wininet!HttpSendRequestW cannot read req_hndl") as u64;
    let hdrs_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("wininet!HttpSendRequestW cannot read hdrs_ptr") as u64;
    let hdrs_len = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("wininet!HttpSendRequestW cannot read hdrs_len");
    let opt_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("wininet!HttpSendRequestW cannot read opt_ptr") as u64;
    let opt_len = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("wininet!HttpSendRequestW cannot read opt_len");

    let hdrs = emu.maps.read_wide_string(hdrs_ptr);
    let opt = emu.maps.read_wide_string(opt_ptr);

    log::info!(
        "{}** {} wininet!HttpSendRequestW hdrs: {} opt: {} {}",
        emu.colors.light_red,
        emu.pos,
        hdrs,
        opt,
        emu.colors.nc
    );

    if !helper::handler_exist(req_hndl) {
        log::info!("\tinvalid handle.");
    }

    /*
    if emu.cfg.endpoint {
        endpoint::http_set_headers_str(&hdrs.replace("\x00", ""));
        endpoint::http_send_request();
    }*/

    for _ in 0..5 {
        emu.stack_pop32(false);
    }

    emu.regs.rax = 1; // true
}

fn InternetErrorDlg(emu: &mut emu::Emu) {
    let err = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("wininet!InternetErrorDlg cannot read error");

    log::info!(
        "{}** {} wininet!InternetErrorDlg err: {} {}",
        emu.colors.light_red,
        emu.pos,
        err,
        emu.colors.nc
    );

    for _ in 0..5 {
        emu.stack_pop32(false);
    }
    emu.regs.rax = 0;
}

fn InternetReadFile(emu: &mut emu::Emu) {
    let file_hndl = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("wininet!InternetReadFile cannot read file_hndl") as u64;
    let buff_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("wininet!InternetReadFile cannot read buff_ptr") as u64;
    let bytes_to_read =
        emu.maps
            .read_dword(emu.regs.get_esp() + 8)
            .expect("wininet!InternetReadFile cannot read bytes_to_read") as u64;
    let bytes_read_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("wininet!InternetReadFile cannot read bytes_read") as u64;

    log::info!(
        "{}** {} wininet!InternetReadFile sz: {} buff: 0x{:x} {}",
        emu.colors.light_red,
        emu.pos,
        bytes_to_read,
        buff_ptr,
        emu.colors.nc
    );

    if !helper::handler_exist(file_hndl) {
        log::info!("\tinvalid handle.");
    }

    if emu.cfg.endpoint {
        /*
        let buff = endpoint::http_read_data();
        emu.maps.write_buffer(buff_ptr, &buff);
        emu.maps.write_dword(bytes_read_ptr, buff.len() as u32);
        */
    } else {
        let mut count = COUNT_RECEIVE.lock().unwrap();
        *count += 1;

        if *count < 3 {
            emu.maps.write_spaced_bytes(buff_ptr, "90 90 90 90");
            emu.maps.write_dword(bytes_read_ptr, bytes_to_read as u32);
        } else {
            emu.maps.write_dword(bytes_read_ptr, 0);
        }
    }

    for _ in 0..4 {
        emu.stack_pop32(false);
    }

    emu.regs.rax = 1; // true
}

fn HttpQueryInfoA(emu: &mut emu::Emu) {
    let hrequest = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("wininet!HttpQueryInfoA cannot read hrequest") as u64;
    let infolvl = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("wininet!HttpQueryInfoA cannot read infolvl") as u64;
    let buff = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("wininet!HttpQueryInfoA cannot read buffer") as u64;
    let buff_len = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("wininet!HttpQueryInfoA cannot read buffer len") as u64;
    let index = emu
        .maps
        .read_dword(emu.regs.get_esp() + 16)
        .expect("wininet!HttpQueryInfoA cannot read index") as u64;

    log::info!(
        "{}** {} wininet!HttpQueryInfoA buff: 0x{:x} sz:{} {}",
        emu.colors.light_red,
        emu.pos,
        buff,
        buff_len,
        emu.colors.nc
    );

    for _ in 0..5 {
        emu.stack_pop32(false);
    }

    emu.regs.rax = 1; // true
}

fn InternetCloseHandle(emu: &mut emu::Emu) {
    let handle = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("wininet!InternetCloseHandle cannot read handle") as u64;

    log::info!(
        "{}** {} wininet!InternetCloseHandle handle: {:x} {}",
        emu.colors.light_red,
        emu.pos,
        handle,
        emu.colors.nc
    );

    helper::handler_close(handle);
    emu.stack_pop32(false);
    emu.regs.rax = 1; // true
}

fn InternetCrackUrlA(emu: &mut emu::Emu) {
    let url_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("wininet!InternetCrackUrlA error reading url_ptr") as u64;
    let url_len = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("wininet!InternetCrackUrlA error reading flags");
    let flags = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("wininet!InternetCrackUrlA error reading reserved");
    let components = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("wininet!InternetCrackUrlA error reading component");

    let url = emu.maps.read_string(url_ptr);

    log::info!(
        "{}** {} wininet!InternetCrackUrlA url: `{}` {}",
        emu.colors.light_red,
        emu.pos,
        url,
        emu.colors.nc
    );

    for _ in 0..4 {
        emu.stack_pop32(false);
    }
    emu.regs.rax = 1;
}

fn InternetCrackUrlW(emu: &mut emu::Emu) {
    let url_ptr = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("wininet!InternetCrackUrlW error reading url_ptr") as u64;
    let url_len = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("wininet!InternetCrackUrlW error reading url_len");
    let flags = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("wininet!InternetCrackUrlW error reading flags");
    let components = emu
        .maps
        .read_dword(emu.regs.get_esp() + 12)
        .expect("wininet!InternetCrackUrlW error reading components");

    let url = emu.maps.read_wide_string(url_ptr);

    log::info!(
        "{}** {} wininet!InternetCrackUrlW url: `{}` {}",
        emu.colors.light_red,
        emu.pos,
        url,
        emu.colors.nc
    );

    for _ in 0..4 {
        emu.stack_pop32(false);
    }

    emu.regs.rax = 1;
}
