use crate::emu32;


pub fn gateway(addr:u32, emu:&mut emu32::Emu32) {
    match addr {
        0x7633f18e => InternetOpenA(emu),
        0x76339197 => InternetOpenW(emu),
        0x763349e9 => InternetConnectA(emu),
        0x7633492c => InternetConnectW(emu),
        0x76334c7d => HttpOpenRequestA(emu),
        0x76334a42 => HttpOpenRequestW(emu),
        0x763275e8 => InternetSetOptionA(emu),
        0x76327741 => InternetSetOptionW(emu),
        0x763a18f8 => HttpSendRequestA(emu),
        0x7633ba12 => HttpSendRequestW(emu),
        0x7632b406 => InternetReadFile(emu),
        0x763b3328 => InternetErrorDlg(emu),
        _ => panic!("calling unimplemented wininet API 0x{:x}", addr)
    }
}


pub fn InternetOpenA(emu:&mut emu32::Emu32) {
    let uagent_ptr = emu.maps.read_dword(emu.regs.esp).expect("wininet!InternetOpenA  cannot read uagent_ptr");
    let access = emu.maps.read_dword(emu.regs.esp+4).expect("wininet!InternetOpenA  cannot read access");
    let proxy_ptr = emu.maps.read_dword(emu.regs.esp+8).expect("wininet!InternetOpenA  cannot read proxy_ptr");
    let proxybypass_ptr = emu.maps.read_dword(emu.regs.esp+12).expect("wininet!InternetOpenA  cannot read proxybypass_ptr");
    let flags =  emu.maps.read_dword(emu.regs.esp+16).expect("wininet!InternetOpenA  cannot read flags");

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
    

    println!("{}** {} wininet!InternetOpenA uagent:{} proxy:{} {} {}", emu.colors.light_red, emu.pos, uagent, proxy, proxy_bypass, emu.colors.nc);

    for _ in 0..5 {
        emu.stack_pop(false);
    }

    emu.regs.eax = 0x11111111; // internet handle
}

pub fn InternetOpenW(emu:&mut emu32::Emu32) {
    let uagent_ptr = emu.maps.read_dword(emu.regs.esp).expect("wininet!InternetOpenW  cannot read uagent_ptr");
    let access = emu.maps.read_dword(emu.regs.esp+4).expect("wininet!InternetOpenW  cannot read access");
    let proxy_ptr = emu.maps.read_dword(emu.regs.esp+8).expect("wininet!InternetOpenW  cannot read proxy_ptr");
    let proxybypass_ptr = emu.maps.read_dword(emu.regs.esp+12).expect("wininet!InternetOpenW  cannot read proxybypass_ptr");
    let flags =  emu.maps.read_dword(emu.regs.esp+16).expect("wininet!InternetOpenW  cannot read flags");

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

    println!("{}** {} wininet!InternetOpenW uagent:{} proxy:{} {} {}", emu.colors.light_red, emu.pos, uagent, proxy, proxy_bypass, emu.colors.nc);

    for _ in 0..5 {
        emu.stack_pop(false);
    }

    emu.regs.eax = 0x11111111; // internet handle
}

pub fn InternetConnectA(emu:&mut emu32::Emu32) {
    let internet_hndl = emu.maps.read_dword(emu.regs.esp).expect("wininet!InternetConnectA cannot read hndl");
    let server_ptr = emu.maps.read_dword(emu.regs.esp+4).expect("wininet!InternetConnectA cannot read server_ptr");
    let port = emu.maps.read_dword(emu.regs.esp+8).expect("wininet!InternetConnectA cannot read port");
    let login_ptr = emu.maps.read_dword(emu.regs.esp+12).expect("wininet!InternetConnectA cannot read login_ptr");
    let passw_ptr = emu.maps.read_dword(emu.regs.esp+16).expect("wininet!InternetConnectA cannot read passw_ptr");
    let service = emu.maps.read_dword(emu.regs.esp+20).expect("wininet!InternetConnectA cannot read service");
    let flags  = emu.maps.read_dword(emu.regs.esp+24).expect("wininet!InternetConnectA cannot read flags");
    let ctx  = emu.maps.read_dword(emu.regs.esp+28).expect("wininet!InternetConnectA cannot read ctx");

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


    println!("{}** {} wininet!InternetConnectA host:{} port:{} login:{} passw:{} {}", emu.colors.light_red, emu.pos, server, port, login, passw, emu.colors.nc);

    for _ in 0..8 {
        emu.stack_pop(false);
    }

    emu.regs.eax = 0x22222222; // connect handle
}

pub fn InternetConnectW(emu:&mut emu32::Emu32) {
    let internet_hndl = emu.maps.read_dword(emu.regs.esp).expect("wininet!InternetConnectW cannot read hndl");
    let server_ptr = emu.maps.read_dword(emu.regs.esp+4).expect("wininet!InternetConnectW cannot read server_ptr");
    let port = emu.maps.read_dword(emu.regs.esp+8).expect("wininet!InternetConnectW cannot read port");
    let login_ptr = emu.maps.read_dword(emu.regs.esp+12).expect("wininet!InternetConnectW cannot read login_ptr");
    let passw_ptr = emu.maps.read_dword(emu.regs.esp+16).expect("wininet!InternetConnectW cannot read passw_ptr");
    let service = emu.maps.read_dword(emu.regs.esp+20).expect("wininet!InternetConnectW cannot read service");
    let flags  = emu.maps.read_dword(emu.regs.esp+24).expect("wininet!InternetConnectW cannot read flags");
    let ctx  = emu.maps.read_dword(emu.regs.esp+28).expect("wininet!InternetConnectW cannot read ctx");

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


    println!("{}** {} wininet!InternetConnectW host: {} port: {} login: {} passw: {} {}", emu.colors.light_red, emu.pos, server, port, login, passw, emu.colors.nc);

    for _ in 0..8 {
        emu.stack_pop(false);
    }

    emu.regs.eax = 0x22222222; // connect handle
}

fn HttpOpenRequestA(emu:&mut emu32::Emu32) {
    let conn_hndl = emu.maps.read_dword(emu.regs.esp).expect("wininet!HttpOpenRequestA cannot read hndl");
    let method_ptr = emu.maps.read_dword(emu.regs.esp+4).expect("wininet!HttpOpenRequestA cannot read method_ptr");
    let path_ptr = emu.maps.read_dword(emu.regs.esp+8).expect("wininet!HttpOpenRequestA cannot read path_ptr");
    let version_ptr = emu.maps.read_dword(emu.regs.esp+12).expect("wininet!HttpOpenRequestA cannot read version_ptr");
    let referrer_ptr = emu.maps.read_dword(emu.regs.esp+16).expect("wininet!HttpOpenRequestA cannot read referrer_ptr");
    let access_ptr = emu.maps.read_dword(emu.regs.esp+20).expect("wininet!HttpOpenRequestA cannot read access_ptr");
    let flags = emu.maps.read_dword(emu.regs.esp+24).expect("wininet!HttpOpenRequestA cannot read flags");
    let ctx = emu.maps.read_dword(emu.regs.esp+28).expect("wininet!HttpOpenRequestA cannot read ctx");

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

    println!("{}** {} wininet!HttpOpenRequestA method: {} path: {} ver: {} ref: {} access: {} {}", emu.colors.light_red, emu.pos, method, path, version, referrer, access, emu.colors.nc);


    for _ in 0..8 {
        emu.stack_pop(false);
    }

    emu.regs.eax = 0x33333333; // request handle

}

fn HttpOpenRequestW(emu:&mut emu32::Emu32) {
    let conn_hndl = emu.maps.read_dword(emu.regs.esp).expect("wininet!HttpOpenRequestW cannot read hndl");
    let method_ptr = emu.maps.read_dword(emu.regs.esp+4).expect("wininet!HttpOpenRequestW cannot read method_ptr");
    let path_ptr = emu.maps.read_dword(emu.regs.esp+8).expect("wininet!HttpOpenRequestW cannot read path_ptr");
    let version_ptr = emu.maps.read_dword(emu.regs.esp+12).expect("wininet!HttpOpenRequestW cannot read version_ptr");
    let referrer_ptr = emu.maps.read_dword(emu.regs.esp+16).expect("wininet!HttpOpenRequestW cannot read referrer_ptr");
    let access_ptr = emu.maps.read_dword(emu.regs.esp+20).expect("wininet!HttpOpenRequestW cannot read access_ptr");
    let flags = emu.maps.read_dword(emu.regs.esp+24).expect("wininet!HttpOpenRequestW cannot read flags");
    let ctx = emu.maps.read_dword(emu.regs.esp+28).expect("wininet!HttpOpenRequestW cannot read ctx");

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

    println!("{}** {} wininet!HttpOpenRequestW method: {} path: {} ver: {} ref: {} access: {} {}", emu.colors.light_red, emu.pos, method, path, version, referrer, access, emu.colors.nc);


    for _ in 0..8 {
        emu.stack_pop(false);
    }

    emu.regs.eax = 0x33333333; // request handle

}

fn InternetSetOptionA(emu:&mut emu32::Emu32) {
    let inet_hndl = emu.maps.read_dword(emu.regs.esp).expect("wininet!InternetSetOptionA cannot read inet_hndl");
    let option = emu.maps.read_dword(emu.regs.esp+4).expect("wininet!InternetSetOptionA cannot read option"); 
    let buffer = emu.maps.read_dword(emu.regs.esp+8).expect("wininet!InternetSetOptionA cannot read buffer"); 
    let len = emu.maps.read_dword(emu.regs.esp+12).expect("wininet!InternetSetOptionA cannot read len");

    let mut buffer_content = "".to_string();
    if buffer != 0 {
        buffer_content =  emu.maps.read_string_of_bytes(buffer, len as usize);
    }
    let sbuff = emu.maps.read_string(buffer);

    println!("{}** {} wininet!InternetSetOptionA option: 0x{:x} buff: {{{}}} {} {}", emu.colors.light_red, emu.pos, option, buffer_content, sbuff, emu.colors.nc);

    for _ in 0..4 {
        emu.stack_pop(false);
    }

    emu.regs.eax = 1; // true 
}

fn InternetSetOptionW(emu:&mut emu32::Emu32) {
    let inet_hndl = emu.maps.read_dword(emu.regs.esp).expect("wininet!InternetSetOptionW cannot read inet_hndl");
    let option = emu.maps.read_dword(emu.regs.esp+4).expect("wininet!InternetSetOptionW cannot read option"); 
    let buffer = emu.maps.read_dword(emu.regs.esp+8).expect("wininet!InternetSetOptionW cannot read buffer"); 
    let len = emu.maps.read_dword(emu.regs.esp+12).expect("wininet!InternetSetOptionW cannot read len");

    let mut buffer_content = "".to_string();
    if buffer != 0 {
        buffer_content =  emu.maps.read_string_of_bytes(buffer, len as usize);
    }
    let sbuff = emu.maps.read_wide_string(buffer);

    println!("{}** {} wininet!InternetSetOptionW option: 0x{:x} buff: {{{}}} {} {}", emu.colors.light_red, emu.pos, option, buffer_content, sbuff, emu.colors.nc);

    for _ in 0..4 {
        emu.stack_pop(false);
    }

    emu.regs.eax = 1; // true 
}

fn HttpSendRequestA(emu:&mut emu32::Emu32) {
    let req_hndl = emu.maps.read_dword(emu.regs.esp).expect("wininet!HttpSendRequestA cannot read req_hndl");
    let hdrs_ptr = emu.maps.read_dword(emu.regs.esp+4).expect("wininet!HttpSendRequestA cannot read hdrs_ptr");
    let hdrs_len = emu.maps.read_dword(emu.regs.esp+8).expect("wininet!HttpSendRequestA cannot read hdrs_len");
    let opt_ptr = emu.maps.read_dword(emu.regs.esp+12).expect("wininet!HttpSendRequestA cannot read opt_ptr");
    let opt_len = emu.maps.read_dword(emu.regs.esp+16).expect("wininet!HttpSendRequestA cannot read opt_len");

    let hdrs = emu.maps.read_string(hdrs_ptr);
    let opt = emu.maps.read_string(opt_ptr);

    println!("{}** {} wininet!HttpSendRequestA hdrs: {} opt: {} {}", emu.colors.light_red, emu.pos, hdrs, opt, emu.colors.nc);

    for _ in 0..5 {
        emu.stack_pop(false);
    }

    emu.regs.eax = 1; // true 
}

fn HttpSendRequestW(emu:&mut emu32::Emu32) {
    let req_hndl = emu.maps.read_dword(emu.regs.esp).expect("wininet!HttpSendRequestW cannot read req_hndl");
    let hdrs_ptr = emu.maps.read_dword(emu.regs.esp+4).expect("wininet!HttpSendRequestW cannot read hdrs_ptr");
    let hdrs_len = emu.maps.read_dword(emu.regs.esp+8).expect("wininet!HttpSendRequestW cannot read hdrs_len");
    let opt_ptr = emu.maps.read_dword(emu.regs.esp+12).expect("wininet!HttpSendRequestW cannot read opt_ptr");
    let opt_len = emu.maps.read_dword(emu.regs.esp+16).expect("wininet!HttpSendRequestW cannot read opt_len");

    let hdrs = emu.maps.read_wide_string(hdrs_ptr);
    let opt = emu.maps.read_wide_string(opt_ptr);

    println!("{}** {} wininet!HttpSendRequestW hdrs: {} opt: {} {}", emu.colors.light_red, emu.pos, hdrs, opt, emu.colors.nc);

    for _ in 0..5 {
        emu.stack_pop(false);
    }

    emu.regs.eax = 1; // true 
}

fn InternetErrorDlg(emu:&mut emu32::Emu32) {
    let err = emu.maps.read_dword(emu.regs.esp+8).expect("wininet!InternetErrorDlg cannot read error");

    println!("{}** {} wininet!InternetErrorDlg err: {} {}", emu.colors.light_red, emu.pos, err, emu.colors.nc);

    for _ in 0..5 {
        emu.stack_pop(false);
    }
    emu.regs.eax = 0;
}

fn InternetReadFile(emu:&mut emu32::Emu32) {
    let file_hndl = emu.maps.read_dword(emu.regs.esp).expect("wininet!InternetReadFile cannot read file_hndl");
    let buff_ptr = emu.maps.read_dword(emu.regs.esp+4).expect("wininet!InternetReadFile cannot read buff_ptr");
    let bytes_to_read = emu.maps.read_dword(emu.regs.esp+8).expect("wininet!InternetReadFile cannot read bytes_to_read");
    let bytes_read_ptr = emu.maps.read_dword(emu.regs.esp+12).expect("wininet!InternetReadFile cannot read bytes_read");

    emu.maps.write_spaced_bytes(buff_ptr, "90 90 90 90".to_string());
    emu.maps.write_dword(bytes_read_ptr, bytes_to_read);

    println!("{}** {} wininet!InternetReadFile sz: {} buff: 0x{:x} {}", emu.colors.light_red, emu.pos, bytes_to_read, buff_ptr, emu.colors.nc);

    for _ in 0..4 {
        emu.stack_pop(false);
    }
    emu.regs.eax = 1; // true
}
