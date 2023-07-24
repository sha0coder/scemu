use crate::emu;
use crate::emu::endpoint;
use crate::emu::winapi32::helper;

use lazy_static::lazy_static;
use std::sync::Mutex;

pub fn gateway(addr: u64, emu: &mut emu::Emu) -> String {
    match addr {
        0x7fefeeb4980 => WsaStartup(emu),
        0x7fefeeb2010 => WsaSocketA(emu),
        0x7fefeeb45c0 => connect(emu),
        0x7fefeebdf40 => recv(emu),
        0x7fefeeb8000 => send(emu),
        0x7fefeebde90 => socket(emu),
        0x7fefeeddda0 => WsaHtons(emu),
        0x7fefeeb1250 => htons(emu),
        0x7fefeeb1350 => inet_addr(emu),
        0x7fefeeb1f00 => bind(emu),
        0x7fefeeb8290 => listen(emu),
        0x7fefeebea00 => accept(emu),
        0x7fefeeb18e0 => closesocket(emu),
        0x7fefeebdd30 => setsockopt(emu),
        0x7fefeebe200 => getsockopt(emu),
        0x7fefeebea20 => WsaAccept(emu),
        0x7fefeeb9480 => GetSockName(emu),

        //0x7fefeebd7f0 => sendto(emu),

        /*
        0x774834b5 => sendto(emu),
        0x7748b6dc => recvfrom(emu),
        0x77487089 => WsaRecv(emu),
        0x7748cba6 => WsaRecvFrom(emu),
        0x7748cc3f => WsaConnect(emu),
        */
        _ => {
            let apiname = emu::winapi64::kernel32::guess_api_name(emu, addr);
            println!("calling unimplemented ws2_32 API 0x{:x} {}", addr, apiname);
            return apiname;
        }
    }

    return String::new();
}

lazy_static! {
    static ref COUNT_SEND: Mutex<u32> = Mutex::new(0);
    static ref COUNT_RECV: Mutex<u32> = Mutex::new(0);
}

fn WsaStartup(emu: &mut emu::Emu) {
    println!(
        "{}** {} ws2_32!WsaStartup {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );

    emu.regs.rax = 0;
}

fn WsaSocketA(emu: &mut emu::Emu) {
    println!(
        "{}** {} ws2_32!WsaSocketA {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );

    for _ in 0..2 {
        emu.stack_pop64(false);
    }

    emu.regs.rax = helper::socket_create();
}

fn socket(emu: &mut emu::Emu) {
    println!(
        "{}** {} ws2_32!socket {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );

    emu.regs.rax = helper::socket_create();
}

fn WsaHtons(emu: &mut emu::Emu) {
    let host_port = emu.regs.rdx;
    let out_port = emu.regs.r8;

    println!(
        "{}** {} ws2_32!WsaHtons {} {}",
        emu.colors.light_red, emu.pos, host_port, emu.colors.nc
    );

    //TODO: implement this
    emu.regs.rax = 0;
}

fn htons(emu: &mut emu::Emu) {
    let port: u16 = emu.regs.rcx as u16;

    println!(
        "{}** {} ws2_32!htons port: {} {}",
        emu.colors.light_red, emu.pos, port, emu.colors.nc
    );

    emu.regs.rax = port.to_be() as u64;
}

fn inet_addr(emu: &mut emu::Emu) {
    let addr = emu.regs.rcx;

    //TODO: derreferece addr

    println!(
        "{}** {} ws2_32!inet_addr {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );

    emu.regs.rax = 0;
}

fn connect(emu: &mut emu::Emu) {
    let sock = emu.regs.rcx;
    let sockaddr_ptr = emu.regs.rdx;
    //let sockaddr = emu.maps.read_bytes(sockaddr_ptr, 8);
    let family: u16 = emu
        .maps
        .read_word(sockaddr_ptr)
        .expect("ws2_32!connect: error reading family");
    let port: u16 = emu
        .maps
        .read_word(sockaddr_ptr + 2)
        .expect("ws2_32!connect: error reading port")
        .to_be();
    let ip: u32 = emu
        .maps
        .read_dword(sockaddr_ptr + 4)
        .expect("ws2_32!connect: error reading ip");

    let sip = format!(
        "{}.{}.{}.{}",
        ip & 0xff,
        (ip & 0xff00) >> 8,
        (ip & 0xff0000) >> 16,
        (ip & 0xff000000) >> 24
    );
    println!(
        "{}** {} ws2_32!connect  family: {} {}:{} {}",
        emu.colors.light_red, emu.pos, family, sip, port, emu.colors.nc
    );

    if emu.cfg.endpoint {
        if endpoint::sock_connect(sip.as_str(), port) {
            println!("\tconnected to the endpoint.");
        } else {
            println!("\tcannot connect. dont use -e");
        }
        emu.regs.rax = 0;
    } else {
        // offline mode

        if !helper::socket_exist(sock) {
            println!("\tinvalid socket.");
            emu.regs.rax = 1;
        } else {
            emu.regs.rax = 0;
        }
    }
}

fn recv(emu: &mut emu::Emu) {
    let sock = emu.regs.rcx;
    let buff = emu.regs.rdx;
    let mut len = emu.regs.r8;
    let flags = emu.regs.r9;

    println!(
        "{}** {} ws2_32!recv   buff: 0x{:x} sz: {} {}",
        emu.colors.light_red, emu.pos, buff, len, emu.colors.nc
    );

    if !helper::socket_exist(sock) {
        println!("\tinvalid socket.");
        emu.regs.rax = 1;
        return;
    }

    if emu.cfg.endpoint {
        let mut rbuff: Vec<u8> = vec![0; len as usize];
        let n = endpoint::sock_recv(&mut rbuff);

        emu.maps.write_buffer(buff, &rbuff);

        println!("\nreceived {} bytes from the endpoint.", n);
        emu.regs.rax = n as u64;
    } else {
        let mut count_recv = COUNT_RECV.lock().unwrap();
        *count_recv += 1;
        if *count_recv > 3 {
            len = 0; // finish the recv loop
        }

        if helper::socket_exist(sock) {
            //emu.maps.write_spaced_bytes(buff, "6c 73 0d 0a".to_string()); // send a ls\r\n
            if len == 4 {
                emu.maps.write_dword(buff, 0x0100); // probably expect a size
            } else {
                emu.maps.memset(buff, 0x90, len as usize);
            }

            emu.regs.rax = len;
        }
    }
}

fn send(emu: &mut emu::Emu) {
    let sock = emu.regs.rcx;
    let buff = emu.regs.rdx;
    let mut len = emu.regs.r8;
    let flags = emu.regs.r9;

    let bytes = emu.maps.read_string_of_bytes(buff, len as usize);

    println!(
        "{}** {} ws2_32!send {{{}}}   {}",
        emu.colors.light_red, emu.pos, bytes, emu.colors.nc
    );

    if !helper::socket_exist(sock) {
        println!("\tinvalid socket.");
        emu.regs.rax = 0;
        return;
    }

    if emu.cfg.endpoint {
        let buffer = emu.maps.read_buffer(buff, len as usize);
        let n = endpoint::sock_send(&buffer);
        println!("\tsent {} bytes.", n);
        emu.regs.rax = n as u64;
    } else {
        let mut count_send = COUNT_SEND.lock().unwrap();
        *count_send += 1;
        if *count_send > 3 {
            len = 0; // finish the send loop
        }

        emu.regs.rax = len;
    }
}

fn bind(emu: &mut emu::Emu) {
    let sock = emu.regs.rcx;
    let saddr = emu.regs.rdx;
    let len = emu.regs.r8;

    let family: u16 = emu
        .maps
        .read_word(saddr)
        .expect("ws2_32!connect: error reading family");
    let port: u16 = emu
        .maps
        .read_word(saddr + 2)
        .expect("ws2_32!connect: error reading port");
    let ip: u32 = emu
        .maps
        .read_dword(saddr + 4)
        .expect("ws2_32!connect: error reading ip");

    let sip = format!(
        "{}.{}.{}.{}",
        ip & 0xff,
        (ip & 0xff00) >> 8,
        (ip & 0xff0000) >> 16,
        (ip & 0xff000000) >> 24
    );

    println!(
        "{}** {} ws2_32!bind  family: {} {}:{}  {}",
        emu.colors.light_red,
        emu.pos,
        family,
        sip,
        port.to_be(),
        emu.colors.nc
    );

    if !helper::socket_exist(sock) {
        println!("\tbad socket.");
        emu.regs.rax = 1;
    } else {
        emu.regs.rax = 0;
    }
}

fn listen(emu: &mut emu::Emu) {
    let sock = emu.regs.rcx;
    let connections = emu.regs.rdx;

    println!(
        "{}** {} ws2_32!listen  connections: {}  {}",
        emu.colors.light_red, emu.pos, connections, emu.colors.nc
    );

    if !helper::socket_exist(sock) {
        println!("\tinvalid socket.");
        emu.regs.rax = 1;
    } else {
        emu.regs.rax = 0;
    }
}

fn accept(emu: &mut emu::Emu) {
    let sock = emu.regs.rcx;
    let saddr = emu.regs.rdx;
    let len = emu.regs.r8;
    let flags = emu.regs.r9;

    let bytes = emu.maps.read_string_of_bytes(saddr, len as usize);

    println!(
        "{}** {} ws2_32!accept  connections: {}  {}",
        emu.colors.light_red, emu.pos, bytes, emu.colors.nc
    );

    if !helper::socket_exist(sock) {
        println!("\tinvalid socket.");
        emu.regs.rax = 1;
    } else {
        emu.regs.rax = 0;
    }
}

fn closesocket(emu: &mut emu::Emu) {
    let sock = emu.regs.rcx;

    println!(
        "{}** {} ws2_32!closesocket {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );

    helper::socket_close(sock);

    if emu.cfg.endpoint {
        endpoint::sock_close();
    }

    emu.regs.rax = 0;
}

fn setsockopt(emu: &mut emu::Emu) {
    let sock = emu.regs.rcx;
    let level = emu.regs.rdx;
    let optname = emu.regs.r8;
    let optval = emu.regs.r9;
    let optlen = emu
        .maps
        .read_qword(emu.regs.get_esp())
        .expect("ws2_32!setsockopt: error reading optlen");

    let val = match emu.maps.read_dword(optval) {
        Some(v) => v,
        None => 0,
    };

    println!(
        "{}** {} ws2_32!setsockopt  lvl: {} opt: {} val: {} {}",
        emu.colors.light_red, emu.pos, level, optname, val, emu.colors.nc
    );

    emu.stack_pop64(false);

    if !helper::socket_exist(sock) {
        println!("\tinvalid socket.");
        emu.regs.rax = 1;
    } else {
        emu.regs.rax = 0;
    }
}

fn getsockopt(emu: &mut emu::Emu) {
    let sock = emu.regs.rcx;
    let level = emu.regs.rdx;
    let optname = emu.regs.r8;
    let optval = emu.regs.r9;
    let optlen = emu
        .maps
        .read_qword(emu.regs.get_esp())
        .expect("ws2_32!getsockopt: error reading optlen") as u64;

    emu.maps.write_dword(optval, 1);

    println!(
        "{}** {} ws2_32!getsockopt  lvl: {} opt: {} {}",
        emu.colors.light_red, emu.pos, level, optname, emu.colors.nc
    );

    emu.stack_pop64(false);

    if !helper::socket_exist(sock) {
        println!("\tinvalid socket.");
        emu.regs.rax = 1;
    } else {
        emu.regs.rax = 0;
    }
}

fn WsaAccept(emu: &mut emu::Emu) {
    let sock = emu.regs.rcx;
    let saddr = emu.regs.rdx;
    let len = emu.regs.r8;
    let cond = emu.regs.r9;
    let callback = emu
        .maps
        .read_qword(emu.regs.get_esp())
        .expect("ws2_32!WsaAccept: error reading callback") as u64;

    let bytes = emu.maps.read_string_of_bytes(saddr, len as usize);

    println!(
        "{}** {} ws2_32!WsaAccept  connections: {} callback: {} {}",
        emu.colors.light_red, emu.pos, bytes, callback, emu.colors.nc
    );

    emu.stack_pop64(false);

    if !helper::socket_exist(sock) {
        println!("\tinvalid socket.");
        emu.regs.rax = 1;
    } else {
        emu.regs.rax = 0;
    }
}

fn GetSockName(emu: &mut emu::Emu) {
    let sock = emu.regs.rcx;
    let sockaddr_ptr = emu.regs.rdx;
    let namelen_ptr = emu.regs.r8;

    emu.maps.write_dword(sockaddr_ptr, 0);
    emu.maps.write_dword(namelen_ptr, 4);

    println!(
        "{}** {} ws2_32!GetSockName sock: {} {}",
        emu.colors.light_red, emu.pos, sock, emu.colors.nc
    );

    emu.regs.rax = 0;
}
