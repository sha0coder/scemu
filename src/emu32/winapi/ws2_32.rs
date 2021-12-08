use crate::emu32;
use crate::emu32::winapi::helper;
use crate::emu32::endpoint;

use lazy_static::lazy_static; 
use std::sync::Mutex;


pub fn gateway(addr:u32, emu:&mut emu32::Emu32)  {
    match addr {
        0x77483ab2 => WsaStartup(emu),
        0x7748c82a => WsaSocketA(emu),
        0x77483eb8 => socket(emu),
        0x77493c11 => WsaHtons(emu),
        0x77482d8b => htons(emu),
        0x7748311b => inet_addr(emu),
        0x77486bdd => connect(emu),
        0x77486b0e => recv(emu),
        0x77486f01 => send(emu),
        0x77484582 => bind(emu),
        0x7748b001 => listen(emu),
        0x774868b6 => accept(emu),
        0x77483918 => closesocket(emu),
        0x774841b6 => setsockopt(emu),
        0x7748737d => getsockopt(emu),
        0x774868d6 => WsaAccept(emu),

        /*
        0x774834b5 => sendto(emu),
        0x7748b6dc => recvfrom(emu),
        0x77487089 => WsaRecv(emu),
        0x7748cba6 => WsaRecvFrom(emu),
        0x7748cc3f => WsaConnect(emu),
        */

        _ => panic!("calling unimplemented ws2_32 API 0x{:x}", addr)
    }
}

lazy_static! {
    static ref COUNT_SEND:Mutex<u32> = Mutex::new(0);
    static ref COUNT_RECV:Mutex<u32> = Mutex::new(0);
}


fn WsaStartup(emu:&mut emu32::Emu32) {

    println!("{}** {} ws2_32!WsaStartup {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    for _ in 0..2 {
        emu.stack_pop(false);
    }
    emu.regs.eax = 0;
}

fn WsaSocketA(emu:&mut emu32::Emu32) {
    println!("{}** {} ws2_32!WsaSocketA {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    for _ in 0..6 {
        emu.stack_pop(false);
    }

    emu.regs.eax = helper::socket_create();
}

fn socket(emu:&mut emu32::Emu32) {
    println!("{}** {} ws2_32!socket {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    for _ in 0..3 {
        emu.stack_pop(false);
    }

    emu.regs.eax = helper::socket_create();
}

fn WsaHtons(emu:&mut emu32::Emu32) {
    let host_port = emu.maps.read_dword(emu.regs.esp+4).expect("ws2_32!WsaHtons cannot read host_port");
    let out_port = emu.maps.read_dword(emu.regs.esp+8).expect("ws2_32!WsaHtons cannot read out_port");

    println!("{}** {} ws2_32!WsaHtons {} {}", emu.colors.light_red, emu.pos, host_port, emu.colors.nc);

    for _ in 0..3 {
        emu.stack_pop(false);
    }

    //TODO: implement this

    emu.regs.eax = 0; 
}


fn htons(emu:&mut emu32::Emu32) {
    let port:u16 = match emu.maps.read_word(emu.regs.esp) {
        Some(p) => p,
        None => 0,
    };

    println!("{}** {} ws2_32!htons port: {} {}", emu.colors.light_red, emu.pos, port, emu.colors.nc);

    emu.stack_pop(false);
    emu.regs.eax = port.to_be() as u32;
}


fn inet_addr(emu:&mut emu32::Emu32) {
    let addr = emu.maps.read_dword(emu.regs.esp).expect("ws2_32!inet_addr: error reading addr");

    println!("{}** {} ws2_32!inet_addr {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.stack_pop(false);
    emu.regs.eax = 0; 
}

fn connect(emu:&mut emu32::Emu32) {
    let sock = emu.maps.read_dword(emu.regs.esp).expect("ws2_32!connect: error reading sock");
    let sockaddr_ptr = emu.maps.read_dword(emu.regs.esp+4).expect("ws2_32!connect: error reading sockaddr ptr");
    //let sockaddr = emu.maps.read_bytes(sockaddr_ptr, 8);
    let family:u16 = emu.maps.read_word(sockaddr_ptr).expect("ws2_32!connect: error reading family");
    let port:u16 = emu.maps.read_word(sockaddr_ptr+2).expect("ws2_32!connect: error reading port").to_be();
    let ip:u32 = emu.maps.read_dword(sockaddr_ptr+4).expect("ws2_32!connect: error reading ip");

    let sip = format!("{}.{}.{}.{}", ip&0xff, (ip&0xff00)>>8, (ip&0xff0000)>>16, (ip&0xff000000)>>24);
    println!("{}** {} ws2_32!connect  family: {} {}:{} {}", emu.colors.light_red, emu.pos, family, sip, port,  emu.colors.nc);

    for _ in 0..3 {
        emu.stack_pop(false);
    }

    if emu.cfg.endpoint {  
        if endpoint::sock_connect(sip.as_str(), port) {
            println!("\tconnected to the endpoint.");
        } else {
            println!("\tcannot connect. dont use -e");
        }
        emu.regs.eax = 0;
    } else {

        if !helper::socket_exist(sock) {
            println!("\tinvalid socket.");
            emu.regs.eax = 1;
        } else {
            emu.regs.eax = 0; 
        }
    }
}

fn recv(emu:&mut emu32::Emu32) {
    let sock = emu.maps.read_dword(emu.regs.esp).expect("ws2_32!recv: error reading sock");
    let buff = emu.maps.read_dword(emu.regs.esp+4).expect("ws2_32!recv: error reading buff");
    let mut len = emu.maps.read_dword(emu.regs.esp+8).expect("ws2_32!recv: error reading len"); 
    let flags = emu.maps.read_dword(emu.regs.esp+12).expect("ws2_32!recv: error reading flags");

    println!("{}** {} ws2_32!recv   buff: 0x{:x} sz: {} {}", emu.colors.light_red, emu.pos, buff, len, emu.colors.nc);

    for _ in 0..4 {
        emu.stack_pop(false);
    }

    if !helper::socket_exist(sock) {
        println!("\tinvalid socket.");
        emu.regs.eax = 1;
        return;
    }

    if emu.cfg.endpoint {

        let mut rbuff:Vec<u8> = vec![0;len as usize];
        let n = endpoint::sock_recv(&mut rbuff);

        emu.maps.write_buffer(buff, &rbuff);

        println!("\nreceived {} bytes from the endpoint.", n);
        emu.regs.eax = n as u32;

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

            emu.regs.eax = len;
        }
    }
}

fn send(emu:&mut emu32::Emu32) {
    let sock = emu.maps.read_dword(emu.regs.esp).expect("ws2_32!send: error reading sock");
    let buff = emu.maps.read_dword(emu.regs.esp+4).expect("ws2_32!send: error reading buff");
    let mut len = emu.maps.read_dword(emu.regs.esp+8).expect("ws2_32!send: error reading len"); 
    let flags = emu.maps.read_dword(emu.regs.esp+12).expect("ws2_32!send: error reading flags");

    let bytes = emu.maps.read_string_of_bytes(buff, len as usize);

    for _ in 0..4 {
        emu.stack_pop(false);
    }

    println!("{}** {} ws2_32!send {{{}}}   {}", emu.colors.light_red, emu.pos, bytes, emu.colors.nc);

    if !helper::socket_exist(sock) {
        println!("\tinvalid socket.");
        emu.regs.eax = 0;
        return;
    }

    if emu.cfg.endpoint {

        let buffer = emu.maps.read_buffer(buff, len as usize);
        let n = endpoint::sock_send(&buffer);
        println!("\tsent {} bytes.", n);
        emu.regs.eax = n as u32;

    } else {
        let mut count_send = COUNT_SEND.lock().unwrap();
        *count_send += 1;
        if *count_send > 3 {
            len = 0; // finish the send loop
        }

        emu.regs.eax = len;
    }
    
    
}

fn bind(emu:&mut emu32::Emu32) {
    let sock = emu.maps.read_dword(emu.regs.esp).expect("ws2_32!send: error reading sock");
    let saddr = emu.maps.read_dword(emu.regs.esp+4).expect("ws2_32!send: error reading addr");
    let len = emu.maps.read_dword(emu.regs.esp+8).expect("ws2_32!send: error reading len"); 

    let family:u16 = emu.maps.read_word(saddr).expect("ws2_32!connect: error reading family");
    let port:u16 = emu.maps.read_word(saddr+2).expect("ws2_32!connect: error reading port");
    let ip:u32 = emu.maps.read_dword(saddr+4).expect("ws2_32!connect: error reading ip");

    let sip = format!("{}.{}.{}.{}", ip&0xff, (ip&0xff00)>>8, (ip&0xff0000)>>16, (ip&0xff000000)>>24);

    println!("{}** {} ws2_32!bind  family: {} {}:{}  {}", emu.colors.light_red, emu.pos, family, sip, port.to_be(), emu.colors.nc);

    for _ in 0..3 {
        emu.stack_pop(false);
    }

    if !helper::socket_exist(sock) {
        println!("\tbad socket.");
        emu.regs.eax = 1;
    } else {
        emu.regs.eax = 0;
    }

}

fn listen(emu:&mut emu32::Emu32) {
    let sock = emu.maps.read_dword(emu.regs.esp).expect("ws2_32!send: error reading sock");
    let connections = emu.maps.read_dword(emu.regs.esp+4).expect("ws2_32!send: error reading num of connections");

    println!("{}** {} ws2_32!listen  connections: {}  {}", emu.colors.light_red, emu.pos, connections, emu.colors.nc);

    for _ in 0..2 {
        emu.stack_pop(false);
    }

    if !helper::socket_exist(sock) {
        println!("\tinvalid socket.");
        emu.regs.eax = 1;
    } else {
        emu.regs.eax = 0;
    }
}

fn accept(emu:&mut emu32::Emu32) {
    let sock = emu.maps.read_dword(emu.regs.esp).expect("ws2_32!accept: error reading sock");
    let saddr = emu.maps.read_dword(emu.regs.esp+4).expect("ws2_32!accept: error reading sockaddr");
    let len = emu.maps.read_dword(emu.regs.esp+8).expect("ws2_32!seacceptnd: error reading len"); 
    let flags = emu.maps.read_dword(emu.regs.esp+12).expect("ws2_32!accept: error reading flags");

    let bytes = emu.maps.read_string_of_bytes(saddr, len as usize);

    println!("{}** {} ws2_32!accept  connections: {}  {}", emu.colors.light_red, emu.pos, bytes, emu.colors.nc);

    for _ in 0..4 {
        emu.stack_pop(false);
    }

    if !helper::socket_exist(sock) {
        println!("\tinvalid socket.");
        emu.regs.eax = 1;
    } else {
        emu.regs.eax = 0;
    }
}

fn closesocket(emu:&mut emu32::Emu32) {
    let sock = emu.maps.read_dword(emu.regs.esp).expect("ws2_32!send: error reading sock");

    println!("{}** {} ws2_32!closesocket {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    helper::socket_close(sock);

    if emu.cfg.endpoint {
        endpoint::sock_close();
    }

    emu.stack_pop(false);
    emu.regs.eax = 0;
}

fn setsockopt(emu:&mut emu32::Emu32) {
    let sock = emu.maps.read_dword(emu.regs.esp).expect("ws2_32!setsockopt: error reading sock");
    let level = emu.maps.read_dword(emu.regs.esp+4).expect("ws2_32!setsockopt: error reading level");
    let optname = emu.maps.read_dword(emu.regs.esp+8).expect("ws2_32!setsockopt: error reading optname"); 
    let optval = emu.maps.read_dword(emu.regs.esp+12).expect("ws2_32!setsockopt: error reading optval");
    let optlen = emu.maps.read_dword(emu.regs.esp+16).expect("ws2_32!setsockopt: error reading optlen");

    let val = match emu.maps.read_dword(optval) {
        Some(v) => v,
        None => 0,
    };

    println!("{}** {} ws2_32!setsockopt  lvl: {} opt: {} val: {} {}", emu.colors.light_red, emu.pos, level, optname, val, emu.colors.nc);

    for _ in 0..5 {
        emu.stack_pop(false);
    }

    if !helper::socket_exist(sock) {
        println!("\tinvalid socket.");
        emu.regs.eax = 1;
    } else {
        emu.regs.eax = 0;
    }
}

fn getsockopt(emu:&mut emu32::Emu32) {
    let sock = emu.maps.read_dword(emu.regs.esp).expect("ws2_32!getsockopt: error reading sock");
    let level = emu.maps.read_dword(emu.regs.esp+4).expect("ws2_32!getsockopt: error reading level");
    let optname = emu.maps.read_dword(emu.regs.esp+8).expect("ws2_32!getsockopt: error reading optname"); 
    let optval = emu.maps.read_dword(emu.regs.esp+12).expect("ws2_32!getsockopt: error reading optval");
    let optlen = emu.maps.read_dword(emu.regs.esp+16).expect("ws2_32!getsockopt: error reading optlen");


    emu.maps.write_dword(optval, 1);

    println!("{}** {} ws2_32!getsockopt  lvl: {} opt: {} {}", emu.colors.light_red, emu.pos, level, optname, emu.colors.nc);

    for _ in 0..5 {
        emu.stack_pop(false);
    }

    if !helper::socket_exist(sock) {
        println!("\tinvalid socket.");
        emu.regs.eax = 1;
    } else {
        emu.regs.eax = 0;
    }
}

fn WsaAccept(emu:&mut emu32::Emu32) {
    let sock = emu.maps.read_dword(emu.regs.esp).expect("ws2_32!WsaAccept: error reading sock");
    let saddr = emu.maps.read_dword(emu.regs.esp+4).expect("ws2_32!WsaAccept: error reading sockaddr");
    let len = emu.maps.read_dword(emu.regs.esp+8).expect("ws2_32!WsaAccept: error reading len"); 
    let cond = emu.maps.read_dword(emu.regs.esp+12).expect("ws2_32!WsaAccept: error reading cond");
    let callback = emu.maps.read_dword(emu.regs.esp+16).expect("ws2_32!WsaAccept: error reading callback");

    let bytes = emu.maps.read_string_of_bytes(saddr, len as usize);

    println!("{}** {} ws2_32!WsaAccept  connections: {} callback: {} {}", emu.colors.light_red, emu.pos, bytes, callback, emu.colors.nc);

    for _ in 0..4 {
        emu.stack_pop(false);
    }

    if !helper::socket_exist(sock) {
        println!("\tinvalid socket.");
        emu.regs.eax = 1;
    } else {
        emu.regs.eax = 0;
    }
}
