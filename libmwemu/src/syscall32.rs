use crate::emu;
use crate::constants;
use crate::console::Console;
//use crate::endpoint;
use crate::winapi32::helper;

//  /usr/include/asm/unistd_32.h

//TODO: check if buff is mapped

pub fn gateway(emu: &mut emu::Emu) {
    emu.regs.sanitize32();

    match emu.regs.get_eax() {
        0 => {
            log::info!(
                "{}** {} syscall restart_syscall {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        1 => {
            log::info!(
                "{}** {} syscall exit()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
            std::process::exit(1);
        }

        2 => {
            log::info!(
                "{}** {} syscall fork()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
            Console::spawn_console(emu);
        }

        3 => {
            let fd = emu.regs.rbx;
            let buff = emu.regs.rcx;
            let sz = emu.regs.rdx;
            emu.regs.rax = buff;
            log::info!(
                "{}** {} syscall read() fd: {} buf: 0x{:x} sz: {} {}",
                emu.colors.light_red,
                emu.pos,
                fd,
                buff,
                sz,
                emu.colors.nc
            );
        }

        4 => {
            let fd = emu.regs.rbx;
            let buff = emu.regs.rcx;
            let sz = emu.regs.rdx;
            emu.regs.rax = sz;
            log::info!(
                "{}** {} syscall write() fd: {} buf: 0x{:x} sz: {} {}",
                emu.colors.light_red,
                emu.pos,
                fd,
                buff,
                sz,
                emu.colors.nc
            );
        }

        5 => {
            let file_path = emu.maps.read_string(emu.regs.rbx);
            let fd = helper::socket_create();
            emu.regs.rax = fd;
            log::info!(
                "{}** {} syscall open() file: {} fd:{} {}",
                emu.colors.light_red,
                emu.pos,
                file_path,
                fd,
                emu.colors.nc
            );
        }

        6 => {
            let fd = emu.regs.rbx;
            log::info!(
                "{}** {} syscall close() fd: {}  {}",
                emu.colors.light_red,
                emu.pos,
                fd,
                emu.colors.nc
            );
            helper::socket_close(fd);
            //endpoint::sock_close();
        }

        7 => {
            log::info!(
                "{}** {} syscall waitpid()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        8 => {
            log::info!(
                "{}** {} syscall creat()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        9 => {
            log::info!(
                "{}** {} syscall link()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        10 => {
            log::info!(
                "{}** {} syscall unlink()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        11 => {
            let cmd = emu.maps.read_string(emu.regs.rbx);
            log::info!(
                "{}** {} syscall execve()  cmd: {} {}",
                emu.colors.light_red,
                emu.pos,
                cmd,
                emu.colors.nc
            );
            emu.regs.rax = 0;
        }

        12 => {
            let path = emu.maps.read_string(emu.regs.rbx);
            log::info!(
                "{}** {} syscall chdir() path: {} {}",
                emu.colors.light_red,
                emu.pos,
                path,
                emu.colors.nc
            );
        }

        13 => {
            log::info!(
                "{}** {} syscall time()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        14 => {
            log::info!(
                "{}** {} syscall mknod()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        15 => {
            let file_path = emu.maps.read_string(emu.regs.rbx);
            let perm = emu.regs.rcx;
            log::info!(
                "{}** {} syscall chmod() file: {} perm: {} {}",
                emu.colors.light_red,
                emu.pos,
                file_path,
                perm,
                emu.colors.nc
            );
        }

        16 => {
            log::info!(
                "{}** {} syscall lchown()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        17 => {
            log::info!(
                "{}** {} syscall break()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        18 => {
            log::info!(
                "{}** {} syscall oldstat()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        19 => {
            let fd = emu.regs.rbx;
            log::info!(
                "{}** {} syscall lseek()  fd: {} {}",
                emu.colors.light_red,
                emu.pos,
                fd,
                emu.colors.nc
            );
        }

        20 => {
            log::info!(
                "{}** {} syscall getpid()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        21 => {
            log::info!(
                "{}** {} syscall mount()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        22 => {
            log::info!(
                "{}** {} syscall umount()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        23 => {
            log::info!(
                "{}** {} syscall setuid()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        24 => {
            log::info!(
                "{}** {} syscall getuid()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        25 => {
            log::info!(
                "{}** {} syscall stime()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        26 => {
            log::info!(
                "{}** {} syscall ptrace()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        27 => {
            log::info!(
                "{}** {} syscall alarm()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        28 => {
            log::info!(
                "{}** {} syscall oldfstat()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        29 => {
            log::info!(
                "{}** {} syscall pause()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        30 => {
            log::info!(
                "{}** {} syscall utime()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        31 => {
            log::info!(
                "{}** {} syscall stty()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        32 => {
            log::info!(
                "{}** {} syscall gtty()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        33 => {
            log::info!(
                "{}** {} syscall access()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        34 => {
            log::info!(
                "{}** {} syscall nice()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        35 => {
            log::info!(
                "{}** {} syscall ftime()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        36 => {
            log::info!(
                "{}** {} syscall sync()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        37 => {
            let pid = emu.regs.rbx;
            let sig = emu.regs.rcx;
            log::info!(
                "{}** {} syscall kill() pid: {} sig: {} {}",
                emu.colors.light_red,
                emu.pos,
                pid,
                sig,
                emu.colors.nc
            );
        }

        38 => {
            log::info!(
                "{}** {} syscall rename()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        39 => {
            log::info!(
                "{}** {} syscall mkdir()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        40 => {
            log::info!(
                "{}** {} syscall rmdir()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        41 => {
            let fd = emu.regs.rbx;
            log::info!(
                "{}** {} syscall dup() fd: {} {}",
                emu.colors.light_red,
                emu.pos,
                fd,
                emu.colors.nc
            );
        }

        42 => {
            log::info!(
                "{}** {} syscall pipe()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        43 => {
            log::info!(
                "{}** {} syscall times()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        44 => {
            log::info!(
                "{}** {} syscall prof()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        45 => {
            log::info!(
                "{}** {} syscall brk()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        46 => {
            log::info!(
                "{}** {} syscall setgid()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        47 => {
            log::info!(
                "{}** {} syscall getgid()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        48 => {
            log::info!(
                "{}** {} syscall signal()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        49 => {
            log::info!(
                "{}** {} syscall geteuid()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        50 => {
            log::info!(
                "{}** {} syscall getegid()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        51 => {
            log::info!(
                "{}** {} syscall acct()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        52 => {
            log::info!(
                "{}** {} syscall umount2()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        53 => {
            log::info!(
                "{}** {} syscall lock()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        54 => {
            log::info!(
                "{}** {} syscall ioctl()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        55 => {
            log::info!(
                "{}** {} syscall fcntl()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        56 => {
            log::info!(
                "{}** {} syscall mpx()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        57 => {
            log::info!(
                "{}** {} syscall setpgid()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        58 => {
            log::info!(
                "{}** {} syscall ulimit()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        59 => {
            log::info!(
                "{}** {} syscall oldolduname()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        60 => {
            log::info!(
                "{}** {} syscall umask()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        61 => {
            log::info!(
                "{}** {} syscall chroot()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        62 => {
            log::info!(
                "{}** {} syscall ustat()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        63 => {
            let old_fd = emu.regs.get_ebx();
            let new_fd = emu.regs.get_ecx();
            log::info!(
                "{}** {} syscall dup2() oldfd: {} newfd: {} {}",
                emu.colors.light_red,
                emu.pos,
                old_fd,
                new_fd,
                emu.colors.nc
            );
        }

        64 => {
            log::info!(
                "{}** {} syscall getppid()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        65 => {
            log::info!(
                "{}** {} syscall getpgrp()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        66 => {
            log::info!(
                "{}** {} syscall setsid()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        67 => {
            log::info!(
                "{}** {} syscall sigaction()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        68 => {
            log::info!(
                "{}** {} syscall sgetmask()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        69 => {
            log::info!(
                "{}** {} syscall ssetmask()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        70 => {
            log::info!(
                "{}** {} syscall setreuid()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        71 => {
            log::info!(
                "{}** {} syscall setregid()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        72 => {
            log::info!(
                "{}** {} syscall sigsuspend()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        73 => {
            log::info!(
                "{}** {} syscall sigpending()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        74 => {
            log::info!(
                "{}** {} syscall sethostname()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        75 => {
            log::info!(
                "{}** {} syscall setrlimit()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        76 => {
            log::info!(
                "{}** {} syscall getrlimit()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        77 => {
            log::info!(
                "{}** {} syscall getrusage()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        78 => {
            log::info!(
                "{}** {} syscall gettimeofday()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        79 => {
            log::info!(
                "{}** {} syscall settimeofday()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        80 => {
            log::info!(
                "{}** {} syscall getgroups()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        81 => {
            log::info!(
                "{}** {} syscall setgroups()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        82 => {
            log::info!(
                "{}** {} syscall select()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        83 => {
            log::info!(
                "{}** {} syscall symlink()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        84 => {
            log::info!(
                "{}** {} syscall oldlstat()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        85 => {
            log::info!(
                "{}** {} syscall readlink()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        86 => {
            log::info!(
                "{}** {} syscall uselib()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        87 => {
            log::info!(
                "{}** {} syscall swapon()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        88 => {
            log::info!(
                "{}** {} syscall reboot()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        89 => {
            log::info!(
                "{}** {} syscall readdir()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        90 => {
            log::info!(
                "{}** {} syscall mmap()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        91 => {
            log::info!(
                "{}** {} syscall munmap()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        92 => {
            log::info!(
                "{}** {} syscall truncate()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        93 => {
            log::info!(
                "{}** {} syscall ftruncate()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        94 => {
            log::info!(
                "{}** {} syscall fchmod()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        95 => {
            log::info!(
                "{}** {} syscall fchown()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        96 => {
            log::info!(
                "{}** {} syscall getpriority()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        97 => {
            log::info!(
                "{}** {} syscall setpriority()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        98 => {
            log::info!(
                "{}** {} syscall profil()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        99 => {
            log::info!(
                "{}** {} syscall statfs()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        100 => {
            log::info!(
                "{}** {} syscall fstatfs()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        101 => {
            log::info!(
                "{}** {} syscall ioperm()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        102 => {
            match emu.regs.rbx as u32 {
                constants::SYS_SOCKET => {
                    let sock = helper::socket_create();
                    let fam = emu
                        .maps
                        .read_dword(emu.regs.get_esp())
                        .expect("socket() cannot read family");
                    let typ = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 4)
                        .expect("socket() cannot ready type");
                    let proto = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 8)
                        .expect("socket() cannot read proto");

                    log::info!("{}** {} syscall socketcall socket()  fam: {} type: {} proto: {} sock: {} {}", emu.colors.light_red, emu.pos, fam, typ, proto, sock, emu.colors.nc);
                    emu.regs.rax = sock;
                }

                constants::SYS_BIND => {
                    let sock = emu
                        .maps
                        .read_dword(emu.regs.get_esp())
                        .expect("bind() cannot read sock");
                    let sockaddr = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 4)
                        .expect("bind() cannot read sockaddr");
                    let len = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 8)
                        .expect("bind() cannot read len");

                    let fam: u16 = emu
                        .maps
                        .read_word(sockaddr as u64)
                        .expect("cannot read family id");
                    let port: u16 = emu
                        .maps
                        .read_word((sockaddr + 2) as u64)
                        .expect("cannot read the port")
                        .to_be();
                    let ip: u32 = emu
                        .maps
                        .read_dword((sockaddr + 4) as u64)
                        .expect("cannot read the ip");
                    let sip = format!(
                        "{}.{}.{}.{}",
                        ip & 0xff,
                        (ip & 0xff00) >> 8,
                        (ip & 0xff0000) >> 16,
                        (ip & 0xff000000) >> 24
                    );

                    log::info!(
                        "{}** {} syscall socketcall bind() sock: {} fam: {} {}:{} {}",
                        emu.colors.light_red,
                        emu.pos,
                        sock,
                        fam,
                        sip,
                        port,
                        emu.colors.nc
                    );

                    if !helper::socket_exist(sock as u64) {
                        log::info!("\tbad socket/");
                        emu.regs.rax = constants::ENOTSOCK;
                    } else {
                        emu.regs.rax = 0;
                    }
                }

                constants::SYS_CONNECT => {
                    let sock = emu
                        .maps
                        .read_dword(emu.regs.get_esp())
                        .expect("connect() cannot read sock");
                    let sockaddr = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 4)
                        .expect("connect() cannot read sockaddr");
                    let len = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 8)
                        .expect("connect() cannot read len");

                    let fam: u16 = emu
                        .maps
                        .read_word(sockaddr as u64)
                        .expect("cannot read family id");
                    let port: u16 = emu
                        .maps
                        .read_word((sockaddr + 2) as u64)
                        .expect("cannot read the port")
                        .to_be();
                    let ip: u32 = emu
                        .maps
                        .read_dword((sockaddr + 4) as u64)
                        .expect("cannot read the ip");
                    let sip = format!(
                        "{}.{}.{}.{}",
                        ip & 0xff,
                        (ip & 0xff00) >> 8,
                        (ip & 0xff0000) >> 16,
                        (ip & 0xff000000) >> 24
                    );

                    log::info!(
                        "{}** {} syscall socketcall connect() sock: {} fam: {} {}:{} {}",
                        emu.colors.light_red,
                        emu.pos,
                        sock,
                        fam,
                        sip,
                        port,
                        emu.colors.nc
                    );

                    if !helper::socket_exist(sock as u64) {
                        log::info!("\tbad socket/");
                        emu.regs.rax = constants::ENOTSOCK;
                        return;
                    }

                    /*
                    if emu.cfg.endpoint {
                        if endpoint::sock_connect(sip.as_str(), port) {
                            log::info!("\tconnected to the endpoint.");
                        } else {
                            log::info!("\tcannot connect. dont use -e");
                        }
                    }*/

                    emu.regs.rax = 0;
                }

                constants::SYS_LISTEN => {
                    let sock = emu
                        .maps
                        .read_dword(emu.regs.get_esp())
                        .expect("listen() cannot read sock");
                    let conns = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 4)
                        .expect("listen() cannot read num of conns");

                    log::info!(
                        "{}** {} syscall socketcall listen() sock: {} conns: {} {}",
                        emu.colors.light_red,
                        emu.pos,
                        sock,
                        conns,
                        emu.colors.nc
                    );

                    if !helper::socket_exist(sock as u64) {
                        log::info!("\tbad socket/");
                        emu.regs.rax = constants::ENOTSOCK;
                    } else {
                        emu.regs.rax = 0;
                    }
                }

                constants::SYS_ACCEPT => {
                    let sock = emu
                        .maps
                        .read_dword(emu.regs.get_esp())
                        .expect("accept() cannot read sock");
                    let sockaddr = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 4)
                        .expect("accept() cannot read sockaddr");
                    let len = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 8)
                        .expect("accept() cannot read len");
                    let port: u16 = 8080;
                    let incoming_ip: u32 = 0x11223344;

                    if sockaddr != 0 && emu.maps.is_mapped(sockaddr as u64) {
                        emu.maps.write_word(sockaddr as u64, 0x0002);
                        emu.maps.write_word((sockaddr + 2) as u64, port.to_le()); //TODO: port should be the same than bind()
                        emu.maps.write_dword((sockaddr + 4) as u64, incoming_ip);
                    }

                    log::info!(
                        "{}** {} syscall socketcall accept() {}",
                        emu.colors.light_red,
                        emu.pos,
                        emu.colors.nc
                    );

                    if !helper::socket_exist(sock as u64) {
                        log::info!("\tbad socket/");
                        emu.regs.rax = constants::ENOTSOCK;
                    } else {
                        emu.regs.rax = 0;
                    }
                }

                constants::SYS_GETSOCKNAME => {
                    let sock = emu
                        .maps
                        .read_dword(emu.regs.get_esp())
                        .expect("getsockname() cannot read sock");
                    log::info!(
                        "{}** {} syscall socketcall getsockname() sock: {} {}",
                        emu.colors.light_red,
                        emu.pos,
                        sock,
                        emu.colors.nc
                    );
                    todo!("implement this");
                }

                constants::SYS_GETPEERNAME => {
                    log::info!(
                        "{}** {} syscall socketcall getpeername()  {}",
                        emu.colors.light_red,
                        emu.pos,
                        emu.colors.nc
                    );
                }

                constants::SYS_SOCKETPAIR => {
                    log::info!(
                        "{}** {} syscall socketcall socketpair()  {}",
                        emu.colors.light_red,
                        emu.pos,
                        emu.colors.nc
                    );
                }

                constants::SYS_SEND => {
                    let sock = emu
                        .maps
                        .read_dword(emu.regs.get_esp())
                        .expect("send() cannot read sock");
                    let buf = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 4)
                        .expect("send() cannot read buff");
                    let len = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 8)
                        .expect("send() cannot read len");
                    let flags = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 12)
                        .expect("send() cannot read flags");

                    log::info!(
                        "{}** {} syscall socketcall send() sock: {} buff: {} len: {} {}",
                        emu.colors.light_red,
                        emu.pos,
                        sock,
                        buf,
                        len,
                        emu.colors.nc
                    );

                    if !helper::socket_exist(sock as u64) {
                        log::info!("\tbad socket/");
                        emu.regs.rax = constants::ENOTSOCK;
                        return;
                    }

                    /*
                    if emu.cfg.endpoint {
                        let buffer = emu.maps.read_buffer(buf as u64, len as usize);
                        let n = endpoint::sock_send(&buffer);
                        log::info!("\tsent {} bytes.", n);
                        emu.regs.rax = n as u64;
                    } else {
                        emu.regs.rax = len as u64;
                    }*/

                    emu.regs.rax = len as u64;
                }

                constants::SYS_RECV => {
                    let sock = emu
                        .maps
                        .read_dword(emu.regs.get_esp())
                        .expect("recv() cannot read sock");
                    let buf = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 4)
                        .expect("recv() cannot read buff");
                    let len = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 8)
                        .expect("recv() cannot read len");
                    let flags = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 12)
                        .expect("recv() cannot read flags");

                    log::info!(
                        "{}** {} syscall socketcall recv() sock: {} buff: {} len: {}  {}",
                        emu.colors.light_red,
                        emu.pos,
                        sock,
                        buf,
                        len,
                        emu.colors.nc
                    );

                    if !helper::socket_exist(sock as u64) {
                        log::info!("\tbad socket/");
                        emu.regs.rax = constants::ENOTSOCK;
                        return;
                    }

                    /*
                    if emu.cfg.endpoint {
                        let mut rbuff: Vec<u8> = vec![0; len as usize];
                        let n = endpoint::sock_recv(&mut rbuff);
                        emu.maps.write_buffer(buf as u64, &rbuff);
                        log::info!("\nreceived {} bytes from the endpoint.", n);
                        emu.regs.rax = n as u64;
                    } else {
                        emu.regs.rax = len as u64; //TODO: avoid loops
                    }*/

                    emu.regs.rax = len as u64; //TODO: avoid loops
                }

                constants::SYS_SENDTO => {
                    let sock = emu
                        .maps
                        .read_dword(emu.regs.get_esp())
                        .expect("sendto() cannot read sock");
                    let buf = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 4)
                        .expect("sendto() cannot read buff");
                    let len = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 8)
                        .expect("sendto() cannot read len");
                    let flags = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 12)
                        .expect("sendto() cannot read flags");
                    let sockaddr = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 16)
                        .expect("sendto() cannot read sockaddr");
                    let addrlen = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 20)
                        .expect("sendto() cannot read addrlen");

                    if sockaddr != 0 && emu.maps.is_mapped(sockaddr as u64) {
                        let fam: u16 = emu
                            .maps
                            .read_word(sockaddr as u64)
                            .expect("cannot read family id");
                        let port: u16 = emu
                            .maps
                            .read_word((sockaddr + 2) as u64)
                            .expect("cannot read the port")
                            .to_be();
                        let ip: u32 = emu
                            .maps
                            .read_dword((sockaddr + 4) as u64)
                            .expect("cannot read the ip");
                        let sip = format!(
                            "{}.{}.{}.{}",
                            ip & 0xff,
                            (ip & 0xff00) >> 8,
                            (ip & 0xff0000) >> 16,
                            (ip & 0xff000000) >> 24
                        );

                        log::info!("{}** {} syscall socketcall sendto() sock: {} buff: {} len: {} fam: {} {}:{} {}", emu.colors.light_red, emu.pos, sock, buf, len, fam, sip, port, emu.colors.nc);
                    } else {
                        log::info!(
                            "{}** {} syscall socketcall sendto() sock: {} buff: {} len: {} {}",
                            emu.colors.light_red,
                            emu.pos,
                            sock,
                            buf,
                            len,
                            emu.colors.nc
                        );
                    }

                    if !helper::socket_exist(sock as u64) {
                        log::info!("\tbad socket/");
                        emu.regs.rax = constants::ENOTSOCK;
                    } else {
                        emu.regs.rax = len as u64;
                    }
                }

                constants::SYS_RECVFROM => {
                    let sock = emu
                        .maps
                        .read_dword(emu.regs.get_esp())
                        .expect("recvfrom() cannot read sock");
                    let buf = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 8)
                        .expect("recvfrom() cannot read buff");
                    let len = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 12)
                        .expect("recvfrom() cannot read len");
                    let flags = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 16)
                        .expect("recvfrom() cannot read flags");
                    let sockaddr = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 20)
                        .expect("recvfrom() cannot read sockaddr");
                    let addrlen = emu
                        .maps
                        .read_dword(emu.regs.get_esp() + 24)
                        .expect("recvfrom() cannot read sockaddr len");

                    if sockaddr != 0 && emu.maps.is_mapped(sockaddr as u64) {
                        let port: u16 = 8080;
                        let incoming_ip: u32 = 0x11223344;

                        emu.maps.write_word(sockaddr as u64, 0x0002);
                        emu.maps.write_word((sockaddr + 2) as u64, port.to_le()); //TODO: port should be the same than bind()
                        emu.maps.write_dword((sockaddr + 4) as u64, incoming_ip);
                    }

                    log::info!(
                        "{}** {} syscall socketcall recvfrom() sock: {} buff: {} len: {} {}",
                        emu.colors.light_red,
                        emu.pos,
                        sock,
                        buf,
                        len,
                        emu.colors.nc
                    );

                    if !helper::socket_exist(sock as u64) {
                        log::info!("\tbad socket/");
                        emu.regs.rax = constants::ENOTSOCK;
                    } else {
                        emu.regs.rax = len as u64; //TODO: avoid loops
                    }
                }

                constants::SYS_SHUTDOWN => {
                    log::info!(
                        "{}** {} syscall socketcall shutdown()  {}",
                        emu.colors.light_red,
                        emu.pos,
                        emu.colors.nc
                    );
                    //endpoint::sock_close();
                }

                constants::SYS_SETSOCKOPT => {
                    log::info!(
                        "{}** {} syscall socketcall setsockopt()  {}",
                        emu.colors.light_red,
                        emu.pos,
                        emu.colors.nc
                    );
                }

                constants::SYS_GETSOCKOPT => {
                    log::info!(
                        "{}** {} syscall socketcall getsockopt()  {}",
                        emu.colors.light_red,
                        emu.pos,
                        emu.colors.nc
                    );
                }

                constants::SYS_SENDMSG => {
                    log::info!(
                        "{}** {} syscall socketcall sendmsg()  {}",
                        emu.colors.light_red,
                        emu.pos,
                        emu.colors.nc
                    );
                }

                constants::SYS_RECVMSG => {
                    log::info!(
                        "{}** {} syscall socketcall recvmsg()  {}",
                        emu.colors.light_red,
                        emu.pos,
                        emu.colors.nc
                    );
                }

                constants::SYS_ACCEPT4 => {
                    log::info!(
                        "{}** {} syscall socketcall accept4()  {}",
                        emu.colors.light_red,
                        emu.pos,
                        emu.colors.nc
                    );
                }

                constants::SYS_RECVMMSG => {
                    log::info!(
                        "{}** {} syscall socketcall recvmsg()  {}",
                        emu.colors.light_red,
                        emu.pos,
                        emu.colors.nc
                    );
                }

                constants::SYS_SENDMMSG => {
                    log::info!(
                        "{}** {} syscall socketcall sendmsg()  {}",
                        emu.colors.light_red,
                        emu.pos,
                        emu.colors.nc
                    );
                }

                _ => panic!("invalid socket call {} ", emu.regs.rbx),
            }
        }

        103 => {
            log::info!(
                "{}** {} syscall syslog()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        104 => {
            log::info!(
                "{}** {} syscall setitimer()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        105 => {
            log::info!(
                "{}** {} syscall getitimer()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        106 => {
            log::info!(
                "{}** {} syscall stat()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        107 => {
            log::info!(
                "{}** {} syscall lstat()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        108 => {
            log::info!(
                "{}** {} syscall fstat()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        109 => {
            log::info!(
                "{}** {} syscall olduname()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        110 => {
            log::info!(
                "{}** {} syscall iopl()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        111 => {
            log::info!(
                "{}** {} syscall vhanghup()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        112 => {
            log::info!(
                "{}** {} syscall idle()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        113 => {
            log::info!(
                "{}** {} syscall vm86old()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        114 => {
            log::info!(
                "{}** {} syscall wait4()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        115 => {
            log::info!(
                "{}** {} syscall swapoff()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        116 => {
            log::info!(
                "{}** {} syscall sysinfo()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        117 => {
            log::info!(
                "{}** {} syscall ipc()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        118 => {
            log::info!(
                "{}** {} syscall fsync()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        119 => {
            log::info!(
                "{}** {} syscall sigreturn()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        120 => {
            log::info!(
                "{}** {} syscall clone()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        121 => {
            log::info!(
                "{}** {} syscall setdomainname()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        122 => {
            log::info!(
                "{}** {} syscall uname()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        123 => {
            log::info!(
                "{}** {} syscall modify_ltd()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        124 => {
            log::info!(
                "{}** {} syscall adjtimex()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        125 => {
            log::info!(
                "{}** {} syscall mprotect()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        126 => {
            log::info!(
                "{}** {} syscall sigprocmask()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        127 => {
            log::info!(
                "{}** {} syscall create_module()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        128 => {
            log::info!(
                "{}** {} syscall init_module()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        129 => {
            log::info!(
                "{}** {} syscall delete_module()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        130 => {
            log::info!(
                "{}** {} syscall get_kernel_syms()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        131 => {
            log::info!(
                "{}** {} syscall quotactl()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        132 => {
            log::info!(
                "{}** {} syscall getpgid()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        133 => {
            log::info!(
                "{}** {} syscall fchdir()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        134 => {
            log::info!(
                "{}** {} syscall bdflush()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        135 => {
            log::info!(
                "{}** {} syscall sysfs()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        136 => {
            log::info!(
                "{}** {} syscall personality()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        137 => {
            log::info!(
                "{}** {} syscall afs_syscall()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        138 => {
            log::info!(
                "{}** {} syscall setfsuid()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        139 => {
            log::info!(
                "{}** {} syscall setfsgid()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        140 => {
            log::info!(
                "{}** {} syscall _llseek()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        141 => {
            log::info!(
                "{}** {} syscall getdents()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        142 => {
            log::info!(
                "{}** {} syscall _newselect()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        143 => {
            log::info!(
                "{}** {} syscall flock()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        144 => {
            log::info!(
                "{}** {} syscall msync()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        145 => {
            log::info!(
                "{}** {} syscall readv()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        146 => {
            log::info!(
                "{}** {} syscall writev()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        147 => {
            log::info!(
                "{}** {} syscall getsid()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        148 => {
            log::info!(
                "{}** {} syscall fdatasync()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        149 => {
            log::info!(
                "{}** {} syscall _sysctl()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        150 => {
            log::info!(
                "{}** {} syscall mlock()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        151 => {
            log::info!(
                "{}** {} syscall munlock()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        152 => {
            log::info!(
                "{}** {} syscall mlockall()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        153 => {
            log::info!(
                "{}** {} syscall munlockall()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        154 => {
            log::info!(
                "{}** {} syscall sched_setparam()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        155 => {
            log::info!(
                "{}** {} syscall sched_getparam()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        156 => {
            log::info!(
                "{}** {} syscall sched_setscheduler()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        157 => {
            log::info!(
                "{}** {} syscall sched_getscheduler()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        158 => {
            log::info!(
                "{}** {} syscall sched_yield()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        159 => {
            log::info!(
                "{}** {} syscall sched_get_priority_max()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        160 => {
            log::info!(
                "{}** {} syscall sched_get_priority_min()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        161 => {
            log::info!(
                "{}** {} syscall sched_rr_get_inverval()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        162 => {
            log::info!(
                "{}** {} syscall nanosleep()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        163 => {
            log::info!(
                "{}** {} syscall mremap()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        164 => {
            log::info!(
                "{}** {} syscall setresuid()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        165 => {
            log::info!(
                "{}** {} syscall getresuid()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        166 => {
            log::info!(
                "{}** {} syscall vm86()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        167 => {
            log::info!(
                "{}** {} syscall query_module()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        168 => {
            log::info!(
                "{}** {} syscall poll()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        169 => {
            log::info!(
                "{}** {} syscall nfsservctrl()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        170 => {
            log::info!(
                "{}** {} syscall setresgid()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        171 => {
            log::info!(
                "{}** {} syscall getresgid()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        172 => {
            log::info!(
                "{}** {} syscall prctl()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        173 => {
            log::info!(
                "{}** {} syscall rt_sigreturn()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        174 => {
            log::info!(
                "{}** {} syscall rt_sigcation()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        175 => {
            log::info!(
                "{}** {} syscall rt_sigprocmask()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        176 => {
            log::info!(
                "{}** {} syscall rt_sigpending()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        177 => {
            log::info!(
                "{}** {} syscall rt_sigtimedwait()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        178 => {
            log::info!(
                "{}** {} syscall rt_sigqueueinfo()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        179 => {
            log::info!(
                "{}** {} syscall rt_sigsuspend()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        180 => {
            log::info!(
                "{}** {} syscall pread64()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        181 => {
            log::info!(
                "{}** {} syscall pwrite64()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        182 => {
            log::info!(
                "{}** {} syscall chown()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        183 => {
            log::info!(
                "{}** {} syscall getcwd()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        184 => {
            log::info!(
                "{}** {} syscall capget()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        185 => {
            log::info!(
                "{}** {} syscall capset()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        186 => {
            log::info!(
                "{}** {} syscall sigaltstack()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        187 => {
            log::info!(
                "{}** {} syscall sendfile()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        188 => {
            log::info!(
                "{}** {} syscall getpmsg()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        189 => {
            log::info!(
                "{}** {} syscall putpmsg()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        190 => {
            log::info!(
                "{}** {} syscall vfork()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        191 => {
            log::info!(
                "{}** {} syscall ugetrlimit()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        192 => {
            log::info!(
                "{}** {} syscall mmap2()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        193 => {
            log::info!(
                "{}** {} syscall truncate64()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        194 => {
            log::info!(
                "{}** {} syscall ftruncate64()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        195 => {
            log::info!(
                "{}** {} syscall stat64()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        196 => {
            log::info!(
                "{}** {} syscall lstat64()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        197 => {
            log::info!(
                "{}** {} syscall fstat64()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        198 => {
            log::info!(
                "{}** {} syscall lchown32()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        199 => {
            log::info!(
                "{}** {} syscall getuid32()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        200 => {
            log::info!(
                "{}** {} syscall getgid32()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        201 => {
            log::info!(
                "{}** {} syscall geteuid32()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        202 => {
            log::info!(
                "{}** {} syscall getegid32()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        203 => {
            log::info!(
                "{}** {} syscall getreuid32()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        204 => {
            log::info!(
                "{}** {} syscall getregid32()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        205 => {
            log::info!(
                "{}** {} syscall getgrups32()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        206 => {
            log::info!(
                "{}** {} syscall setgroups32()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        207 => {
            log::info!(
                "{}** {} syscall fchown32()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        208 => {
            log::info!(
                "{}** {} syscall setresuid32()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        209 => {
            log::info!(
                "{}** {} syscall getresuid32()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        210 => {
            log::info!(
                "{}** {} syscall setresgid32()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        211 => {
            log::info!(
                "{}** {} syscall getresgid32()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        212 => {
            log::info!(
                "{}** {} syscall chown32()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        213 => {
            log::info!(
                "{}** {} syscall setuid32()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        214 => {
            log::info!(
                "{}** {} syscall setgid32()  {}",
                emu.colors.light_red,
                emu.pos,
                emu.colors.nc
            );
        }

        _ => {
            let data: Vec<String> = vec![
                "restart_syscall".to_string(),
                "exit".to_string(),
                "fork".to_string(),
                "read".to_string(),
                "write".to_string(),
                "open".to_string(),
                "close".to_string(),
                "waitpid".to_string(),
                "creat".to_string(),
                "link".to_string(),
                "unlink".to_string(),
                "execve".to_string(),
                "chdir".to_string(),
                "time".to_string(),
                "mknod".to_string(),
                "chmod".to_string(),
                "lchown".to_string(),
                "break".to_string(),
                "oldstat".to_string(),
                "lseek".to_string(),
                "getpid".to_string(),
                "mount".to_string(),
                "umount".to_string(),
                "setuid".to_string(),
                "getuid".to_string(),
                "stime".to_string(),
                "ptrace".to_string(),
                "alarm".to_string(),
                "oldfstat".to_string(),
                "pause".to_string(),
                "utime".to_string(),
                "stty".to_string(),
                "gtty".to_string(),
                "access".to_string(),
                "nice".to_string(),
                "ftime".to_string(),
                "sync".to_string(),
                "kill".to_string(),
                "rename".to_string(),
                "mkdir".to_string(),
                "rmdir".to_string(),
                "dup".to_string(),
                "pipe".to_string(),
                "times".to_string(),
                "prof".to_string(),
                "brk".to_string(),
                "setgid".to_string(),
                "getgid".to_string(),
                "signal".to_string(),
                "geteuid".to_string(),
                "getegid".to_string(),
                "acct".to_string(),
                "umount2".to_string(),
                "lock".to_string(),
                "ioctl".to_string(),
                "fcntl".to_string(),
                "mpx".to_string(),
                "setpgid".to_string(),
                "ulimit".to_string(),
                "oldolduname".to_string(),
                "umask".to_string(),
                "chroot".to_string(),
                "ustat".to_string(),
                "dup2".to_string(),
                "getppid".to_string(),
                "getpgrp".to_string(),
                "setsid".to_string(),
                "sigaction".to_string(),
                "sgetmask".to_string(),
                "ssetmask".to_string(),
                "setreuid".to_string(),
                "setregid".to_string(),
                "sigsuspend".to_string(),
                "sigpending".to_string(),
                "sethostname".to_string(),
                "setrlimit".to_string(),
                "getrlimit".to_string(),
                "getrusage".to_string(),
                "gettimeofday".to_string(),
                "settimeofday".to_string(),
                "getgroups".to_string(),
                "setgroups".to_string(),
                "select".to_string(),
                "symlink".to_string(),
                "oldlstat".to_string(),
                "readlink".to_string(),
                "uselib".to_string(),
                "swapon".to_string(),
                "reboot".to_string(),
                "readdir".to_string(),
                "mmap".to_string(),
                "munmap".to_string(),
                "truncate".to_string(),
                "ftruncate".to_string(),
                "fchmod".to_string(),
                "fchown".to_string(),
                "getpriority".to_string(),
                "setpriority".to_string(),
                "profil".to_string(),
                "statfs".to_string(),
                "fstatfs".to_string(),
                "ioperm".to_string(),
                "socketcall".to_string(),
                "syslog".to_string(),
                "setitimer".to_string(),
                "getitimer".to_string(),
                "stat".to_string(),
                "lstat".to_string(),
                "fstat".to_string(),
                "olduname".to_string(),
                "iopl".to_string(),
                "vhangup".to_string(),
                "idle".to_string(),
                "vm86old".to_string(),
                "wait4".to_string(),
                "swapoff".to_string(),
                "sysinfo".to_string(),
                "ipc".to_string(),
                "fsync".to_string(),
                "sigreturn".to_string(),
                "clone".to_string(),
                "setdomainname".to_string(),
                "uname".to_string(),
                "modify_ldt".to_string(),
                "adjtimex".to_string(),
                "mprotect".to_string(),
                "sigprocmask".to_string(),
                "create_module".to_string(),
                "init_module".to_string(),
                "delete_module".to_string(),
                "get_kernel_syms".to_string(),
                "quotactl".to_string(),
                "getpgid".to_string(),
                "fchdir".to_string(),
                "bdflush".to_string(),
                "sysfs".to_string(),
                "personality".to_string(),
                "afs_syscall".to_string(),
                "setfsuid".to_string(),
                "setfsgid".to_string(),
                "_llseek".to_string(),
                "getdents".to_string(),
                "_newselect".to_string(),
                "flock".to_string(),
                "msync".to_string(),
                "readv".to_string(),
                "writev".to_string(),
                "getsid".to_string(),
                "fdatasync".to_string(),
                "_sysctl".to_string(),
                "mlock".to_string(),
                "munlock".to_string(),
                "mlockall".to_string(),
                "munlockall".to_string(),
                "sched_setparam".to_string(),
                "sched_getparam".to_string(),
                "sched_setscheduler".to_string(),
                "sched_getscheduler".to_string(),
                "sched_yield".to_string(),
                "sched_get_priority_max".to_string(),
                "sched_get_priority_min".to_string(),
                "sched_rr_get_interval".to_string(),
                "nanosleep".to_string(),
                "mremap".to_string(),
                "setresuid".to_string(),
                "getresuid".to_string(),
                "vm86".to_string(),
                "query_module".to_string(),
                "poll".to_string(),
                "nfsservctl".to_string(),
                "setresgid".to_string(),
                "getresgid".to_string(),
                "prctl".to_string(),
                "rt_sigreturn".to_string(),
                "rt_sigaction".to_string(),
                "rt_sigprocmask".to_string(),
                "rt_sigpending".to_string(),
                "rt_sigtimedwait".to_string(),
                "rt_sigqueueinfo".to_string(),
                "rt_sigsuspend".to_string(),
                "pread64".to_string(),
                "pwrite64".to_string(),
                "chown".to_string(),
                "getcwd".to_string(),
                "capget".to_string(),
                "capset".to_string(),
                "sigaltstack".to_string(),
                "sendfile".to_string(),
                "getpmsg".to_string(),
                "putpmsg".to_string(),
                "vfork".to_string(),
                "ugetrlimit".to_string(),
                "mmap2".to_string(),
                "truncate64".to_string(),
                "ftruncate64".to_string(),
                "stat64".to_string(),
                "lstat64".to_string(),
                "fstat64".to_string(),
                "lchown32".to_string(),
                "getuid32".to_string(),
                "getgid32".to_string(),
                "geteuid32".to_string(),
                "getegid32".to_string(),
                "setreuid32".to_string(),
                "setregid32".to_string(),
                "getgroups32".to_string(),
                "setgroups32".to_string(),
                "fchown32".to_string(),
                "setresuid32".to_string(),
                "getresuid32".to_string(),
                "setresgid32".to_string(),
                "getresgid32".to_string(),
                "chown32".to_string(),
                "setuid32".to_string(),
                "setgid32".to_string(),
                "setfsuid32".to_string(),
                "setfsgid32".to_string(),
                "pivot_root".to_string(),
                "mincore".to_string(),
                "madvise".to_string(),
                "getdents64".to_string(),
                "fcntl64".to_string(),
                "gettid".to_string(),
                "readahead".to_string(),
                "setxattr".to_string(),
                "lsetxattr".to_string(),
                "fsetxattr".to_string(),
                "getxattr".to_string(),
                "lgetxattr".to_string(),
                "fgetxattr".to_string(),
                "listxattr".to_string(),
                "llistxattr".to_string(),
                "flistxattr".to_string(),
                "removexattr".to_string(),
                "lremovexattr".to_string(),
                "fremovexattr".to_string(),
                "tkill".to_string(),
                "sendfile64".to_string(),
                "futex".to_string(),
                "sched_setaffinity".to_string(),
                "sched_getaffinity".to_string(),
                "set_thread_area".to_string(),
                "get_thread_area".to_string(),
                "io_setup".to_string(),
                "io_destroy".to_string(),
                "io_getevents".to_string(),
                "io_submit".to_string(),
                "io_cancel".to_string(),
                "fadvise64".to_string(),
                "exit_group".to_string(),
                "lookup_dcookie".to_string(),
                "epoll_create".to_string(),
                "epoll_ctl".to_string(),
                "epoll_wait".to_string(),
                "remap_file_pages".to_string(),
                "set_tid_address".to_string(),
                "timer_create".to_string(),
                "timer_settime".to_string(),
                "timer_gettime".to_string(),
                "timer_getoverrun".to_string(),
                "timer_delete".to_string(),
                "clock_settime".to_string(),
                "clock_gettime".to_string(),
                "clock_getres".to_string(),
                "clock_nanosleep".to_string(),
                "statfs64".to_string(),
                "fstatfs64".to_string(),
                "tgkill".to_string(),
                "utimes".to_string(),
                "fadvise64_64".to_string(),
                "vserver".to_string(),
                "mbind".to_string(),
                "get_mempolicy".to_string(),
                "set_mempolicy".to_string(),
                "mq_open".to_string(),
                "mq_unlink".to_string(),
                "mq_timedsend".to_string(),
                "mq_timedreceive".to_string(),
                "mq_notify".to_string(),
                "mq_getsetattr".to_string(),
                "kexec_load".to_string(),
                "waitid".to_string(),
                "add_key".to_string(),
                "request_key".to_string(),
                "keyctl".to_string(),
                "ioprio_set".to_string(),
                "ioprio_get".to_string(),
                "inotify_init".to_string(),
                "inotify_add_watch".to_string(),
                "inotify_rm_watch".to_string(),
                "migrate_pages".to_string(),
                "openat".to_string(),
                "mkdirat".to_string(),
                "mknodat".to_string(),
                "fchownat".to_string(),
                "futimesat".to_string(),
                "fstatat64".to_string(),
                "unlinkat".to_string(),
                "renameat".to_string(),
                "linkat".to_string(),
                "symlinkat".to_string(),
                "readlinkat".to_string(),
                "fchmodat".to_string(),
                "faccessat".to_string(),
                "pselect6".to_string(),
                "ppoll".to_string(),
                "unshare".to_string(),
                "set_robust_list".to_string(),
                "get_robust_list".to_string(),
                "splice".to_string(),
                "sync_file_range".to_string(),
                "tee".to_string(),
                "vmsplice".to_string(),
                "move_pages".to_string(),
                "getcpu".to_string(),
                "epoll_pwait".to_string(),
                "utimensat".to_string(),
                "signalfd".to_string(),
                "timerfd_create".to_string(),
                "eventfd".to_string(),
                "fallocate".to_string(),
                "timerfd_settime".to_string(),
                "timerfd_gettime".to_string(),
                "signalfd4".to_string(),
                "eventfd2".to_string(),
                "epoll_create1".to_string(),
                "dup3".to_string(),
                "pipe2".to_string(),
                "inotify_init1".to_string(),
                "preadv".to_string(),
                "pwritev".to_string(),
                "rt_tgsigqueueinfo".to_string(),
                "perf_event_open".to_string(),
                "recvmmsg".to_string(),
                "fanotify_init".to_string(),
                "fanotify_mark".to_string(),
                "prlimit64".to_string(),
                "name_to_handle_at".to_string(),
                "open_by_handle_at".to_string(),
                "clock_adjtime".to_string(),
                "syncfs".to_string(),
                "sendmmsg".to_string(),
                "setns".to_string(),
                "process_vm_readv".to_string(),
                "process_vm_writev".to_string(),
                "kcmp".to_string(),
                "finit_module".to_string(),
                "sched_setattr".to_string(),
                "sched_getattr".to_string(),
                "renameat2".to_string(),
                "seccomp".to_string(),
                "getrandom".to_string(),
                "memfd_create".to_string(),
                "bpf".to_string(),
                "execveat".to_string(),
                "socket".to_string(),
                "socketpair".to_string(),
                "bind".to_string(),
                "connect".to_string(),
                "listen".to_string(),
                "accept4".to_string(),
                "getsockopt".to_string(),
                "setsockopt".to_string(),
                "getsockname".to_string(),
                "getpeername".to_string(),
                "sendto".to_string(),
                "sendmsg".to_string(),
                "recvfrom".to_string(),
                "recvmsg".to_string(),
                "shutdown".to_string(),
                "userfaultfd".to_string(),
                "membarrier".to_string(),
                "mlock2".to_string(),
                "copy_file_range".to_string(),
                "preadv2".to_string(),
                "pwritev2".to_string(),
                "pkey_mprotect".to_string(),
                "pkey_alloc".to_string(),
                "pkey_free".to_string(),
                "statx".to_string(),
                "arch_prctl".to_string(),
                "io_pgetevents".to_string(),
                "rseq".to_string(),
                "semget".to_string(),
                "semctl".to_string(),
                "shmget".to_string(),
                "shmctl".to_string(),
                "shmat".to_string(),
                "shmdt".to_string(),
                "msgget".to_string(),
                "msgsnd".to_string(),
                "msgrcv".to_string(),
                "msgctl".to_string(),
                "clock_gettime64".to_string(),
                "clock_settime64".to_string(),
                "clock_adjtime64".to_string(),
                "clock_getres_time64".to_string(),
                "clock_nanosleep_time64".to_string(),
                "timer_gettime64".to_string(),
                "timer_settime64".to_string(),
                "timerfd_gettime64".to_string(),
                "timerfd_settime64".to_string(),
                "utimensat_time64".to_string(),
                "pselect6_time64".to_string(),
                "ppoll_time64".to_string(),
                "io_pgetevents_time64".to_string(),
                "recvmmsg_time64".to_string(),
                "mq_timedsend_time64".to_string(),
                "mq_timedreceive_time64".to_string(),
                "semtimedop_time64".to_string(),
                "rt_sigtimedwait_time64".to_string(),
                "futex_time64".to_string(),
                "sched_rr_get_interval_time64".to_string(),
                "pidfd_send_signal".to_string(),
                "io_uring_setup".to_string(),
                "io_uring_enter".to_string(),
                "io_uring_register".to_string(),
                "open_tree".to_string(),
                "move_mount".to_string(),
                "fsopen".to_string(),
                "fsconfig".to_string(),
                "fsmount".to_string(),
                "fspick".to_string(),
                "pidfd_open".to_string(),
                "clone3".to_string(),
                "close_range".to_string(),
                "openat2".to_string(),
                "pidfd_getfd".to_string(),
                "faccessat2".to_string(),
                "process_madvise".to_string(),
                "epoll_pwait2".to_string(),
                "mount_setattr".to_string(),
                "quotactl_fd".to_string(),
                "landlock_create_ruleset".to_string(),
                "landlock_add_rule".to_string(),
                "landlock_restrict_self".to_string(),
                "memfd_secret".to_string(),
                "process_mrelease".to_string(),
            ];
            if emu.regs.rax >= data.len() as u64 {
                log::info!(
                    "{}** interrupt 0x80 bad rax value 0x{:x} {}",
                    emu.colors.light_red,
                    emu.regs.rax,
                    emu.colors.nc
                );
            } else {
                log::info!(
                    "{}** interrupt 0x80 function:{} {}",
                    emu.colors.light_red,
                    data[emu.regs.rax as usize],
                    emu.colors.nc
                );
            }
        }
    }
}
