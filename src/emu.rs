
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_must_use)]
#![allow(clippy::assertions_on_constants)]

             
mod flags; 
mod eflags;
pub mod maps;
pub mod regs64;
mod console;
pub mod colors;
pub mod constants;
mod winapi32;
mod winapi64;
mod fpu;
pub mod context32;
pub mod context64;
pub mod syscall32;
pub mod syscall64;
mod breakpoint;
pub mod endpoint;
pub mod structures;
mod exception;
mod pe32;
mod pe64;
mod peb32;
mod peb64;
mod inline;

use fpu::FPU;
use pe32::PE32;
use pe64::PE64;
use maps::Maps;
use flags::Flags;
use colors::Colors;
use eflags::Eflags;
use regs64::Regs64;
use console::Console;
use std::sync::Arc;
use std::sync::atomic;
use crate::config::Config;
use breakpoint::Breakpoint;

use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter, Mnemonic, OpKind, 
    InstructionInfoFactory, Register, MemorySize};

/*
macro_rules! rotate_left {
    ($val:expr, $rot:expr, $bits:expr) => {
       ($val << $rot) | ($val >> ($bits-$rot)) 
    };
}

macro_rules! rotate_right {
    ($val:expr, $rot:expr, $bits:expr) => {
        ($val >> $rot) | ($val << ($bits-$rot))
    };
}*/

macro_rules! get_bit {
    ($val:expr, $count:expr) => {
        ($val & (1 << $count )) >> $count
    };
}

macro_rules! set_bit {
    ($val:expr, $count:expr, $bit:expr) => {
        if $bit == 1 {
            $val |= 1 << $count;
        } else {
            $val &= !(1 << $count);
        }
    };
}

macro_rules! to32 {
    ($val:expr) => {
        ($val & 0xffffffff) as u32
    };
}


pub struct Emu {
    pub regs: Regs64,
    flags: Flags,
    eflags: Eflags,
    fpu: FPU,
    pub maps: Maps,
    exp: u64,
    break_on_alert: bool,
    bp: Breakpoint,
    seh: u64,
    veh: u64,
    eh_ctx: u32,
    cfg: Config,
    colors: Colors,
    pos: u64,
    force_break: bool,
    tls_callbacks: Vec<u64>,
    tls: Vec<u32>,
    fls: Vec<u32>,
    step: bool,
    out: String,
    main_thread_cont: u64,
    gateway_return: u64,
    is_running: Arc<atomic::AtomicU32>,
    break_on_next_cmp: bool,
    break_on_next_return: bool,
    filename: String,
    enabled_ctrlc: bool,
    run_until_ret: bool,
}

impl Emu {
    pub fn new() -> Emu {
        Emu{
            regs: Regs64::new(),
            flags: Flags::new(),
            eflags: Eflags::new(),
            fpu: FPU::new(),
            maps: Maps::new(),
            exp: 0,
            break_on_alert: false,
            bp: Breakpoint::new(),
            seh: 0,
            veh: 0,
            eh_ctx: 0,
            cfg: Config::new(),
            colors: Colors::new(),
            pos: 0,
            force_break: false,
            tls_callbacks: Vec::new(),
            tls: Vec::new(),
            fls: Vec::new(),
            step: false,
            out: String::new(),
            main_thread_cont: 0,
            gateway_return: 0,
            is_running: Arc::new(atomic::AtomicU32::new(0)), 
            break_on_next_cmp: false,
            break_on_next_return: false,
            filename: String::new(),
            enabled_ctrlc: true,
            run_until_ret: false,
        }
    }

    pub fn enable_ctrlc(&mut self) {
        self.enabled_ctrlc = true;
    }

    pub fn disable_ctrlc(&mut self) {
        self.enabled_ctrlc = false;
    }

    pub fn init_stack32(&mut self) {
        let stack = self.maps.get_mem("stack");

        stack.set_base(0x212000); //22d000
        stack.set_size(0x030000);
        //self.regs.set_esp(0x22e000);
        self.regs.set_esp(0x22e000+4);
        self.regs.set_ebp(0x22f000);

        assert!(self.regs.get_esp() < self.regs.get_ebp());
        assert!(self.regs.get_esp() > stack.get_base());
        assert!(self.regs.get_esp() < stack.get_bottom());
        assert!(self.regs.get_ebp() > stack.get_base());
        assert!(self.regs.get_ebp() < stack.get_bottom());
        assert!(stack.inside(self.regs.get_esp()));
        assert!(stack.inside(self.regs.get_ebp()));
    }

    pub fn init_stack64(&mut self) {
        let stack = self.maps.get_mem("stack");

        self.regs.rsp = 0x22e000;
        self.regs.rbp = 0x22f000;
        stack.set_base(0x22a000);
        stack.set_size(0x6000);

        assert!(self.regs.rsp < self.regs.rbp);
        assert!(self.regs.rsp > stack.get_base());
        assert!(self.regs.rsp < stack.get_bottom());
        assert!(self.regs.rbp > stack.get_base());
        assert!(self.regs.rbp < stack.get_bottom());
        assert!(stack.inside(self.regs.rsp));
        assert!(stack.inside(self.regs.rbp));
    }

    pub fn init(&mut self) {
        
        println!("initializing regs");
        self.regs.clear::<64>();
        self.regs.rand();

        if self.cfg.is_64bits {
            self.regs.rip = self.cfg.entry_point;
            self.maps.is_64bits = true;
            self.init_mem64();
            self.init_stack64();
       
        } else { // 32bits
            self.regs.sanitize32();
            self.regs.set_eip(self.cfg.entry_point);
            self.init_mem32();
            self.init_stack32();
        }

        self.init_tests();
    }

    pub fn init_mem32(&mut self) {
        println!("loading memory maps");
        self.maps.create_map("10000");
        self.maps.create_map("20000");
        self.maps.create_map("stack");
        self.maps.create_map("code");
        //self.maps.create_map("peb");
        self.maps.create_map("teb");
        self.maps.create_map("ntdll");
        self.maps.create_map("ntdll_text");
        self.maps.create_map("ntdll_data");
        self.maps.create_map("kernel32");
        self.maps.create_map("kernel32_text");
        self.maps.create_map("kernel32_data");
        self.maps.create_map("kernelbase");
        self.maps.create_map("kernelbase_text");
        self.maps.create_map("kernelbase_data");
        self.maps.create_map("msvcrt");
        self.maps.create_map("msvcrt_text");
        self.maps.create_map("reserved");
        self.maps.create_map("kuser_shared_data");
        self.maps.create_map("binary");
        //self.maps.create_map("reserved2");
        self.maps.create_map("ws2_32");
        self.maps.create_map("ws2_32_text");
        self.maps.create_map("wininet");
        self.maps.create_map("wininet_text");
        self.maps.create_map("shlwapi");
        self.maps.create_map("shlwapi_text");
        self.maps.create_map("gdi32");
        self.maps.create_map("gdi32_text");
        self.maps.create_map("user32");
        self.maps.create_map("user32_text");
        self.maps.create_map("lpk");
        self.maps.create_map("lpk_text");
        self.maps.create_map("usp10");
        self.maps.create_map("usp10_text");
        self.maps.create_map("advapi32");
        self.maps.create_map("advapi32_text");
        self.maps.create_map("sechost");
        self.maps.create_map("sechost_text");
        self.maps.create_map("rpcrt4");
        self.maps.create_map("rpcrt4_text");
        self.maps.create_map("urlmon");
        self.maps.create_map("urlmon_text");
        self.maps.create_map("ole32");
        self.maps.create_map("ole32_text");
        self.maps.create_map("oleaut32");
        self.maps.create_map("oleaut32_text");
        self.maps.create_map("crypt32");
        self.maps.create_map("crypt32_text");
        self.maps.create_map("msasn1");
        self.maps.create_map("msasn1_text");
        self.maps.create_map("iertutils");
        self.maps.create_map("iertutils_text");
        self.maps.create_map("imm32");
        self.maps.create_map("imm32_text");
        self.maps.create_map("msctf");
        self.maps.create_map("msctf_text");


        //self.maps.write_byte(0x2c3000, 0x61); // metasploit trick


        let orig_path = std::env::current_dir().unwrap();
        std::env::set_current_dir(self.cfg.maps_folder.clone());

        self.maps.get_mem("code").set_base(self.cfg.code_base_addr);
        let kernel32 = self.maps.get_mem("kernel32");
        kernel32.set_base(0x75e40000);
        if !kernel32.load("kernel32.bin") {
            println!("cannot find the maps files, use --maps flag to speficy the folder.");
            std::process::exit(1);
        }

        let kernel32_text = self.maps.get_mem("kernel32_text");
        kernel32_text.set_base(0x75e41000);
        kernel32_text.load("kernel32_text.bin");

        let kernel32_data = self.maps.get_mem("kernel32_data");
        kernel32_data.set_base(0x75f06000);
        kernel32_data.load("kernel32_data.bin");

        let kernelbase = self.maps.get_mem("kernelbase");
        kernelbase.set_base(0x75940000);
        kernelbase.load("kernelbase.bin");

        let kernelbase_text = self.maps.get_mem("kernelbase_text");
        kernelbase_text.set_base(0x75941000);
        kernelbase_text.load("kernelbase_text.bin");

        let kernelbase_data = self.maps.get_mem("kernelbase_data");
        kernelbase_data.set_base(0x75984000);
        kernelbase_data.load("kernelbase_data.bin");

        let msvcrt = self.maps.get_mem("msvcrt");
        msvcrt.set_base(0x761e0000);
        msvcrt.load("msvcrt.bin");

        let msvcrt_text = self.maps.get_mem("msvcrt_text");
        msvcrt_text.set_base(0x761e1000);
        msvcrt_text.load("msvcrt_text.bin");

        /*let reserved2 = self.maps.get_mem("reserved2");
          reserved2.set_base(0x2c3000); //0x2c3018
          reserved2.set_size(0xfd000);*/

        let reserved = self.maps.get_mem("reserved");
        reserved.set_base(0x2c0000);
        reserved.load("reserved.bin");
        assert!(reserved.read_byte(0x2c31a0) != 0);


        /*let peb = self.maps.get_mem("peb");
        peb.set_base(0x7ffdf000);
        peb.load("peb.bin");*/
    

        let teb = self.maps.get_mem("teb");
        teb.set_base(0x7ffde000);
        teb.load("teb.bin");

        let ntdll = self.maps.get_mem("ntdll");
        ntdll.set_base(0x77570000);
        ntdll.load("ntdll.bin");

        let ntdll_text = self.maps.get_mem("ntdll_text");
        ntdll_text.set_base(0x77571000);
        ntdll_text.load("ntdll_text.bin");

        let ntdll_data = self.maps.get_mem("ntdll_data");
        ntdll_data.set_base(0x77647000);
        ntdll_data.load("ntdll_data.bin");

        let kuser_shared_data = self.maps.get_mem("kuser_shared_data");
        kuser_shared_data.set_base(0x7ffe0000);
        kuser_shared_data.load("kuser_shared_data.bin");

        let binary = self.maps.get_mem("binary");
        binary.set_base(0x400000);
        binary.set_size(0x1000);



        let ws2_32 = self.maps.get_mem("ws2_32");
        ws2_32.set_base(0x77480000);
        ws2_32.load("ws2_32.bin");

        let ws2_32_text = self.maps.get_mem("ws2_32_text");
        ws2_32_text.set_base(0x77481000);
        ws2_32_text.load("ws2_32_text.bin");

        let wininet = self.maps.get_mem("wininet");
        wininet.set_base(0x76310000);
        wininet.load("wininet.bin");

        let wininet_text = self.maps.get_mem("wininet_text");
        wininet_text.set_base(0x76311000);
        wininet_text.load("wininet_text.bin");

        let shlwapi = self.maps.get_mem("shlwapi");
        shlwapi.set_base(0x76700000);
        shlwapi.load("shlwapi.bin");

        let shlwapi_text = self.maps.get_mem("shlwapi_text");
        shlwapi_text.set_base(0x76701000);
        shlwapi_text.load("shlwapi_text.bin");

        let gdi32 = self.maps.get_mem("gdi32");
        gdi32.set_base(0x759c0000);
        gdi32.load("gdi32.bin");

        let gdi32_text = self.maps.get_mem("gdi32_text");
        gdi32_text.set_base(0x759c1000);
        gdi32_text.load("gdi32_text.bin");

        let user32 = self.maps.get_mem("user32");
        user32.set_base(0x773b0000);
        user32.load("user32.bin");

        let user32_text = self.maps.get_mem("user32_text");
        user32_text.set_base(0x773b1000);
        user32_text.load("user32_text.bin");

        let lpk = self.maps.get_mem("lpk");
        lpk.set_base(0x75b00000);
        lpk.load("lpk.bin");

        let lpk_text = self.maps.get_mem("lpk_text");
        lpk_text.set_base(0x75b01000);
        lpk_text.load("lpk_text.bin");

        let usp10 = self.maps.get_mem("usp10");
        usp10.set_base(0x76660000);
        usp10.load("usp10.bin");

        let usp10_text = self.maps.get_mem("usp10_text");
        usp10_text.set_base(0x76661000);
        usp10_text.load("usp10_text.bin");

        let advapi32 = self.maps.get_mem("advapi32");
        advapi32.set_base(0x776f0000);
        advapi32.load("advapi32.bin");

        let advapi32_text = self.maps.get_mem("advapi32_text");
        advapi32_text.set_base(0x776f1000);
        advapi32_text.load("advapi32_text.bin");

        let sechost = self.maps.get_mem("sechost");
        sechost.set_base(0x75a10000);
        sechost.load("sechost.bin");

        let sechost_text = self.maps.get_mem("sechost_text");
        sechost_text.set_base(0x75a11000);
        sechost_text.load("sechost_text.bin");

        let rpcrt4 = self.maps.get_mem("rpcrt4");
        rpcrt4.set_base(0x774c0000);
        rpcrt4.load("rpcrt4.bin");

        let rpcrt4_text = self.maps.get_mem("rpcrt4_text");
        rpcrt4_text.set_base(0x774c1000);
        rpcrt4_text.load("rpcrt4_text.bin");

        let urlmon = self.maps.get_mem("urlmon");
        urlmon.set_base(0x75b60000);
        urlmon.load("urlmon.bin");

        let urlmon_text = self.maps.get_mem("urlmon_text");
        urlmon_text.set_base(0x75b61000);
        urlmon_text.load("urlmon_text.bin");

        let ole32 = self.maps.get_mem("ole32");
        ole32.set_base(0x76500000);
        ole32.load("ole32.bin");

        let ole32_text = self.maps.get_mem("ole32_text");
        ole32_text.set_base(0x76501000);
        ole32_text.load("ole32_text.bin");

        let oleaut32 = self.maps.get_mem("oleaut32");
        oleaut32.set_base(0x76470000);
        oleaut32.load("oleaut32.bin");

        let oleaut32_text = self.maps.get_mem("oleaut32_text");
        oleaut32_text.set_base(0x76471000);
        oleaut32_text.load("oleaut32_text.bin");

        let crypt32 = self.maps.get_mem("crypt32");
        crypt32.set_base(0x757d0000);
        crypt32.load("crypt32.bin");

        let crypt32_text = self.maps.get_mem("crypt32_text");
        crypt32_text.set_base(0x757d1000);
        crypt32_text.load("crypt32_text.bin");

        let msasn1 = self.maps.get_mem("msasn1");
        msasn1.set_base(0x75730000);
        msasn1.load("msasn1.bin");

        let msasn1_text = self.maps.get_mem("msasn1_text");
        msasn1_text.set_base(0x75731000);
        msasn1_text.load("msasn1_text.bin");

        let iertutils = self.maps.get_mem("iertutils");
        iertutils.set_base(0x75fb0000);
        iertutils.load("iertutils.bin");

        let iertutils_text = self.maps.get_mem("iertutils_text");
        iertutils_text.set_base(0x75fb1000);
        iertutils_text.load("iertutils_text.bin");

        let imm32 = self.maps.get_mem("imm32");
        imm32.set_base(0x776d0000);
        imm32.load("imm32.bin");

        let imm32_text = self.maps.get_mem("imm32_text");
        imm32_text.set_base(0x776d1000);
        imm32_text.load("imm32_text.bin");

        let msctf = self.maps.get_mem("msctf");
        msctf.set_base(0x75a30000);
        msctf.load("msctf.bin");

        let msctf_text = self.maps.get_mem("msctf_text");
        msctf_text.set_base(0x75a31000);
        msctf_text.load("msctf_text.bin");

        let m10000 = self.maps.get_mem("10000");
        m10000.set_base(0x10000);
        m10000.load("m10000.bin");
        m10000.set_size(0xffff);


        let m20000 = self.maps.get_mem("20000");
        m20000.set_base(0x20000);
        m20000.load("m20000.bin");
        m20000.set_size(0xffff);



        let (base, pe_hdr) = self.load_pe32("nsi.dll", false, 0x776c0000);



        //let nsi = self.maps.create_map("NSI.dll");
        //nsi.set_base(0x776c0000);
        //nsi.load("nsi.dll");



        // xloader initial state hack
        //self.memory_write("dword ptr [esp + 4]", 0x22a00);
        //self.maps.get_mem("kernel32_xloader").set_base(0x75e40000) 


        std::env::set_current_dir(orig_path);

    }

    pub fn init_tests(&mut self) {

        let mem = self.maps.create_map("test");
        mem.set_base(0);
        mem.set_size(1024);
        mem.write_qword(0, 0x1122334455667788);
        assert!(mem.read_qword(0) == 0x1122334455667788);
        self.maps.free("test");



        // some tests
        assert!(get_bit!(0xffffff00u32, 0) == 0);
        assert!(get_bit!(0xffffffffu32, 5) == 1);
        assert!(get_bit!(0xffffff00u32, 5) == 0);
        assert!(get_bit!(0xffffff00u32, 7) == 0);
        assert!(get_bit!(0xffffff00u32, 8) == 1);

        let mut a:u32 = 0xffffff00;
        set_bit!(a, 0, 1);
        set_bit!(a, 1, 1);
        set_bit!(a, 2, 1);
        set_bit!(a, 3, 1);
        set_bit!(a, 4, 1);
        set_bit!(a, 5, 1);
        set_bit!(a, 6, 1);
        set_bit!(a, 7, 1);

        assert!(a == 0xffffffff);

        set_bit!(a, 0, 0);
        set_bit!(a, 1, 0);
        set_bit!(a, 2, 0);
        set_bit!(a, 3, 0);
        set_bit!(a, 4, 0);
        set_bit!(a, 5, 0);
        set_bit!(a, 6, 0);
        set_bit!(a, 7, 0);

        assert!(a == 0xffffff00);

        assert!(self.shrd(0x9fd88893, 0x1b, 0x6, 32) == 0x6e7f6222);
        assert!(self.shrd(0x6fdcb03, 0x0, 0x6, 32) == 0x1bf72c);
        assert!(self.shrd(0x91545f1d, 0x6fe2, 0x6, 32) == 0x8a45517c);
        assert!(self.shld(0x1b, 0xf1a7eb1d, 0xa, 32) == 0x6fc6);
        assert!(self.shld(0x1, 0xffffffff, 4, 32) == 0x1f);
        assert!(self.shld(0x1, 0xffffffff, 33, 32) == 0x3);
        assert!(self.shld(0x144e471f8, 0x14F498, 0x3e, 64) == 0x53d26);


        if self.maps.mem_test() {
            println!("memory test Ok.");
        } else {
            eprintln!("It doesn't pass the memory tests!!");
            self.spawn_console();
            std::process::exit(1);
        }
    }

    pub fn init_mem64(&mut self) {
        println!("loading memory maps");

        let orig_path = std::env::current_dir().unwrap();
        std::env::set_current_dir(self.cfg.maps_folder.clone());

        self.maps.create_map("m10000").load_at(0x10000);
        self.maps.create_map("m20000").load_at(0x20000);
        self.maps.create_map("m520000").load_at(0x520000);
        self.maps.create_map("m53b000").load_at(0x53b000);
        self.maps.create_map("exe_pe").load_at(0x400000);
        self.maps.create_map("code").set_base(self.cfg.code_base_addr);
        self.maps.create_map("stack");
        //self.maps.create_map("peb").load_at(0x7fffffdf000);
        peb64::init_peb(self);
        self.maps.create_map("teb").load_at(0x7fffffdd000);
        self.maps.create_map("ntdll_pe").load_at(0x76fd0000);
        self.maps.create_map("ntdll_text").load_at(0x76fd1000);
        self.maps.create_map("ntdll_rt").load_at(0x770d2000);
        self.maps.create_map("ntdll_rdata").load_at(0x770d3000);
        self.maps.create_map("ntdll_data").load_at(0x77102000);
        self.maps.create_map("kernel32_pe").load_at(0x76db0000);
        self.maps.create_map("kernel32_text").load_at(0x76db1000);
        self.maps.create_map("kernel32_rdata").load_at(0x76e4c000);
        self.maps.create_map("kernel32_data").load_at(0x76eba000);
        self.maps.create_map("kernelbase_pe").load_at(0x7fefd010000);
        self.maps.create_map("kernelbase_text").load_at(0x7fefd011000);
        self.maps.create_map("kernelbase_rdata").load_at(0x7fefd05a000);
        self.maps.create_map("kernelbase_data").load_at(0x7fefd070000);
        self.maps.create_map("msvcrt_pe").load_at(0x7fefef00000);
        self.maps.create_map("msvcrt_text").load_at(0x7fefef01000);
        self.maps.create_map("msvcrt_rdata").load_at(0x7fefef7a000);
        self.maps.create_map("user32_pe").load_at(0x76ed0000);
        self.maps.create_map("user32_text").load_at(0x76ed1000);
        self.maps.create_map("user32_rdata").load_at(0x76f52000);
        self.maps.create_map("msasn1_pe").load_at(0x7fefcfc0000);
        self.maps.create_map("msasn1_text").load_at(0x7fefcfc1000);
        self.maps.create_map("msasn1_rdata").load_at(0x7fefcfc9000);
        self.maps.create_map("crypt32_pe").load_at(0x7fefd0c0000);
        self.maps.create_map("crypt32_text").load_at(0x7fefd0c1000);
        self.maps.create_map("crypt32_rdata").load_at(0x7fefd18f000);
        self.maps.create_map("msctf_pe").load_at(0x7fefd2f0000);
        self.maps.create_map("msctf_text").load_at(0x7fefd2f1000);
        self.maps.create_map("msctf_rdata").load_at(0x7fefd391000);
        self.maps.create_map("iertutil_pe").load_at(0x7fefd400000);
        self.maps.create_map("iertutil_text").load_at(0x7fefd401000);
        self.maps.create_map("iertutil_rdata").load_at(0x7fefd43e000);
        self.maps.create_map("ole32_pe").load_at(0x7fefd660000);
        self.maps.create_map("ole32_text").load_at(0x7fefd661000);
        self.maps.create_map("ole32_rdata").load_at(0x7fefd7df000);
        self.maps.create_map("lpk_pe").load_at(0x7fefd870000);
        self.maps.create_map("lpk_text").load_at(0x7fefd871000);
        self.maps.create_map("lpk_rdata").load_at(0x7fefd878000);
        self.maps.create_map("wininet_pe").load_at(0x6fefd880000);
        self.maps.create_map("wininet_text").load_at(0x6fefd881000);
        self.maps.create_map("gdi32_pe").load_at(0x7fefd9b0000);
        self.maps.create_map("gdi32_text").load_at(0x7fefd9b1000);
        self.maps.create_map("gdi32_rdata").load_at(0x7fefda02000);
        self.maps.create_map("imm32_pe").load_at(0x7fefe990000);
        self.maps.create_map("imm32_text").load_at(0x7fefe991000);
        self.maps.create_map("imm32_rdata").load_at(0x7fefe9ad000);
        self.maps.create_map("usp10_pe").load_at(0x7fefe9c0000);
        self.maps.create_map("usp10_text").load_at(0x7fefe9c1000);
        self.maps.create_map("sechost_pe").load_at(0x7fefea90000);
        self.maps.create_map("sechost_text").load_at(0x7fefea91000);
        self.maps.create_map("rpcrt4_pe").load_at(0x7fefeab0000);
        self.maps.create_map("rpcrt4_text").load_at(0x7fefeab1000);
        self.maps.create_map("rpcrt4_rdata").load_at(0x7fefeb93000);
        self.maps.create_map("nsi_pe").load_at(0x7fefebe0000);
        self.maps.create_map("nsi_text").load_at(0x7fefebe1000);
        self.maps.create_map("nsi_rdata").load_at(0x7fefebe3000);
        self.maps.create_map("urlmon_pe").load_at(0x7fefed30000);
        self.maps.create_map("urlmon_text").load_at(0x7fefed31000);
        self.maps.create_map("urlmon_rdata").load_at(0x7fefee05000);
        self.maps.create_map("ws2_32_pe").load_at(0x7fefeeb0000);
        self.maps.create_map("ws2_32_text").load_at(0x7fefeeb1000);
        self.maps.create_map("ws2_32_rdata").load_at(0x7fefeee1000);
        self.maps.create_map("msvcrt_pe").load_at(0x7fefef00000);
        self.maps.create_map("msvcrt_text").load_at(0xfefef01000);
        self.maps.create_map("advapi32_pe").load_at(0xfefefa0000);
        self.maps.create_map("advapi32_text").load_at(0x7fefefa1000);
        self.maps.create_map("oleaut32_pe").load_at(0x7feff180000);
        self.maps.create_map("oleaut32_text").load_at(0x7feff181000);
        self.maps.create_map("oleaut32_rdata").load_at(0x7feff21d000);
        self.maps.create_map("shlwapi_pe").load_at(0x7feff260000);
        self.maps.create_map("shlwapi_text").load_at(0x7feff261000);
        self.maps.create_map("shlwapi_rdata").load_at(0x7feff2a5000);
        self.maps.create_map("winhttp_pe").load_at(0x7fef9760000);
        self.maps.create_map("winhttp_text").load_at(0x7fef9761000);
        self.maps.create_map("dnsapi_pe").load_at(0x7fefc5f0000);
        self.maps.create_map("dnsapi_text").load_at(0x7fefc5f1000);
        self.maps.create_map("iphlpapi_pe").load_at(0x7fefc1b0000);
        self.maps.create_map("iphlpapi_text").load_at(0x7fefc1b1000);

        // peb64 patch for being_debugged
        let peb = self.maps.get_mem("peb");
        peb.write_byte(peb.get_base() + 2, 0);


        std::env::set_current_dir(orig_path);
    }

    pub fn filename_to_mapname(&self, filename: &str) -> String {
        let spl:Vec<&str> = filename.split('.').collect();
        let spl2:Vec<&str> = spl[0].split('/').collect();
        let last = spl2.len() -1;
        spl2[last].to_string()
    }   

    pub fn load_pe32(&mut self, filename: &str, set_entry: bool, force_base: u32) -> (u32,u32) {
        let mut pe32 = PE32::load(filename);
        let mut base;

        if force_base > 0 {
            base = force_base;
        } else {
            base = pe32.opt.image_base;
        }

        if self.cfg.code_base_addr != 0x3c0000 {
            base = self.cfg.code_base_addr as u32;
        }

        let map_name = self.filename_to_mapname(filename);

        if set_entry {
            let space_addr = peb32::create_ldr_entry(self, base as u64, pe32.dos.e_lfanew, 
                                                     &map_name, 0, 0x2c1950);
            let peb = peb32::init_peb(self, space_addr, base);
            self.maps.write_dword(peb + 8, base);
            
            pe32.iat_binding(self);
        }

        //TODO: query if this vaddr is already used
        let pemap = self.maps.create_map(&format!("{}.pe", map_name));

    
        pemap.set_base(base.into());
        pemap.set_size(pe32.opt.size_of_headers.into());
        pemap.memcpy(pe32.get_headers(), pe32.opt.size_of_headers as usize);

        println!("Loaded {}", filename);
        println!("\t{} sections  base addr 0x{:x}", pe32.num_of_sections(), base);

        for i in 0..pe32.num_of_sections() {
            let base:u32;
            if force_base > 0 {
                base = force_base;
            } else {
                base = pe32.opt.image_base;
            }
            let ptr = pe32.get_section_ptr(i);
            let sect = pe32.get_section(i);
            let map = self.maps.create_map(&format!("{}{}", map_name, 
                                                    sect.get_name().replace(" ","").replace("\t","")
                                                    .replace("\x0a","").replace("\x0d","")));

            map.set_base(base as u64 + sect.virtual_address as u64);
            if sect.virtual_size > sect.size_of_raw_data {
                map.set_size(sect.virtual_size as u64);
            } else {
                map.set_size(sect.size_of_raw_data as u64);
            }
            map.memcpy(ptr, ptr.len());

            println!("\tcreated pe32 map for section `{}` at 0x{:x} size: {}", sect.get_name(), 
                     map.get_base(), sect.virtual_size);
            if set_entry {
                if sect.get_name() == ".text" || i == 0 {
                    if self.cfg.entry_point != 0x3c0000 {
                        self.regs.rip = self.cfg.entry_point;
                        println!("entry point at 0x{:x} but forcing it at 0x{:x} by -a flag", 
                                 base as u64 + pe32.opt.address_of_entry_point as u64,
                                 self.regs.rip);

                    } else {
                        self.regs.rip = base as u64 + pe32.opt.address_of_entry_point as u64;
                    }
                    println!("\tentry point at 0x{:x}  0x{:x} ", self.regs.rip, pe32.opt.address_of_entry_point);
                }
            }
        }

        let pe_hdr_off = pe32.dos.e_lfanew;


        pe32.clear();
        return (base, pe_hdr_off);
    }

    pub fn load_pe64(&mut self, filename: &str, set_entry: bool, force_base: u64) -> (u64,u32) {
        let mut pe64 = PE64::load(filename);
        let mut base:u64;

        if force_base > 0 {
            base = force_base;
        } else {
            base = pe64.opt.image_base;
        }

        if self.cfg.code_base_addr != 0x3c0000 {
            base = self.cfg.code_base_addr;
        }

        let map_name = self.filename_to_mapname(filename);

        if set_entry {
            //TODO: update the peb64 with latest changes on peb32
            pe64.iat_binding(self);
        }

    
        //TODO: query if this vaddr is already used
        let pemap = self.maps.create_map(&format!("{}.pe", map_name));
        pemap.set_base(base.into());
        pemap.set_size(pe64.opt.size_of_headers.into());
        pemap.memcpy(pe64.get_headers(), pe64.opt.size_of_headers as usize);

        println!("Loaded {}", filename);
        println!("\t{} sections, base addr 0x{:x}", pe64.num_of_sections(), base);

        for i in 0..pe64.num_of_sections() {
            let base;
            if force_base > 0 {
                base = force_base;
            } else {
                base = pe64.opt.image_base;
            }
            let ptr = pe64.get_section_ptr(i);
            let sect = pe64.get_section(i);
            let map = self.maps.create_map(&format!("{}{}", map_name, 
                                                    sect.get_name().replace(" ","").replace("\t","")
                                                    .replace("\x0a","").replace("\x0d","")));

            map.set_base(base + sect.virtual_address as u64);
            if sect.virtual_size > sect.size_of_raw_data {
                map.set_size(sect.virtual_size as u64);
            } else {
                map.set_size(sect.size_of_raw_data as u64);
            }
            map.memcpy(ptr, ptr.len());

            println!("\tcreated pe64 map for section `{}` at 0x{:x} size: {}", sect.get_name(), 
                     map.get_base(), sect.virtual_size);

            if set_entry {
                if sect.get_name() == ".text" || i == 0 {

                    if pe64.opt.address_of_entry_point == 0 {
                        self.regs.rip = base + sect.virtual_address as u64 + 
                            sect.pointer_to_raw_data as u64;
                    } else {
                        self.regs.rip = base + pe64.opt.address_of_entry_point as u64; 
                    }

                    println!("\tentry point at 0x{:x}  0x{:x} ", self.regs.rip, pe64.opt.address_of_entry_point);
                } else if sect.get_name() == ".tls" {
                    let tls_off = sect.pointer_to_raw_data;
                    self.tls_callbacks = pe64.get_tls_callbacks(sect.virtual_address);
                }
            }
        }

        let pe_hdr_off = pe64.dos.e_lfanew;

        pe64.clear();
        return (base, pe_hdr_off);
    }

    pub fn set_config(&mut self, cfg:Config) {
        self.cfg = cfg;
        if self.cfg.console {
            self.exp = self.cfg.console_num;
        }
        if self.cfg.nocolors {
            self.colors.disable();
        }
    }

    pub fn load_code(&mut self, filename: &str) {
        self.filename = filename.to_string();

        //let map_name = self.filename_to_mapname(filename);  
        //self.cfg.filename = map_name; 

        if !self.cfg.is_64bits && PE32::is_pe32(filename) {
            println!("PE32 header detected.");
            self.load_pe32(filename, true, 0);

        } else if self.cfg.is_64bits && PE64::is_pe64(filename) {
            println!("PE64 header detected.");
            let (base, pe_off) = self.load_pe64(filename, true, 0);
            let ep = self.regs.rip;

            // emulating tls callbacks
            for i in 0..self.tls_callbacks.len() {
                println!("Emulating tls_callback {}", i+1);
                self.regs.rip = self.tls_callbacks[i];
                println!("ret address: 0x{:x}", base);
                self.stack_push64(base);
                self.run(base);
            }

            self.regs.rip = ep;

        } else { // shellcode

            println!("shellcode detected.");
            if !self.cfg.is_64bits {
                peb32::init_peb(self, 0x2c18c0, 0);
            }


            if !self.maps.get_mem("code").load(filename) {
                println!("shellcode not found, select the file with -f");
                std::process::exit(1);
            }
            let code = self.maps.get_mem("code");
            code.extend(0xffff);
        }
    }

    pub fn alloc(&mut self, name:&str, size:u64) -> u64 {
        let addr = match self.maps.alloc(size) {
            Some(a) => a,
            None => {
                println!("low memory");
                return 0;
            }
        };
        let map = self.maps.create_map(name);
        map.set_base(addr);
        map.set_size(size);
        addr
    }

    pub fn stack_push32(&mut self, value:u32) {
        if self.cfg.stack_trace {
            println!("--- stack push32 ---");
            self.maps.dump_dwords(self.regs.get_esp(), 5);
        }

        self.regs.set_esp(self.regs.get_esp() - 4);
        let stack = self.maps.get_mem("stack");
        if stack.inside(self.regs.get_esp()) {
            stack.write_dword(self.regs.get_esp(), value);
        } else {
            let mem = match self.maps.get_mem_by_addr(self.regs.get_esp()) {
                Some(m) => m,
                None =>  {
                    println!("/!\\ pushing stack outside maps esp: 0x{:x}", self.regs.get_esp());
                    self.spawn_console();
                    return;
                }
            };
            mem.write_dword(self.regs.get_esp(), value);
        }
    }

    pub fn stack_push64(&mut self, value:u64) {
        if self.cfg.stack_trace { 
            println!("--- stack push64  ---");
            self.maps.dump_qwords(self.regs.rsp, 5);
        }


        self.regs.rsp -= 8;
        let stack = self.maps.get_mem("stack");
        if stack.inside(self.regs.rsp) {
            stack.write_qword(self.regs.rsp, value);
        } else {
            let mem = match self.maps.get_mem_by_addr(self.regs.rsp) {
                Some(m) => m,
                None =>  {
                    println!("pushing stack outside maps rsp: 0x{:x}", self.regs.get_esp());
                    self.spawn_console();
                    return;
                }
            };
            mem.write_qword(self.regs.rsp, value);
        }
    }

    pub fn stack_pop32(&mut self, pop_instruction:bool) -> u32 {
        if self.cfg.stack_trace {   
            println!("--- stack pop32 ---");
            self.maps.dump_dwords(self.regs.get_esp(), 5);
        }
        
        let stack = self.maps.get_mem("stack");
        if stack.inside(self.regs.get_esp()) {
            let value = stack.read_dword(self.regs.get_esp());
            if self.cfg.verbose >= 1 && pop_instruction && self.maps.get_mem("code").inside(value.into()) {
                println!("/!\\ poping a code address 0x{:x}", value);
            }
            self.regs.set_esp(self.regs.get_esp() + 4);
            return value;
        }

        let mem = match self.maps.get_mem_by_addr(self.regs.get_esp()) {
            Some(m) => m,
            None => panic!("poping stack outside map  esp: 0x{:x}", self.regs.get_esp() as u32),
        };

        let value = mem.read_dword(self.regs.get_esp());
        self.regs.set_esp(self.regs.get_esp() + 4);
        value
    }

    pub fn stack_pop64(&mut self, pop_instruction:bool) -> u64 {
        if self.cfg.stack_trace {
            println!("--- stack pop64 ---");
            self.maps.dump_qwords(self.regs.rsp, 5);
        }

        let stack = self.maps.get_mem("stack");
        if stack.inside(self.regs.rsp) {
            let value = stack.read_qword(self.regs.rsp);
            if self.cfg.verbose >= 1 && pop_instruction && self.maps.get_mem("code").inside(value.into()) {
                println!("/!\\ poping a code address 0x{:x}", value);
            }
            self.regs.rsp += 8;
            return value;
        }

        let mem = match self.maps.get_mem_by_addr(self.regs.rsp) {
            Some(m) => m,
            None => panic!("poping stack outside map  esp: 0x{:x}", self.regs.rsp),
        };

        let value = mem.read_qword(self.regs.rsp);
        self.regs.rsp += 8;
        value
    }

    // this is not used on the emulation
    pub fn memory_operand_to_address(&mut self, operand:&str) -> u64 {
        let spl:Vec<&str> = operand.split('[').collect::<Vec<&str>>()[1].split(']').collect::<Vec<&str>>()[0].split(' ').collect();

        if operand.contains("fs:[") || operand.contains("gs:[") {
            let mem = operand.split(':').collect::<Vec<&str>>()[1];
            let value = self.memory_operand_to_address(mem);

            /*
               fs:[0x30]

               FS:[0x00] : Current SEH Frame
               FS:[0x18] : TEB (Thread Environment Block)
               FS:[0x20] : PID
               FS:[0x24] : TID
               FS:[0x30] : PEB (Process Environment Block)
               FS:[0x34] : Last Error Value
               */

            //let inm = self.get_inmediate(spl[0]);
            if self.cfg.verbose >= 1 {
                println!("FS ACCESS TO 0x{:x}", value);
            }

            if value == 0x30 { // PEB
                if self.cfg.verbose >= 1 {
                    println!("ACCESS TO PEB");
                }
                let peb = self.maps.get_mem("peb");
                return peb.get_base();
            }

            if value == 0x18 {
                if self.cfg.verbose >= 1 {
                    println!("ACCESS TO TEB");
                }
                let teb = self.maps.get_mem("teb");
                return teb.get_base();
            }

            panic!("not implemented: {}", operand);
        }

        if spl.len() == 3 { //ie eax + 0xc
            let sign = spl[1];

            // weird case: [esi + eax*4]
            if spl[2].contains('*') {
                let spl2:Vec<&str> = spl[2].split('*').collect();
                if spl2.len() != 2 {
                    panic!("case ie [esi + eax*4] bad parsed the *  operand:{}", operand);
                } 

                let reg1_val = self.regs.get_by_name(spl[0]);
                let reg2_val = self.regs.get_by_name(spl2[0]);
                let num = u64::from_str_radix(spl2[1].trim_start_matches("0x"),16).expect("bad num conversion");

                if sign != "+" && sign != "-" {
                    panic!("weird sign2 {}", sign);
                }

                if sign == "+" {
                    return reg1_val + (reg2_val * num);
                }

                if sign == "-" {
                    return reg1_val - (reg2_val * num);
                }

                unimplemented!(); 
            }

            let reg = spl[0];
            let sign = spl[1];
            //println!("disp --> {}  operand:{}", spl[2], operand);
            let disp:u64;
            if self.regs.is_reg(spl[2]) {
                disp = self.regs.get_by_name(spl[2]);
            } else {
                disp = u64::from_str_radix(spl[2].trim_start_matches("0x"),16).expect("bad disp");
            }


            if sign != "+" && sign != "-" {
                panic!("weird sign {}", sign);
            }

            if sign == "+" {
                let r:u64 = self.regs.get_by_name(reg) as u64 + disp as u64;
                return r & 0xffffffff;
            } else {
                return self.regs.get_by_name(reg) - disp;
            }

        }

        if spl.len() == 1 { //ie [eax]
            let reg = spl[0];

            if reg.contains("0x") {
                let addr:u64 = u64::from_str_radix(reg.trim_start_matches("0x"),16).expect("bad disp2");
                return addr;
                // weird but could be a hardcoded address [0x11223344]
            }

            let reg_val = self.regs.get_by_name(reg);
            return reg_val;

        }

        0
    }

    // this is not used on the emulation
    pub fn memory_read(&mut self, operand:&str) -> Option<u64> {
        if operand.contains("fs:[0]") {
            if self.cfg.verbose >= 1 {
                println!("{} Reading SEH fs:[0] 0x{:x}", self.pos, self.seh);
            }
            return Some(self.seh);
        }

        let addr:u64 = self.memory_operand_to_address(operand);

        if operand.contains("fs:[") || operand.contains("gs:[") {
            return Some(addr);
        }

        let bits = self.get_size(operand);
        // check integrity of eip, esp and ebp registers


        let stack = self.maps.get_mem("stack");

        // could be normal using part of code as stack
        if !stack.inside(self.regs.get_esp()) {
            //hack: redirect stack
            self.regs.set_esp(stack.get_base() + 0x1ff);
            panic!("/!\\ fixing stack.")
        }

        match bits {
            64 => {
                match self.maps.read_qword(addr) {
                    Some(v) => {
                        if self.cfg.trace_mem {
                            let name = match self.maps.get_addr_name(addr) {
                                Some(n) => n,
                                None => "not mapped".to_string(),
                            };
                            println!("mem trace read -> '{}' 0x{:x}: 0x{:x}  map:'{}'", operand, addr, v, name);
                        }
                        return Some(v);
                    }
                    None => return None,
                }
            }
            32 => {
                match self.maps.read_dword(addr) {
                    Some(v) => {
                        if self.cfg.trace_mem {
                            let name = match self.maps.get_addr_name(addr) {
                                Some(n) => n,
                                None => "not mapped".to_string(),
                            };
                            println!("mem trace read -> '{}' 0x{:x}: 0x{:x}  map:'{}'", operand, addr, v, name);
                        }
                        return Some(v.into());
                    },
                    None => return None,
                }
            }
            16 => {
                match self.maps.read_word(addr) {
                    Some(v) => {
                        if self.cfg.trace_mem {
                            let name = match self.maps.get_addr_name(addr) {
                                Some(n) => n,
                                None => "not mapped".to_string(),
                            };
                            println!("mem trace read -> '{}' 0x{:x}: 0x{:x}  map:'{}'", operand, addr, v, name);
                        }
                        return Some(v.into());
                    },
                    None => return None,
                }
            },
            8 => {
                match self.maps.read_byte(addr) {
                    Some(v) => {
                        if self.cfg.trace_mem {
                            let name = match self.maps.get_addr_name(addr) {
                                Some(n) => n,
                                None => "not mapped".to_string(),
                            };
                            println!("mem trace read -> '{}' 0x{:x}: 0x{:x}  map:'{}'", operand, addr, v, name);
                        }
                        return Some(v.into());
                    },
                    None => return None,
                }
            },
            _ => panic!("weird size: {}", operand),
        };

    }

    // this is not used on the emulation
    pub fn memory_write(&mut self, operand:&str, value:u64) -> bool {
        if operand.contains("fs:[0]") {
            println!("Setting SEH fs:[0]  0x{:x}", value);
            self.seh = value;
            return true;
        }

        let addr:u64 = self.memory_operand_to_address(operand);

        /*if !self.maps.is_mapped(addr) {
          panic!("writting in non mapped memory");
          }*/

        let name = match self.maps.get_addr_name(addr) {
            Some(n) => n,
            None => "error".to_string(),
        };

        if name == "code" {
            if self.cfg.verbose >= 1 {
                println!("/!\\ polymorfic code");
            }
            self.force_break = true;
        }

        if self.cfg.trace_mem {
            println!("mem trace write -> '{}' 0x{:x}: 0x{:x}  map:'{}'", operand, addr, value, name);
        }

        let bits = self.get_size(operand);
        let ret = match bits {
            64 => self.maps.write_qword(addr, value),
            32 => self.maps.write_dword(addr, (value & 0xffffffff) as u32),
            16 => self.maps.write_word(addr, (value & 0x0000ffff) as u16),
            8 => self.maps.write_byte(addr, (value & 0x000000ff) as u8),
            _ => unreachable!("weird size: {}", operand)
        };

        ret
    }

    // this is not used on the emulation
    pub fn get_size(&self, operand:&str) -> u8 {
        if operand.contains("byte ptr") {
            return 8;
        } else if operand.contains("dword ptr") {
            return 32;
        } else if operand.contains("qword ptr") {
            return 64;
        } else if operand.contains("word ptr") {
            return 16;
        }

        let c:Vec<char> = operand.chars().collect();

        if operand.len() == 3 {
            if c[0] == 'e' {
                return 32;
            }

        } else if operand.len() == 2 {
            if c[1] == 'x' {
                return 16;
            }

            if c[1] == 'h' || c[1] == 'l' {
                return 8;
            }

            if c[1]  == 'i' {
                return 16;
            }
        }

        panic!("weird size: {}", operand);
    }

    pub fn set_rip(&mut self, addr:u64, is_branch:bool) {
        if addr == constants::RETURN_THREAD.into() {
            println!("/!\\ Thread returned, continuing the main thread");
            self.regs.rip = self.main_thread_cont;
            self.spawn_console();
            self.force_break = true;
            return;
        }

        let name = match self.maps.get_addr_name(addr) {
            Some(n) => n,
            None => {
                eprintln!("/!\\ setting rip to non mapped addr 0x{:x}", addr);
                self.exception();
                return;
            }
        };

        let map_name = self.filename_to_mapname(&self.cfg.filename);
        if addr < constants::LIBS_BARRIER64 || name == "code" || name.starts_with(&map_name) {
            self.regs.rip = addr;
        } else {
            if self.cfg.verbose >= 1 {
                println!("/!\\ changing RIP to {} ", name);
            }


            self.gateway_return = self.stack_pop64(false);
            self.regs.rip = self.gateway_return;

            winapi64::gateway(addr, name, self);
            self.force_break = true;
        }
    }

    pub fn set_eip(&mut self, addr:u64, is_branch:bool) {
        if addr == constants::RETURN_THREAD.into() {
            println!("/!\\ Thread returned, continuing the main thread");
            self.regs.rip = self.main_thread_cont;
            self.spawn_console();
            self.force_break = true;
            return;
        }

        let name = match self.maps.get_addr_name(addr) {
            Some(n) => n,
            None => { 
                eprintln!("/!\\ setting eip to non mapped addr 0x{:x}", addr);
                self.exception();
                return;
            }
        };

        let map_name = self.filename_to_mapname(&self.cfg.filename);
        if name == "code" || addr < constants::LIBS_BARRIER || name.starts_with(&map_name) {
            self.regs.set_eip(addr);
        } else {
            if self.cfg.verbose >= 1 {
                println!("/!\\ changing EIP to {} 0x{:x}", name, addr);
            }

            self.gateway_return = self.stack_pop32(false).into();
            self.regs.set_eip(self.gateway_return);

            winapi32::gateway(to32!(addr), name, self);
            self.force_break = true;
        }
    }


    fn rol(&self, val:u64, rot:u64, bits:u8) -> u64 {
        let mut ret:u64 = val;
        for _ in 0..rot {
            let last_bit = get_bit!(ret, bits-1);
            //println!("last bit: {}", last_bit);
            let mut ret2:u64 = ret;
            
            for j in 0..bits-1 {
                let bit = get_bit!(ret, j);
                set_bit!(ret2, j+1, bit);
            }
            
            set_bit!(ret2, 0, last_bit);
            ret = ret2;
            //println!("{:b}", ret);
        }
        
        ret
    }

    fn rcl(&self, val:u64, rot2:u64, bits:u8) -> u64 {
        let mut ret:u128 = val as u128;
        let rot = rot2 & 0b11111;
       
        if self.flags.f_cf {
            set_bit!(ret, bits, 1);
        } else {
            set_bit!(ret, bits, 0);
        }
        
        for _ in 0..rot {
            let last_bit = get_bit!(ret, bits);
            //println!("last bit: {}", last_bit);
            let mut ret2:u128 = ret;
            
            for j in 0..bits {
                let bit = get_bit!(ret, j);
                set_bit!(ret2, j+1, bit);
            }
            
            set_bit!(ret2, 0, last_bit);
            ret = ret2;
            //println!("{:b}", ret);
        }

        let a:u128 = 2;
        (ret & (a.pow(bits as u32)-1) ) as u64
    }

    fn ror(&self, val:u64, rot:u64, bits:u8) -> u64 {
        let mut ret:u64 = val;
        for _ in 0..rot {
            let first_bit = get_bit!(ret, 0);
            let mut ret2:u64 = ret;
            
            for j in (1..bits).rev() {
                let bit = get_bit!(ret, j);
                set_bit!(ret2, j-1, bit);
            }
            
            set_bit!(ret2, bits-1, first_bit);
            ret = ret2;
        }
        
        ret
    }

    fn rcr(&self, val:u64, rot2:u64, bits:u8) -> u64 {
        let mut ret:u128 = val as u128;
        let rot = rot2 & 0b11111;
        
        if self.flags.f_cf {
            set_bit!(ret, bits, 1);
        } else {
            set_bit!(ret, bits, 0);
        }
        
        for _ in 0..rot {
            let first_bit = get_bit!(ret, 0);
            let mut ret2:u128 = ret;
            
            for j in (1..=bits).rev() {
                let bit = get_bit!(ret, j);
                set_bit!(ret2, j-1, bit);
            }
            
            set_bit!(ret2, bits, first_bit);
            ret = ret2;
        }
        
        let a:u128 = 2;
        (ret & (a.pow(bits as u32)-1) ) as u64
    }

    fn mul64(&mut self, value0:u64) {
        let value1:u64 = self.regs.rax;
        let value2:u64 = value0;
        let res:u128 = value1 as u128 * value2 as u128;
        self.regs.rdx = ((res & 0xffffffffffffffff0000000000000000) >> 64) as u64;
        self.regs.rax = (res & 0xffffffffffffffff) as u64;
        self.flags.f_pf = (res & 0xff) % 2 == 0;
        self.flags.f_of = self.regs.rdx != 0;
        self.flags.f_cf = self.regs.rdx != 0;
    }

    fn mul32(&mut self, value0:u64) {
        let value1:u32 = to32!(self.regs.get_eax());
        let value2:u32 = value0 as u32;
        let res:u64 = value1 as u64 * value2 as u64;
        self.regs.set_edx( (res & 0xffffffff00000000) >> 32 );
        self.regs.set_eax( res & 0x00000000ffffffff );
        self.flags.f_pf = (res & 0xff) % 2 == 0;
        self.flags.f_of = self.regs.get_edx() != 0;
        self.flags.f_cf = self.regs.get_edx() != 0;
    }

    fn mul16(&mut self, value0:u64) {
        let value1:u32 = to32!(self.regs.get_ax());
        let value2:u32 = value0 as u32;
        let res:u32 = value1 * value2;
        self.regs.set_dx(((res & 0xffff0000) >> 16).into());
        self.regs.set_ax((res & 0xffff).into());
        self.flags.f_pf = (res & 0xff) % 2 == 0;
        self.flags.f_of = self.regs.get_dx() != 0;
        self.flags.f_cf = self.regs.get_dx() != 0;
    }

    fn mul8(&mut self, value0:u64) {
        let value1:u32 = self.regs.get_al() as u32;
        let value2:u32 = value0 as u32;
        let res:u32 = value1 * value2;
        self.regs.set_ax((res & 0xffff).into());
        self.flags.f_pf = (res & 0xff) % 2 == 0;
        self.flags.f_of = self.regs.get_ah() != 0;
        self.flags.f_cf = self.regs.get_ah() != 0;
    }

    fn imul64p1(&mut self, value0:u64) {
        let value1:i64 = self.regs.rax as i64;
        let value2:i64 = value0 as i64;
        let res:i128 = value1 as i128 * value2 as i128;
        let ures:u128 = res as u128;
        self.regs.rdx = ((ures & 0xffffffffffffffff0000000000000000) >> 64) as u64;
        self.regs.rax = (ures & 0xffffffffffffffff) as u64;
        self.flags.f_pf = (ures & 0xff) % 2 == 0;
        self.flags.f_of = self.regs.get_edx() != 0;
        self.flags.f_cf = self.regs.get_edx() != 0;
    }

    fn imul32p1(&mut self, value0:u64) {
        let value1:i32 = self.regs.get_eax() as i32;
        let value2:i32 = value0 as i32;
        let res:i64 = value1 as i64 * value2 as i64;
        let ures:u64 = res as u64;
        self.regs.set_edx((ures & 0xffffffff00000000) >> 32);
        self.regs.set_eax(ures & 0x00000000ffffffff);
        self.flags.f_pf = (ures & 0xff) % 2 == 0;
        self.flags.f_of = self.regs.get_edx() != 0;
        self.flags.f_cf = self.regs.get_edx() != 0;
    }

    fn imul16p1(&mut self, value0:u64) {
        let value1:i32 = self.regs.get_ax() as i32;
        let value2:i32 = value0 as i32;
        let res:i32 = value1 * value2;
        let ures:u32 = res as u32;
        self.regs.set_dx(((ures & 0xffff0000) >> 16).into());
        self.regs.set_ax((ures & 0xffff).into());
        self.flags.f_pf = (ures & 0xff) % 2 == 0;
        self.flags.f_of = self.regs.get_dx() != 0;
        self.flags.f_cf = self.regs.get_dx() != 0;
    }

    fn imul8p1(&mut self, value0:u64) {
        let value1:i32 = self.regs.get_al() as i32;
        let value2:i32 = value0 as i32;
        let res:i32 = value1 * value2;
        let ures:u32 = res as u32;
        self.regs.set_ax((ures & 0xffff).into());
        self.flags.f_pf = (ures & 0xff) % 2 == 0;
        self.flags.f_of = self.regs.get_ah() != 0;
        self.flags.f_cf = self.regs.get_ah() != 0;
    }

    fn div64(&mut self, value0:u64) {
        let mut value1:u128 = self.regs.rdx as u128;
        value1 <<= 64;
        value1 += self.regs.rax as u128;
        let value2:u128 = value0 as u128;

        if value2 == 0 {
            self.flags.f_tf = true;
            println!("/!\\ division by 0 exception");
            self.exception();
            self.force_break = true;
            return;
        }

        let resq:u128 = value1 / value2;
        let resr:u128 = value1 % value2;
        self.regs.rax = resq as u64;
        self.regs.rdx = resr as u64;
        self.flags.f_pf = (resq & 0xff) % 2 == 0;
        self.flags.f_of = resq > 0xffffffffffffffff;
        if self.flags.f_of {
            println!("/!\\ int overflow on division");
        }
    }

    fn div32(&mut self, value0:u64) {
        let mut value1:u64 = self.regs.get_edx();
        value1 <<= 32;
        value1 += self.regs.get_eax();
        let value2:u64 = value0;

        if value2 == 0 {
            self.flags.f_tf = true;
            println!("/!\\ division by 0 exception");
            self.exception();
            self.force_break = true;
            return;
        }

        let resq:u64 = value1 / value2;
        let resr:u64 = value1 % value2;
        self.regs.set_eax(resq);
        self.regs.set_edx(resr);
        self.flags.f_pf = (resq & 0xff) % 2 == 0;
        self.flags.f_of = resq > 0xffffffff;
        if self.flags.f_of {
            println!("/!\\ int overflow on division");
        }
    }

    fn div16(&mut self, value0:u64) {
        let value1:u32 = to32!((self.regs.get_dx() << 16) + self.regs.get_ax());
        let value2:u32 = value0 as u32;

        if value2 == 0 {
            self.flags.f_tf = true;
            println!("/!\\ division by 0 exception");
            self.exception();
            self.force_break = true;
            return;
        } 

        let resq:u32 = value1 / value2;
        let resr:u32 = value1 % value2;
        self.regs.set_ax(resq.into());
        self.regs.set_dx(resr.into());
        self.flags.f_pf = (resq & 0xff) % 2 == 0;
        self.flags.f_of = resq > 0xffff;
        self.flags.f_tf = false;
        if self.flags.f_of {
            println!("/!\\ int overflow on division");
        }
    }

    fn div8(&mut self, value0:u64) {
        let value1:u32 = self.regs.get_ax() as u32;
        let value2:u32 = value0 as u32;
        if value2 == 0 {
            self.flags.f_tf = true;
            println!("/!\\ division by 0 exception");
            self.exception();
            self.force_break = true;
            return;
        } 

        let resq:u32 = value1 / value2;
        let resr:u32 = value1 % value2;
        self.regs.set_al(resq.into());
        self.regs.set_ah(resr.into());
        self.flags.f_pf = (resq & 0xff) % 2 == 0;
        self.flags.f_of = resq > 0xff;
        self.flags.f_tf = false;
        if self.flags.f_of {
            println!("/!\\ int overflow");
        }
    }

    fn idiv64(&mut self, value0:u64) {
        let mut value1:u128 = self.regs.rdx as u128;
        value1 <<= 64;
        value1 += self.regs.rax as u128;
        let value2:u128 = value0 as u128;
        if value2 == 0 {
            self.flags.f_tf = true;
            println!("/!\\ division by 0 exception");
            self.exception();
            self.force_break = true;
            return;
        } 

        let resq:u128 = value1 / value2;
        let resr:u128 = value1 % value2;
        self.regs.rax = resq as u64;
        self.regs.rdx = resr as u64;
        self.flags.f_pf = (resq & 0xff) % 2 == 0;
        if resq > 0xffffffffffffffff {
            println!("/!\\ int overflow exception on division");
            if self.break_on_alert {
                panic!();
            }
        } else if ((value1 as i128) > 0 && (resq as i64) < 0) || ((value1 as i128) < 0 && (resq as i64) > 0) {
            println!("/!\\ sign change exception on division");
            self.exception();
            self.force_break = true;
        } 
    }

    fn idiv32(&mut self, value0:u64) {
        let mut value1:u64 = self.regs.get_edx();
        value1 <<= 32;
        value1 += self.regs.get_eax();
        let value2:u64 = value0;
        if value2 == 0 {
            self.flags.f_tf = true;
            println!("/!\\ division by 0 exception");
            self.exception();
            self.force_break = true;
            return;
        } 

        let resq:u64 = value1 / value2;
        let resr:u64 = value1 % value2;
        self.regs.set_eax(resq);
        self.regs.set_edx(resr);
        self.flags.f_pf = (resq & 0xff) % 2 == 0;
        if resq > 0xffffffff {
            println!("/!\\ int overflow exception on division");
            if self.break_on_alert {
                panic!();
            }
        } else if ((value1 as i64) > 0 && (resq as i32) < 0) || ((value1 as i64) < 0 && (resq as i32) > 0) {
            println!("/!\\ sign change exception on division");
            self.exception();
            self.force_break = true;
        } 
    }

    fn idiv16(&mut self, value0:u64) {
        let value1:u32 = to32!((self.regs.get_dx() << 16) + self.regs.get_ax());
        let value2:u32 = value0 as u32;
        if value2 == 0 {
            self.flags.f_tf = true;
            println!("/!\\ division by 0 exception");
            self.exception();
            self.force_break = true;
            return;
        }

        let resq:u32 = value1 / value2;
        let resr:u32 = value1 % value2;
        self.regs.set_ax(resq.into());
        self.regs.set_dx(resr.into());
        self.flags.f_pf = (resq & 0xff) % 2 == 0;
        self.flags.f_tf = false;
        if resq > 0xffff {
            println!("/!\\ int overflow exception on division");
            if self.break_on_alert {
                panic!();
            }
        } else if ((value1 as i32) > 0 && (resq as i16) < 0) || ((value1 as i32) < 0 && (resq as i16) > 0) {
            println!("/!\\ sign change exception on division");
            self.exception();
            self.force_break = true;
        }
    }

    fn idiv8(&mut self, value0:u64) {
        let value1:u32 = to32!(self.regs.get_ax());
        let value2:u32 = value0 as u32;
        if value2 == 0 {
            self.flags.f_tf = true;
            println!("/!\\ division by 0 exception");
            self.exception();
            self.force_break = true;
            return;
        } 

        let resq:u32 = value1 / value2;
        let resr:u32 = value1 % value2;
        self.regs.set_al(resq.into());
        self.regs.set_ah(resr.into());
        self.flags.f_pf = (resq & 0xff) % 2 == 0;
        self.flags.f_tf = false;
        if  resq > 0xff {
            println!("/!\\ int overflow exception on division");
            if self.break_on_alert {
                panic!();
            }
        } else if ((value1 as i16) > 0 && (resq as i8) < 0) || ((value1 as i16) < 0 && (resq as i8) > 0) {
            println!("/!\\ sign change exception on division");
            self.exception();
            self.force_break = true;
        }
    }

    pub fn shrd(&mut self, value0:u64, value1:u64, pcounter:u64, size:u8) -> u64 {
        let mut storage0:u64 = value0;
        let mut counter:u64 = pcounter;
        self.flags.f_cf = get_bit!(value0, counter - 1) == 1;

        if counter >= size as u64 {
            counter = pcounter - size as u64;
        }

        if counter == 0 {
            return storage0;
        }

        let mut to = size as u64 - 1 - counter;
        if to>64 {
            // println!("to: {}", to);
            to = 64;
        }

        for i in 0..=to {
            let bit = get_bit!(storage0, i as u32 + counter as u32);
            set_bit!(storage0, i as u32, bit);
        }

        let from = size as u64 - counter;

        //println!("from: {}", from);

        for i in from..size as u64 {
            let bit = get_bit!(value1, i as u32 + counter as u32 - size as u32);
            set_bit!(storage0, i as u32, bit);
        }

        self.flags.calc_flags(storage0, size);
        storage0
    }

    pub fn shld(&mut self, value0:u64, value1:u64, pcounter:u64, size:u8) -> u64 {
        let mut storage0:u64 = value0;
        let mut counter:u64 = pcounter;
    
        if counter < size as u64 && size - (counter as u8) < 64 {
            self.flags.f_cf = get_bit!(value0, size - counter as u8) == 1;
        }

        if pcounter >= size as u64 {
            counter = pcounter - size as u64;
        }

        if counter == 0 {
            return storage0;
        }

        for i in (counter..=((size as u64)-1)).rev() {
            let bit = get_bit!(storage0, i - counter);
            set_bit!(storage0, i, bit);
        }

        for i in (0..counter).rev() {
            let bit = get_bit!(value1, i + (size as u64) - counter);
            set_bit!(storage0, i, bit);
        }

        self.flags.calc_flags(storage0, size);

        storage0
    }

    pub fn spawn_console(&mut self) {
        let con = Console::new();
        loop {
            let cmd = con.cmd();
            match cmd.as_str() {
                "q" => std::process::exit(1),
                "h" => con.help(),
                "r" => {
                    if self.cfg.is_64bits {
                        self.featured_regs64();
                    } else {
                        self.featured_regs32();
                    }
                },
                "r rax" => self.regs.show_rax(&self.maps, 0),
                "r rbx" => self.regs.show_rbx(&self.maps, 0),
                "r rcx" => self.regs.show_rcx(&self.maps, 0),
                "r rdx" => self.regs.show_rdx(&self.maps, 0),
                "r rsi" => self.regs.show_rsi(&self.maps, 0),
                "r rdi" => self.regs.show_rdi(&self.maps, 0),
                "r rbp" => println!("\trbp: 0x{:x}", self.regs.rbp),
                "r rsp" => println!("\trsp: 0x{:x}", self.regs.rsp),
                "r rip" => println!("\trip: 0x{:x}", self.regs.rip),
                "r eax" => self.regs.show_eax(&self.maps, 0),
                "r ebx" => self.regs.show_ebx(&self.maps, 0),
                "r ecx" => self.regs.show_ecx(&self.maps, 0),
                "r edx" => self.regs.show_edx(&self.maps, 0),
                "r esi" => self.regs.show_esi(&self.maps, 0),
                "r edi" => self.regs.show_edi(&self.maps, 0),
                "r esp" => println!("\tesp: 0x{:x}", self.regs.get_esp() as u32),
                "r ebp" => println!("\tebp: 0x{:x}", self.regs.get_ebp() as u32),
                "r eip" => println!("\teip: 0x{:x}", self.regs.get_eip() as u32),
                "r r8" => self.regs.show_r8(&self.maps, 0),
                "r r9" => self.regs.show_r9(&self.maps, 0),
                "r r10" => self.regs.show_r10(&self.maps, 0),
                "r r11" => self.regs.show_r11(&self.maps, 0),
                "r r12" => self.regs.show_r12(&self.maps, 0),
                "r r13" => self.regs.show_r13(&self.maps, 0),
                "r r14" => self.regs.show_r14(&self.maps, 0),
                "r r15" => self.regs.show_r15(&self.maps, 0),
                "r r8d" => self.regs.show_r8d(&self.maps, 0),
                "r r9d" => self.regs.show_r9d(&self.maps, 0),
                "r r10d" => self.regs.show_r10d(&self.maps, 0),
                "r r11d" => self.regs.show_r11d(&self.maps, 0),
                "r r12d" => self.regs.show_r12d(&self.maps, 0),
                "r r13d" => self.regs.show_r13d(&self.maps, 0),
                "r r14d" => self.regs.show_r14d(&self.maps, 0),
                "r r15d" => self.regs.show_r15d(&self.maps, 0),
                "r r8w" => self.regs.show_r8w(&self.maps, 0),
                "r r9w" => self.regs.show_r9w(&self.maps, 0),
                "r r10w" => self.regs.show_r10w(&self.maps, 0),
                "r r11w" => self.regs.show_r11w(&self.maps, 0),
                "r r12w" => self.regs.show_r12w(&self.maps, 0),
                "r r13w" => self.regs.show_r13w(&self.maps, 0),
                "r r14w" => self.regs.show_r14w(&self.maps, 0),
                "r r15w" => self.regs.show_r15w(&self.maps, 0),
                "r r8l" => self.regs.show_r8l(&self.maps, 0),
                "r r9l" => self.regs.show_r9l(&self.maps, 0),
                "r r10l" => self.regs.show_r10l(&self.maps, 0),
                "r r11l" => self.regs.show_r11l(&self.maps, 0),
                "r r12l" => self.regs.show_r12l(&self.maps, 0),
                "r r13l" => self.regs.show_r13l(&self.maps, 0),
                "r r14l" => self.regs.show_r14l(&self.maps, 0),
                "r r15l" => self.regs.show_r15l(&self.maps, 0),
                "r xmm0" => println!("\txmm0: 0x{:x}", self.regs.xmm0),
                "r xmm1" => println!("\txmm1: 0x{:x}", self.regs.xmm1),
                "r xmm2" => println!("\txmm2: 0x{:x}", self.regs.xmm2),
                "r xmm3" => println!("\txmm3: 0x{:x}", self.regs.xmm3),
                "r xmm4" => println!("\txmm4: 0x{:x}", self.regs.xmm4),
                "r xmm5" => println!("\txmm5: 0x{:x}", self.regs.xmm5),
                "r xmm6" => println!("\txmm6: 0x{:x}", self.regs.xmm6),
                "r xmm7" => println!("\txmm7: 0x{:x}", self.regs.xmm7),
                "r xmm8" => println!("\txmm8: 0x{:x}", self.regs.xmm8),
                "r xmm9" => println!("\txmm9: 0x{:x}", self.regs.xmm9),
                "r xmm10" => println!("\txmm10: 0x{:x}", self.regs.xmm10),
                "r xmm11" => println!("\txmm11: 0x{:x}", self.regs.xmm11),
                "r xmm12" => println!("\txmm12: 0x{:x}", self.regs.xmm12),
                "r xmm13" => println!("\txmm13: 0x{:x}", self.regs.xmm13),
                "r xmm14" => println!("\txmm14: 0x{:x}", self.regs.xmm14),
                "r xmm15" => println!("\txmm15: 0x{:x}", self.regs.xmm15),

                "rc" => {
                    con.print("register name");
                    let reg = con.cmd();
                    con.print("value");
                    let value = match con.cmd_hex64() {
                        Ok(v) => v,
                        Err(_) => {
                            println!("bad hex value");
                            continue;
                        }
                    };
                    self.regs.set_by_name(reg.as_str(), value);
                },
                "mr"|"rm" => {
                    con.print("memory argument");
                    let operand = con.cmd();
                    let addr:u64 = self.memory_operand_to_address(operand.as_str());
                    let value = match self.memory_read(operand.as_str()) {
                        Some(v) => v,
                        None => {
                            println!("bad address.");
                            continue;
                        },
                    };
                    println!("0x{:x}: 0x{:x}", to32!(addr), value);
                },
                "mw"|"wm" => {
                    con.print("memory argument");
                    let operand = con.cmd();
                    con.print("value");
                    let value = match con.cmd_hex64() {
                        Ok(v) => v,
                        Err(_) => {
                            println!("bad hex value.");
                            continue;
                        }
                    };
                    if self.memory_write(operand.as_str(), value) {
                        println!("done.");
                    } else {
                        println!("cannot write there.");
                    }

                },
                "mwb" => {
                    con.print("addr");
                    let addr = match con.cmd_hex64() {
                        Ok(a) => a,
                        Err(_) => {
                            println!("bad hex value");
                            continue;
                        }
                    };
                    con.print("spaced bytes");
                    let bytes = con.cmd();
                    self.maps.write_spaced_bytes(addr, &bytes);
                    println!("done.");
                },
                "b" => {
                    self.bp.show();
                }
                "ba" => {
                    con.print("address");
                    let addr = match con.cmd_hex64() {
                        Ok(v) => v,
                        Err(_) => {
                            println!("bad hex value.");
                            continue;
                        }
                    };
                    self.bp.set_bp(addr);
                },
                "bmr" => {
                    con.print("address");
                    let addr = match con.cmd_hex64() {
                        Ok(v) => v,
                        Err(_) => {
                            println!("bad hex value.");
                            continue;
                        }
                    };
                    self.bp.set_mem_read(addr);
                },
                "bmw" => {
                    con.print("address");
                    let addr = match con.cmd_hex64() {
                        Ok(v) => v,
                        Err(_) => {
                            println!("bad hex value.");
                            continue;
                        }
                    };
                    self.bp.set_mem_write(addr);
                },
                "bi" => {
                    con.print("instruction number");
                    let num = match con.cmd_num() {
                        Ok(v) => v,
                        Err(_) => {
                            println!("bad hex value.");
                            continue;
                        }
                    };
                    self.bp.set_instruction(num);
                    self.exp = num;
                },
                "bc" => {
                    self.bp.clear_bp();
                    self.exp = self.pos+1;
                },
                "bcmp" => {
                    self.break_on_next_cmp = true;
                },
                "cls" => println!("{}", self.colors.clear_screen),
                "s" => {
                    if self.cfg.is_64bits {
                        self.maps.dump_qwords(self.regs.rsp, 10);
                    } else {
                        self.maps.dump_dwords(self.regs.get_esp(), 10);
                    }
                }
                "v" => {
                    if self.cfg.is_64bits {
                        self.maps.dump_qwords(self.regs.rbp-0x100, 100);
                    } else {
                        self.maps.dump_dwords(self.regs.get_ebp()-0x100, 100);
                    }
                    self.maps.get_mem("stack").print_dwords_from_to(self.regs.get_ebp(), self.regs.get_ebp()+0x100);
                }
                "sv" => {
                    con.print("verbose level");
                    self.cfg.verbose = match con.cmd_num() {
                        Ok(v) => to32!(v),
                        Err(_) => {
                            println!("incorrect verbose level, set 0, 1 or 2");
                            continue;
                        }
                    };
                }
                "tr" => {
                    con.print("register");
                    let reg = con.cmd();
                    self.cfg.trace_reg = true;
                    self.cfg.reg_names.push(reg);
                }
                "trd" => {
                    self.cfg.trace_reg = false;
                    self.cfg.reg_names.clear();
                }
                "c" => {
                    self.is_running.store(1, atomic::Ordering::Relaxed);
                    return;
                },
                "cr" => {
                    self.break_on_next_return = true;
                    self.is_running.store(1, atomic::Ordering::Relaxed);
                    return;
                }
                "f" => self.flags.print(),
                "fc" => self.flags.clear(),
                "fz" => self.flags.f_zf = !self.flags.f_zf,
                "fs" => self.flags.f_sf = !self.flags.f_sf,
                "mc" => {
                    con.print("name ");
                    let name = con.cmd();
                    con.print("size ");
                    let sz = match con.cmd_num() {
                        Ok(v) => v,
                        Err(_) => {
                            println!("bad size.");
                            continue;
                        }
                    };

                    let addr = match self.maps.alloc(sz) {
                        Some(a) => a,
                        None => {
                            println!("memory full");
                            continue;
                        }
                    };
                    let map = self.maps.create_map(&name);
                    map.set_base(addr);
                    map.set_size(sz);
                    println!("allocated {} at 0x{:x} sz: {}", name, addr, sz); 
                },
                "mca" => {
                    con.print("name ");
                    let name = con.cmd();
                    con.print("address ");
                    let addr = match con.cmd_hex64() {
                        Ok(v) => v,
                        Err(_) => {
                            println!("bad size.");
                            continue;
                        }
                    };

                    con.print("size ");
                    let sz = match con.cmd_num() {
                        Ok(v) => v,
                        Err(_) => {
                            println!("bad size.");
                            continue;
                        }
                    };

                    let map = self.maps.create_map(&name);
                    map.set_base(addr);
                    map.set_size(sz);
                    println!("allocated {} at 0x{:x} sz: {}", name, addr, sz); 
                },
                "ml" => {
                    con.print("map name");
                    let name = con.cmd();
                    con.print("filename");
                    let filename = con.cmd();
                    self.maps.get_mem(name.as_str()).load(filename.as_str());
                },
                "mn" => {
                    con.print("address");
                    let addr = match con.cmd_hex64() {
                        Ok(v) => v,
                        Err(_) => {
                            println!("bad hex value.");
                            continue;
                        }
                    };
                    let name = match self.maps.get_addr_name(addr) {
                        Some(n) => n,
                        None => {
                            println!("address not found on any map");
                            continue;
                        }
                    };

                    let mem = self.maps.get_mem(name.as_str());
                    if self.cfg.is_64bits { 
                        println!("map: {} 0x{:x}-0x{:x} ({})", name, mem.get_base(), mem.get_bottom(), mem.size());
                    } else { 
                        println!("map: {} 0x{:x}-0x{:x} ({})", name, to32!(mem.get_base()), to32!(mem.get_bottom()), mem.size());
                    }

                },
                "ma" => {
                    self.maps.show_allocs();
                },
                "md" => {
                    con.print("address");
                    let addr = match con.cmd_hex64() {
                        Ok(v) => v,
                        Err(_) => {
                            println!("bad hex value.");
                            continue;
                        }
                    };
                    self.maps.dump(addr);
                },
                "mrd" => {
                    con.print("address");
                    let addr = match con.cmd_hex64() {
                        Ok(v) => v,
                        Err(_) => {
                            println!("bad hex value.");
                            continue;
                        }
                    };
                    self.maps.dump_dwords(addr, 10);
                },
                "mrq" => {
                    con.print("address");
                    let addr = match con.cmd_hex64() {
                        Ok(v) => v,
                        Err(_) => {
                            println!("bad hex value.");
                            continue;
                        }
                    };
                    self.maps.dump_qwords(addr, 10);
                },
                "mds" => {
                    con.print("address");
                    let addr = match con.cmd_hex64() {
                        Ok(v) => v,
                        Err(_) => {
                            println!("bad hex value.");
                            continue;
                        }
                    };
                    if self.cfg.is_64bits {
                        println!("0x{:x}: '{}'", addr, self.maps.read_string(addr));
                    } else {
                        println!("0x{:x}: '{}'", to32!(addr), self.maps.read_string(addr));
                    }
                },
                "mdw" => {
                    con.print("address");
                    let addr = match con.cmd_hex64() {
                        Ok(v) => v,
                        Err(_) => {
                            println!("bad hex value.");
                            continue;
                        }
                    };
                    if self.cfg.is_64bits {
                        println!("0x{:x}: '{}'", addr, self.maps.read_wide_string(addr));
                    } else {
                        println!("0x{:x}: '{}'", to32!(addr), self.maps.read_wide_string(addr));
                    }
                },
                "mdd" => {
                    con.print("address");
                    let addr = match con.cmd_hex64() {
                        Ok(v) => v,
                        Err(_) => {
                            println!("bad hex value.");
                            continue;
                        }
                    };
                    con.print("size");
                    let sz = match con.cmd_num() {
                        Ok(v) => v,
                        Err(_) => {
                            println!("bad numeric decimal value.");
                            continue;
                        }
                    };
                    if sz > 0 {
                        con.print("file");
                        let filename = con.cmd();
                        self.maps.save(addr, sz, filename);
                    }
                }
                "mdda" => {
                    con.print("path:");
                    let path = con.cmd2();
                    self.maps.save_all_allocs(path);
                }
                "mt" => {
                    if self.maps.mem_test() {
                        println!("mem test passed ok.");
                    } else {
                        println!("memory errors.");
                    }
                }
                "eip" => {
                    con.print("=");
                    let addr = match con.cmd_hex64() {
                        Ok(v) => v,
                        Err(_) => {
                            println!("bad hex value");
                            continue;
                        }
                    };
                    self.force_break = true;
                    self.regs.set_eip(addr);
                },
                "rip" => {
                    con.print("=");
                    let addr = match con.cmd_hex64() {
                        Ok(v) => v,
                        Err(_) => {
                            println!("bad hex value");
                            continue;
                        }
                    };
                    self.force_break = true;
                    self.regs.rip = addr;
                },
                "push" => {
                    con.print("value");
                    if self.cfg.is_64bits {
                        let value = match con.cmd_hex64() {
                            Ok(v) => v,
                            Err(_) => {
                                println!("bad hex value");
                                continue;
                            }
                        };
                        self.stack_push64(value);
                    } else {
                        let value = match con.cmd_hex32() {
                            Ok(v) => v,
                            Err(_) => {
                                println!("bad hex value");
                                continue;
                            }
                        };
                        self.stack_push32(value);
                    }
                    println!("pushed.");
                },
                "pop" => {
                    if self.cfg.is_64bits {
                        let value = self.stack_pop64(false);
                        println!("poped value 0x{:x}", value);
                    } else {
                        let value = self.stack_pop32(false);
                        println!("poped value 0x{:x}", value);
                    }
                },
                "fpu" => {
                    self.fpu.print();
                },
                "md5" => {
                    con.print("map name");
                    let mem_name = con.cmd();
                    let mem = self.maps.get_mem(&mem_name);
                    let md5 = mem.md5();
                    println!("md5sum: {:x}", md5);
                }
                "ss" => {
                    con.print("map name");
                    let mem_name = con.cmd();
                    con.print("string");
                    let kw = con.cmd2();
                    let result = match self.maps.search_string(&kw, &mem_name) {
                        Some(v) => v,
                        None => { 
                            println!("not found.");
                            continue;
                        }
                    };
                    for addr in result.iter() {
                        if self.cfg.is_64bits {
                            println!("found 0x{:x} '{}'", *addr, self.maps.read_string(*addr));
                        } else { 
                            println!("found 0x{:x} '{}'", *addr as u32, self.maps.read_string(*addr));
                        }
                    }
                },
                "sb" => {
                    con.print("map name");
                    let mem_name = con.cmd();
                    con.print("spaced bytes");
                    let sbs = con.cmd();
                    if !self.maps.search_spaced_bytes(&sbs, &mem_name) {
                        println!("not found.");
                    }
                },
                "sba" => {
                    con.print("spaced bytes");
                    let sbs = con.cmd();
                    let results = self.maps.search_space_bytes_in_all(&sbs);
                    if self.cfg.is_64bits {
                        for addr in results.iter() {
                            println!("found at 0x{:x}", addr);
                        }
                    } else {
                        for addr in results.iter() {
                            println!("found at 0x{:x}", to32!(addr));
                        }
                    }
                },
                "ssa" => {
                    con.print("string");
                    let kw = con.cmd2();
                    self.maps.search_string_in_all(kw);
                },
                "seh" => {
                    println!("0x{:x}", self.seh);
                },
                "veh" => {
                    println!("0x{:x}", self.veh);
                },
                "ll" => {
                    con.print("ptr");
                    let ptr1 = match con.cmd_hex64() {
                        Ok(v) => v,
                        Err(_) => {
                            println!("bad hex value");
                            continue;
                        }
                    };
                    let mut ptr = ptr1;
                    loop {
                        println!("- 0x{:x}", ptr);
                        ptr = match self.maps.read_dword(ptr) {
                            Some(v) => v.into(),
                            None => break,
                        };
                        if ptr == 0 || ptr == ptr1 {
                            break;
                        }
                    }
                },
                "n"|"" => {
                    self.exp = self.pos + 1;
                    return;
                },
                "m" => self.maps.print_maps(),
                "ms" => {
                    con.print("keyword");
                    let kw = con.cmd2();
                    self.maps.print_maps_keyword(&kw);
                }
                "d" => {
                    con.print("address");
                    let addr = match con.cmd_hex64() {
                        Ok(v) => v,
                        Err(_) => {
                            println!("bad hex value");
                            continue;
                        }
                    };
                    self.disassemble(addr, 10);
                },
                "ldr" => {
                    if self.cfg.is_64bits {
                        peb64::show_linked_modules(self);
                    } else {
                        peb32::show_linked_modules(self);
                    }
                }
                "iat" => {
                    con.print("api keyword");
                    let kw = con.cmd2();
                    let (addr, lib, name) = winapi32::kernel32::search_api_name(self, &kw);
                    if addr == 0 {
                        println!("api not found");
                    } else {
                        println!("found: 0x{:x} {}!{}", addr, lib, name);
                    }
                }
                "iatd" => {
                    con.print("module");
                    let lib = con.cmd2().to_lowercase();
                    winapi32::kernel32::dump_module_iat(self, &lib);
                }
                "dt" => {
                    con.print("structure");
                    let struc = con.cmd();
                    con.print("address");
                    let addr = match con.cmd_hex64() {
                        Ok(v) => v,
                        Err(_) => {
                            println!("bad hex value");
                            continue;
                        }
                    };

                    match struc.as_str() {
                        "peb" => {
                            let s = structures::PEB::load(addr, &self.maps);
                            s.print();
                        }
                        "teb" => {
                            let s = structures::TEB::load(addr, &self.maps);
                            s.print();
                        }
                        "peb_ldr_data" => {
                            let s = structures::PebLdrData::load(addr, &self.maps);
                            s.print();
                        }
                        "ldr_data_table_entry" => {
                            let s = structures::LdrDataTableEntry::load(addr, &self.maps);
                            s.print();
                        }
                        "list_entry" => {
                            let s = structures::ListEntry::load(addr, &self.maps);
                            s.print();
                        }
                        "cppeh_record" => {
                            let s = structures::CppEhRecord::load(addr, &self.maps);
                            s.print();
                        }
                        "exception_pointers" => {
                            let s = structures::ExceptionPointers::load(addr, &self.maps);
                            s.print();
                        }
                        "eh3_exception_registgration" => {
                            let s = structures::Eh3ExceptionRegistration::load(addr, &self.maps);
                            s.print();
                        }
                        "memory_basic_information" => {
                            let s = structures::MemoryBasicInformation::load(addr, &self.maps);
                            s.print();
                        }
                        "peb64" => {
                            let s = structures::PEB64::load(addr, &self.maps);
                            s.print();
                        }
                        "teb64" => {
                            let s = structures::TEB64::load(addr, &self.maps);
                            s.print();
                        }
                        "ldrdatatableentry64" => {
                            let s = structures::LdrDataTableEntry64::load(addr, &self.maps);
                            s.print();
                        }
                        "image_export_directory" => {
                            let s = structures::ImageExportDirectory::load(addr, &self.maps);
                            s.print();
                        }

                        _  => println!("unrecognized structure."),
                    }


                } // end dt command

                _ => println!("command not found, type h"),
            } // match commands
        } // end loop
    } // end commands function

    fn featured_regs32(&self) {
        self.regs.show_eax(&self.maps, 0);
        self.regs.show_ebx(&self.maps, 0);
        self.regs.show_ecx(&self.maps, 0);
        self.regs.show_edx(&self.maps, 0);
        self.regs.show_esi(&self.maps, 0);
        self.regs.show_edi(&self.maps, 0);
        println!("\tesp: 0x{:x}", self.regs.get_esp() as u32);
        println!("\tebp: 0x{:x}", self.regs.get_ebp() as u32);
        println!("\teip: 0x{:x}", self.regs.get_eip() as u32);
    }

    fn featured_regs64(&self) {
        self.regs.show_rax(&self.maps, 0);
        self.regs.show_rbx(&self.maps, 0);
        self.regs.show_rcx(&self.maps, 0);
        self.regs.show_rdx(&self.maps, 0);
        self.regs.show_rsi(&self.maps, 0);
        self.regs.show_rdi(&self.maps, 0);
        println!("\trsp: 0x{:x}", self.regs.rsp);
        println!("\trbp: 0x{:x}", self.regs.rbp);
        println!("\trip: 0x{:x}", self.regs.rip);
        self.regs.show_r8(&self.maps, 0);
        self.regs.show_r9(&self.maps, 0);
        self.regs.show_r10(&self.maps, 0);
        self.regs.show_r11(&self.maps, 0);
        self.regs.show_r12(&self.maps, 0);
        self.regs.show_r13(&self.maps, 0);
        self.regs.show_r14(&self.maps, 0);
        self.regs.show_r15(&self.maps, 0);

    }

    fn exception(&mut self) {
        let addr:u64;
        let next:u64;

        if self.veh > 0 {
            addr = self.veh;

            exception::enter(self);
            self.set_eip(addr, false);

        } else {

            if self.seh == 0 {
                println!("exception without any SEH handler nor vector configured.");
                self.spawn_console();
                return;
            }

            // SEH

            next = match self.maps.read_dword(self.seh) {
                Some(value) => value.into(),
                None => panic!("exception wihout correct SEH"),
            };

            addr = match self.maps.read_dword(self.seh + 4) {
                Some(value) => value.into(),
                None => panic!("exception without correct SEH."),
            };

            let con = Console::new();
            con.print("jump the exception pointer (y/n)?");
            let cmd = con.cmd();
            if cmd == "y" { 
                self.seh = next;
                exception::enter(self);
                self.set_eip(addr, false);
            }

        }
    }

    pub fn disassemble(&mut self, addr:u64, amount:u32) {
        let map_name = self.maps.get_addr_name(addr).expect("address not mapped");
        let code = self.maps.get_mem(map_name.as_str());
        let block = code.read_from(addr);
        let bits:u32;
        if self.cfg.is_64bits { bits = 64 } else { bits = 32 }
        let mut decoder = Decoder::with_ip(bits, block, addr, DecoderOptions::NONE);
        let mut formatter = IntelFormatter::new();
        formatter.options_mut().set_digit_separator("");
        formatter.options_mut().set_first_operand_char_index(6);
        let mut output = String::new();
        let mut instruction = Instruction::default();
        let mut count:u32 = 1;
        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);
            output.clear();
            formatter.format(&instruction, &mut output);
            if self.cfg.is_64bits {
                println!("0x{:x}: {}", instruction.ip(), output);
            } else {
                println!("0x{:x}: {}", instruction.ip32(), output);
            }
            count += 1;
            if count == amount {
                break;
            }
        }
    }

    pub fn get_operand_value(&mut self, ins:&Instruction, noperand:u32, do_derref:bool) -> Option<u64> {

        assert!(ins.op_count() > noperand);

        let value:u64 = match ins.op_kind(noperand) {
            OpKind::NearBranch64 => ins.near_branch64(),
            OpKind::NearBranch32 => ins.near_branch32().into(),
            OpKind::NearBranch16 => ins.near_branch16().into(),
            OpKind::FarBranch32 => ins.far_branch32().into(),
            OpKind::FarBranch16 => ins.far_branch16().into(),
            OpKind::Immediate64 => ins.immediate64(),
            OpKind::Immediate8 => ins.immediate8().into(),
            OpKind::Immediate16 => ins.immediate16().into(),
            OpKind::Immediate32 => ins.immediate32() as u32 as u64,
            OpKind::Immediate8to64 => ins.immediate8to64() as u64,
            OpKind::Immediate32to64 => ins.immediate32to64() as u64,
            OpKind::Immediate8to32 => ins.immediate8to32() as u32 as u64,
            OpKind::Immediate8to16 => ins.immediate8to16() as u16 as u64,
            OpKind::Register => self.regs.get_reg(ins.op_register(noperand)),
            OpKind::Memory => {
                let mut derref = do_derref;
                let mut fs = false;
                let mut gs = false;


                let mut mem_addr = ins.virtual_address(noperand, 0, |reg,idx,_sz| {
                    if reg == Register::FS {
                        derref = false;
                        fs = true;

                        Some(0)
                    } else if reg == Register::GS {
                        derref = false;
                        gs = true;

                        Some(0)
                    } else {
                        Some(self.regs.get_reg(reg))
                    }
                }).expect("error reading memory");

                if fs {
                    let value:u64 = match mem_addr {
                        0x30 => {
                            let peb = self.maps.get_mem("peb");
                            if self.cfg.verbose >= 1 {
                                println!("{} Reading PEB 0x{:x}", self.pos, peb.get_base());
                            }
                            peb.get_base()
                        }
                        0x20 => {
                            if self.cfg.verbose >= 1 {
                                println!("{} Reading PID 0x{:x}", self.pos, 10);
                            }
                            10
                        }
                        0x24 => {
                            if self.cfg.verbose >= 1 {
                                println!("{} Reading TID 0x{:x}", self.pos, 101);
                            }
                            101
                        }
                        0x34 => {
                            if self.cfg.verbose >= 1 {
                                println!("{} Reading last error value 0", self.pos);
                            }
                            0
                        }
                        0x18 => {
                            let teb = self.maps.get_mem("teb");
                            if self.cfg.verbose >= 1 {
                                println!("{} Reading TEB 0x{:x}", self.pos, teb.get_base());
                            }
                            teb.get_base()
                        }
                        0x00 =>  {
                            if self.cfg.verbose >= 1 {
                                println!("Reading SEH 0x{:x}", self.seh);
                            }
                            self.seh
                        }
                        _ => unimplemented!("fs:[{}]", mem_addr),
                    };
                    mem_addr = value;
                }
                if gs {
                    let value:u64 = match mem_addr {
                        0x60 => {
                            let peb = self.maps.get_mem("peb");
                            if self.cfg.verbose >= 1 {
                                println!("{} Reading PEB 0x{:x}", self.pos, peb.get_base());
                            }
                            peb.get_base()
                        }
                        0x30 => {
                            let teb = self.maps.get_mem("teb");
                            if self.cfg.verbose >= 1 {
                                println!("{} Reading TEB 0x{:x}", self.pos, teb.get_base());
                            }
                            teb.get_base()
                        }
                        0x40 => {
                            if self.cfg.verbose >= 1 {
                                println!("{} Reading PID 0x{:x}", self.pos, 10);
                            }
                            10
                        }
                        0x48 => {
                            if self.cfg.verbose >= 1 {
                                println!("{} Reading TID 0x{:x}", self.pos, 101);
                            }
                            101
                        }
                        0x14 => {
                            unimplemented!("GS:[14]  get stack canary")
                        }
                        _ => unimplemented!("gs:[{}]", mem_addr),
                    };
                    mem_addr = value;
                }

                let value:u64;
                if derref {

                    let sz = self.get_operand_sz(ins, noperand);

                    value = match sz {

                        64 => match self.maps.read_qword(mem_addr) {
                            Some(v) => v,
                            None => { 
                                println!("/!\\ error dereferencing qword on 0x{:x}", mem_addr);
                                self.exception(); 
                                return None; 
                            }
                        }

                        32 => match self.maps.read_dword(mem_addr) {
                            Some(v) => v.into(),
                            None =>  { 
                                println!("/!\\ error dereferencing dword on 0x{:x}", mem_addr);
                                self.exception(); 
                                return None; 
                            }
                        }

                        16 => match self.maps.read_word(mem_addr) {
                            Some(v) => v.into(),
                            None =>  { 
                                println!("/!\\ error dereferencing word on 0x{:x}", mem_addr);
                                self.exception(); 
                                return None; 
                            }
                        }

                        8 => match self.maps.read_byte(mem_addr) {
                            Some(v) => v.into(),
                            None =>  { 
                                println!("/!\\ error dereferencing byte on 0x{:x}", mem_addr);
                                self.exception(); 
                                return None; 
                            }
                        }

                        _ => unimplemented!("weird size")
                    };

                    if self.cfg.trace_mem {
                        let name = match self.maps.get_addr_name(mem_addr) {
                            Some(n) => n,
                            None => "not mapped".to_string(),
                        };
                        println!("{} mem trace read {} bits ->  0x{:x}: 0x{:x}  map:'{}'", self.pos, sz, mem_addr, value, name);
                    }

                    if mem_addr == self.bp.get_mem_read() {
                        println!("Memory breakpoint on read 0x{:x}", mem_addr);
                        self.spawn_console();
                    }

                } else {
                    value = mem_addr;
                }
                value
            }

            _ => unimplemented!("unimplemented operand type {:?}", ins.op_kind(noperand)),
        };
        Some(value)
    }

    pub fn set_operand_value(&mut self, ins:&Instruction, noperand:u32, value:u64) -> bool {

        assert!(ins.op_count() > noperand);

        match ins.op_kind(noperand) {
            OpKind::Register => self.regs.set_reg(ins.op_register(noperand), value), 
            OpKind::Memory => {
                let mut write = true;
                let mem_addr = ins.virtual_address(noperand, 0, |reg,idx,_sz| {
                    if reg == Register::FS || reg == Register::GS {
                        write = false;
                        if idx == 0 {
                            if self.cfg.verbose >= 1 {
                                println!("seting SEH to 0x{:x}", value);
                            }
                            self.seh = value;
                        } else {
                            unimplemented!("set FS:[{}]", idx);
                        }
                        Some(0)

                    } else {
                        Some(self.regs.get_reg(reg) as u64)
                    }
                }).unwrap();

                if write {
                    let sz = self.get_operand_sz(ins, noperand);

                    match sz {
                        64 => {
                            if !self.maps.write_qword(mem_addr, value) {
                                println!("/!\\ exception dereferencing bad address. 0x{:x}", mem_addr);
                                self.exception();
                                return false;
                            }
                        }
                        32 => {
                            if !self.maps.write_dword(mem_addr, to32!(value)) {
                                println!("/!\\ exception dereferencing bad address. 0x{:x}", mem_addr);
                                self.exception();
                                return false;
                            }
                        }
                        16  => {
                            if !self.maps.write_word(mem_addr, value as u16) {
                                println!("/!\\ exception dereferencing bad address. 0x{:x}", mem_addr);
                                self.exception();
                                return false;
                            }
                        }
                        8  => {
                            if !self.maps.write_byte(mem_addr, value as u8) {
                                println!("/!\\ exception dereferencing bad address. 0x{:x}", mem_addr);
                                self.exception();
                                return false;
                            }
                        }
                        _  => unimplemented!("weird size"),
                    }

                    if self.cfg.trace_mem {
                        let name = match self.maps.get_addr_name(mem_addr) {
                            Some(n) => n,
                            None => "not mapped".to_string(),
                        };
                        println!("{} mem trace write {} bits ->  0x{:x}: 0x{:x}  map:'{}'", self.pos, sz, mem_addr, value, name);
                    }

                    let name = match self.maps.get_addr_name(mem_addr) {
                        Some(n) => n,
                        None => "not mapped".to_string(),
                    };

                    if name == "code" {
                        if self.cfg.verbose >= 1 {
                            println!("/!\\ polymorfic code");
                        }
                        self.force_break = true;
                    }

                    if mem_addr == self.bp.get_mem_write() {
                        println!("Memory breakpoint on write 0x{:x}", mem_addr);
                        self.spawn_console();
                    }
                }
            }

            _ => unimplemented!("unimplemented operand type"),
        };
        true
    }

    pub fn get_operand_xmm_value_128(&mut self, ins:&Instruction, noperand:u32, do_derref:bool) -> Option<u128> {

        assert!(ins.op_count() > noperand);

        let value:u128 = match ins.op_kind(noperand) {
            OpKind::Register => self.regs.get_xmm_reg(ins.op_register(noperand)),
            OpKind::Memory => {
                let mem_addr = match ins.virtual_address(noperand, 0, |reg,idx,_sz| {
                    Some(self.regs.get_reg(reg) as u64)
                }) {
                    Some(addr) => addr,
                    None => {
                        println!("/!\\ xmm exception reading operand");
                        self.exception();
                        return None
                    }
                };

                if do_derref {
                    let value:u128 = match self.maps.read_128bits_le(mem_addr) {
                        Some(v) => v,
                        None => { 
                            println!("/!\\ exception reading xmm operand at 0x{:x} ", mem_addr);
                            self.exception(); 
                            return None
                        }
                    };
                    value
                } else {
                    mem_addr as u128
                }
            }
            _ => unimplemented!("unimplemented operand type {:?}", ins.op_kind(noperand)),
        };
        Some(value)
    }

    pub fn set_operand_xmm_value_128(&mut self, ins:&Instruction, noperand:u32, value:u128) {

        assert!(ins.op_count() > noperand);

        match ins.op_kind(noperand) {
            OpKind::Register => self.regs.set_xmm_reg(ins.op_register(noperand), value),
            OpKind::Memory => {
                let mem_addr = match ins.virtual_address(noperand, 0, |reg,idx,_sz| {
                    Some(self.regs.get_reg(reg) as u64)
                }) {
                    Some(addr) => addr,
                    None => {
                        println!("/!\\ exception setting xmm operand.");
                        self.exception();
                        return;
                    }
                };

                for (i,b) in value.to_le_bytes().iter().enumerate() {
                    self.maps.write_byte(mem_addr + i as u64, *b);
                }

            }
            _ => unimplemented!("unimplemented operand type {:?}", ins.op_kind(noperand)),
        };
    }

    fn get_operand_sz(&self, ins:&Instruction, noperand:u32) -> u8 {
        let reg:Register = ins.op_register(noperand);
        if reg.is_xmm() {
            return 128;
        }

        let size:u8 = match ins.op_kind(noperand) {
            OpKind::NearBranch64 => 64,
            OpKind::NearBranch32 => 32,
            OpKind::NearBranch16 => 16,
            OpKind::FarBranch32 => 32,
            OpKind::FarBranch16 => 16,
            OpKind::Immediate8 => 8,
            OpKind::Immediate16 => 16,
            OpKind::Immediate32 => 32,
            OpKind::Immediate64 => 64,
            OpKind::Immediate8to32 => 32,
            OpKind::Immediate8to16 => 16,
            OpKind::Immediate32to64 => 64,
            OpKind::Immediate8to64 => 64,   //TODO: this could be 8
            OpKind::Register => self.regs.get_size(ins.op_register(noperand)),
            OpKind::Memory => {                
                let mut info_factory = InstructionInfoFactory::new();
                let info = info_factory.info(ins);
                let mem = info.used_memory()[0];

                let size2:u8 = match mem.memory_size() {
                    MemorySize::Float16 => 16,
                    MemorySize::Float32 => 32,
                    MemorySize::Float64 => 64,
                    MemorySize::FpuEnv28 => 32,
                    MemorySize::UInt64 => 64,
                    MemorySize::UInt32 => 32,
                    MemorySize::UInt16 => 16,
                    MemorySize::UInt8 => 8,
                    MemorySize::Int64 => 64,
                    MemorySize::Int32 => 32,
                    MemorySize::Int16 => 16,
                    MemorySize::Int8 => 8,
                    MemorySize::QwordOffset => 64,
                    MemorySize::DwordOffset => 32,
                    MemorySize::WordOffset => 16,
                    MemorySize::Packed128_UInt64 => 64, // 128bits packed in 2 qwords
                    MemorySize::Packed128_UInt32 => 32, // 128bits packed in 4 dwords
                    MemorySize::Packed128_UInt16 => 16, // 128bits packed in 8 words
                    _  => unimplemented!("memory size {:?}", mem.memory_size()),
                };

                size2
            }
            _  => unimplemented!("operand type {:?}", ins.op_kind(noperand)),
        };

        size
    }

    pub fn show_instruction(&self, color:&str, ins:&Instruction) {
        if !self.step {
            println!("{}{} 0x{:x}: {}{}", color, self.pos, ins.ip(), self.out, self.colors.nc);
        }
    }

    pub fn show_instruction_ret(&self, color:&str, ins:&Instruction, addr: u64) {
        if !self.step {
            println!("{}{} 0x{:x}: {} ; ret-addr: 0x{:x} ret-value: 0x{:x} {}", color, self.pos, ins.ip(), self.out, addr, self.regs.rax, self.colors.nc);
        }
    }

    pub fn show_instruction_pushpop(&self, color:&str, ins:&Instruction, value:u64) {
        if !self.step {
            println!("{}{} 0x{:x}: {} ;0x{:x} {}", color, self.pos, ins.ip(), self.out, value, self.colors.nc);
        }
    }


    pub fn show_instruction_taken(&self, color:&str, ins:&Instruction) {
        if !self.step {
            println!("{}{} 0x{:x}: {} taken {}", color, self.pos, ins.ip(), self.out, self.colors.nc);
        }
    }

    pub fn show_instruction_not_taken(&self, color:&str, ins:&Instruction) {
        if !self.step { // optimization: show always ins.ip()
            println!("{}{} 0x{:x}: {} not taken {}", color, self.pos, ins.ip(), self.out, self.colors.nc);
        }
    }

    pub fn stop(&mut self) {
        self.is_running.store(0, atomic::Ordering::Relaxed);
    }

    pub fn run_until_ret(&mut self) {
        self.run_until_ret = true;
        self.run(0);
    }

    ///  RUN ENGINE ///

    pub fn run(&mut self, end_addr:u64) {     
        self.is_running.store(1, atomic::Ordering::Relaxed);
        let is_running2 = Arc::clone(&self.is_running);

        if self.enabled_ctrlc {
            ctrlc::set_handler(move || {
                println!("Ctrl-C detected, spawning console");
                is_running2.store(0, atomic::Ordering::Relaxed);
            }).expect("ctrl-c handler failed");
        }


        let mut looped:Vec<u64> = Vec::new();
        let mut prev_addr:u64 = 0;
        let mut repeat_counter:u32 = 0;
    
        if end_addr == 0 {
            println!(" ----- emulation -----");
        }
        
        //let ins = Instruction::default();
        let mut formatter = IntelFormatter::new();
        formatter.options_mut().set_digit_separator("");
        formatter.options_mut().set_first_operand_char_index(6);

        self.pos = 0;

        loop {
        while self.is_running.load(atomic::Ordering::Relaxed) == 1 {
            let code = match self.maps.get_mem_by_addr(self.regs.rip) {
                Some(c) => c,
                None => {
                    println!("redirecting code flow to non maped address 0x{:x}", self.regs.rip);
                    self.spawn_console();
                    return;
                }
            };
            let block = code.read_from(self.regs.rip).to_vec();
            let mut decoder; 

            if self.cfg.is_64bits {
                decoder = Decoder::with_ip(64,  &block, self.regs.rip, DecoderOptions::NONE);
            } else {
                decoder = Decoder::with_ip(32,  &block, self.regs.get_eip(), DecoderOptions::NONE);
            }

            for ins in decoder.iter() {

                let sz = ins.len();
                let addr = ins.ip();

                if end_addr > 0 && addr == end_addr {
                    return;
                }

                self.step = false;
                self.out.clear();
                formatter.format(&ins, &mut self.out);

                self.pos += 1;

                if self.exp == self.pos || self.bp.get_bp() == addr || (self.cfg.console2 && self.cfg.console_addr == addr) {
                    self.cfg.console2 = false;
                    self.step = true;
                    println!("-------");
                    println!("{} 0x{:x}: {}", self.pos, ins.ip(), self.out);
                    self.spawn_console();
                    if self.force_break {
                        self.force_break = false;
                        break;
                    }
                }

                // prevent infinite loop
                if addr == prev_addr {
                    repeat_counter += 1;
                }
                prev_addr = addr;
                if repeat_counter == 100 {
                    println!("infinite loop!  opcode: {}", ins.op_code().op_code_string());
                    return;
                }


                if self.cfg.loops {
                    // loop detector
                    looped.push(addr);
                    let mut count:u32 = 0;
                    for a in looped.iter() {
                        if addr == *a {
                            count += 1;
                        }
                    }
                    if count > 2 {
                        println!("    loop: {} interations", count);
                    }
                    /*
                       if count > self.loop_limit {
                       panic!("/!\\ iteration limit reached");
                       }*/
                    //TODO: if more than x addresses remove the bottom ones
                }

                if self.cfg.trace_regs {
                    if self.cfg.is_64bits {
                        println!("\trax: 0x{:x} rbx: 0x{:x} rcx: 0x{:x} rdx: 0x{:x} rsi: 0x{:x} rdi: 0x{:x} rbp: 0x{:x}", 
                            self.regs.rax, self.regs.rbx, self.regs.rcx, 
                            self.regs.rdx, self.regs.rsi, self.regs.rdi, self.regs.rbp);
                    } else {
                        println!("\teax: 0x{:x} ebx: 0x{:x} ecx: 0x{:x} edx: 0x{:x} esi: 0x{:x} edi: 0x{:x} ebp: 0x{:x}", 
                            self.regs.get_eax() as u32, self.regs.get_ebx() as u32, self.regs.get_ecx() as u32, 
                            self.regs.get_edx() as u32, self.regs.get_esi() as u32, self.regs.get_edi() as u32, self.regs.get_ebp() as u32);
                    }
                }

                if self.cfg.trace_reg {
                    for reg in self.cfg.reg_names.iter() {
                        match reg.as_str() {
                            "rax" => self.regs.show_rax(&self.maps, self.pos),
                            "rbx" => self.regs.show_rbx(&self.maps, self.pos),
                            "rcx" => self.regs.show_rcx(&self.maps, self.pos),
                            "rdx" => self.regs.show_rdx(&self.maps, self.pos),
                            "rsi" => self.regs.show_rsi(&self.maps, self.pos),
                            "rdi" => self.regs.show_rdi(&self.maps, self.pos),
                            "rbp" => println!("\t{} rbp: 0x{:x}", self.pos, self.regs.rbp),
                            "rsp" => println!("\t{} rsp: 0x{:x}", self.pos, self.regs.rsp),
                            "rip" => println!("\t{} rip: 0x{:x}", self.pos, self.regs.rip),
                            "r8" => self.regs.show_r8(&self.maps, self.pos),
                            "r9" => self.regs.show_r9(&self.maps, self.pos),
                            "r10" => self.regs.show_r10(&self.maps, self.pos),
                            "r10d" => self.regs.show_r10d(&self.maps, self.pos),
                            "r11" => self.regs.show_r11(&self.maps, self.pos),
                            "r11d" => self.regs.show_r11d(&self.maps, self.pos),
                            "r12" => self.regs.show_r12(&self.maps, self.pos),
                            "r13" => self.regs.show_r13(&self.maps, self.pos),
                            "r14" => self.regs.show_r14(&self.maps, self.pos),
                            "r15" => self.regs.show_r15(&self.maps, self.pos),
                            "eax" => self.regs.show_eax(&self.maps, self.pos),
                            "ebx" => self.regs.show_ebx(&self.maps, self.pos),
                            "ecx" => self.regs.show_ecx(&self.maps, self.pos),
                            "edx" => self.regs.show_edx(&self.maps, self.pos),
                            "esi" => self.regs.show_esi(&self.maps, self.pos),
                            "edi" => self.regs.show_edi(&self.maps, self.pos),
                            "esp" => println!("\t{} esp: 0x{:x}", self.pos, self.regs.get_esp() as u32),
                            "ebp" => println!("\t{} ebp: 0x{:x}", self.pos, self.regs.get_ebp() as u32),
                            "eip" => println!("\t{} eip: 0x{:x}", self.pos, self.regs.get_eip() as u32),
                            _ => panic!("invalid register."),
                        }
                    }
                }

                if self.cfg.verbose < 2 {
                    self.step = true;
                }

                if self.cfg.trace_string {
                    let s = self.maps.read_string(self.cfg.string_addr);

                    if s.len() >= 2 && s.len() < 80 {
                        println!("\ttrace string -> 0x{:x}: '{}'", self.cfg.string_addr, s);
                    } else {
                        let w = self.maps.read_wide_string(self.cfg.string_addr);
                        if w.len() < 80 {
                            println!("\ttrace wide string -> 0x{:x}: '{}'", self.cfg.string_addr, w);
                        } else {
                            println!("\ttrace wide string -> 0x{:x}: ''", self.cfg.string_addr);
                        }
                    }
                }

                if self.cfg.inspect {
                    let addr:u64 = self.memory_operand_to_address(self.cfg.inspect_seq.clone().as_str());
                    let bits = self.get_size(self.cfg.inspect_seq.clone().as_str());
                    let value = self.memory_read(self.cfg.inspect_seq.clone().as_str()).unwrap_or(0);
                    println!("\t{} {} (0x{:x}): 0x{:x} {} '{}' {{{}}}", self.pos, self.cfg.inspect_seq, addr, value, value, 
                        self.maps.read_string(addr), self.maps.read_string_of_bytes(addr, constants::NUM_BYTES_TRACE));
                }

                let mut info_factory = InstructionInfoFactory::new();
                let info = info_factory.info(&ins);


                // instructions implementation

                match ins.mnemonic() {

                    Mnemonic::Jmp => {
                        self.show_instruction(&self.colors.yellow, &ins);

                        if ins.op_count() != 1 {
                            unimplemented!("weird variant of jmp");
                        }

                        let addr = match self.get_operand_value(&ins, 0, true) {
                            Some(a) => a,
                            None => break
                        };

                        if self.cfg.is_64bits {
                            self.set_rip(addr, false);
                        } else {
                            self.set_eip(addr, false);
                        }
                        break;
                    }

                    Mnemonic::Call => {
                        self.show_instruction(&self.colors.yellow, &ins);

                        if ins.op_count() != 1 {
                            unimplemented!("weird variant of call");
                        }

                        let addr = match self.get_operand_value(&ins, 0, true) {
                            Some(a) => a,
                            None => break
                        };

                        if self.cfg.is_64bits {
                            self.stack_push64(self.regs.rip + sz as u64);
                            self.set_rip(addr, false);
                        } else {
                            self.stack_push32(self.regs.get_eip() as u32 + sz as u32);
                            self.set_eip(addr, false);
                        }
                        break;
                    }

                    Mnemonic::Push => {

                        let value = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break
                        };

                        self.show_instruction_pushpop(&self.colors.blue, &ins, value);

                        if self.cfg.is_64bits {
                            self.stack_push64(value);
                        } else {
                            self.stack_push32(to32!(value));
                        }
                    }

                    Mnemonic::Pop => {

                        let value:u64;

                        if self.cfg.is_64bits { 
                            value = self.stack_pop64(true);
                        } else {
                            value = self.stack_pop32(true) as u64;
                        }

                        self.show_instruction_pushpop(&self.colors.blue, &ins, value);

                        if !self.set_operand_value(&ins, 0, value) {
                            break;
                        }
                    }

                    Mnemonic::Pushad => {
                        self.show_instruction(&self.colors.blue, &ins);

                        // only 32bits instruction
                        let tmp_esp = self.regs.get_esp() as u32;
                        self.stack_push32(self.regs.get_eax() as u32);
                        self.stack_push32(self.regs.get_ecx() as u32);
                        self.stack_push32(self.regs.get_edx() as u32);
                        self.stack_push32(self.regs.get_ebx() as u32);
                        self.stack_push32(tmp_esp);
                        self.stack_push32(self.regs.get_ebp() as u32);
                        self.stack_push32(self.regs.get_esi() as u32);
                        self.stack_push32(self.regs.get_edi() as u32);
                    }

                    Mnemonic::Popad => {
                        self.show_instruction(&self.colors.blue, &ins);
                        let mut poped:u64;

                        // only 32bits instruction
                        poped = self.stack_pop32(false) as u64;
                        self.regs.set_edi(poped);
                        poped = self.stack_pop32(false) as u64;
                        self.regs.set_esi(poped);
                        poped = self.stack_pop32(false) as u64;
                        self.regs.set_ebp(poped);

                        self.regs.set_esp(self.regs.get_esp() + 4); // skip esp

                        poped = self.stack_pop32(false) as u64;
                        self.regs.set_ebx(poped);
                        poped = self.stack_pop32(false) as u64;
                        self.regs.set_edx(poped);
                        poped = self.stack_pop32(false) as u64;
                        self.regs.set_ecx(poped);
                        poped = self.stack_pop32(false) as u64;
                        self.regs.set_eax(poped);
                    }

                    Mnemonic::Cdqe => {
                        self.show_instruction(&self.colors.blue, &ins);

                        self.regs.rax = self.regs.get_eax() as u32 as i32 as i64 as u64; // sign extend
                    }

                    Mnemonic::Cdq => {
                        self.show_instruction(&self.colors.blue, &ins);

                        let num:i64 = self.regs.get_eax() as u32 as i32 as i64; // sign-extend
                        let unum:u64 = num as u64;
                        self.regs.set_edx((unum & 0xffffffff00000000) >> 32);
                        self.regs.set_eax(unum & 0xffffffff);
                    }

                    Mnemonic::Cqo => {
                        self.show_instruction(&self.colors.blue, &ins);

                        let sigextend:u128 = self.regs.rax as u64 as i64 as i128 as u128;
                        self.regs.rdx = ((sigextend & 0xffffffff_ffffffff_00000000_00000000) >> 64) as u64
                    }

                    Mnemonic::Ret => {
                        let ret_addr:u64;

                        if self.cfg.is_64bits {
                            ret_addr = self.stack_pop64(false); // return address
                        } else {
                            ret_addr = self.stack_pop32(false) as u64; // return address
                        }

                        self.show_instruction_ret(&self.colors.yellow, &ins, ret_addr);

                        if self.run_until_ret {
                            return;
                        }

                        if self.break_on_next_return {
                            self.break_on_next_return = false;
                            self.spawn_console();
                        }
    
                        if ins.op_count() > 0 {
                            let mut arg = self.get_operand_value(&ins, 0, true).expect("weird crash on ret");
                            // apply stack compensation of ret operand

                            if self.cfg.is_64bits {

                                if arg % 8 != 0 {
                                    panic!("weird ret argument!");
                                }
    
                                arg /= 8;

                                for _ in 0..arg {
                                    self.stack_pop64(false);
                                }

                            } else {

                                if arg % 4 != 0 {
                                    panic!("weird ret argument!");
                                }
    
                                arg /= 4;

                                for _ in 0..arg {
                                    self.stack_pop32(false);
                                }
                            }
                        }

                        if self.eh_ctx != 0 {
                            exception::exit(self);
                            break;
                        }

                        if self.cfg.is_64bits {
                            self.set_rip(ret_addr, false);                        
                        } else {
                            self.set_eip(ret_addr, false);                        
                        }

                        break;
                    }

                    Mnemonic::Xchg => {
                        self.show_instruction(&self.colors.light_cyan, &ins);

                        assert!(ins.op_count() == 2);

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v)  => v,
                            None => break,
                        };

                        let value1 = match self.get_operand_value(&ins, 1, true) {
                            Some(v)  => v,
                            None => break,
                        };

                        if !self.set_operand_value(&ins, 0, value1) { 
                            break;
                        }
                        if !self.set_operand_value(&ins, 1, value0) {
                            break;
                        }
                    }

                    Mnemonic::Mov => {
                        self.show_instruction(&self.colors.light_cyan, &ins);

                        assert!(ins.op_count() == 2);

                        let value1 = match self.get_operand_value(&ins, 1, true) {
                            Some(v) => v,
                            None => break,
                        };

                        if !self.set_operand_value(&ins, 0, value1) {
                            break;
                        }
                    }

                    Mnemonic::Xor => {
                        self.show_instruction(&self.colors.green, &ins);

                        assert!(ins.op_count() == 2);
                        assert!(self.get_operand_sz(&ins, 0) == self.get_operand_sz(&ins, 1));

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let value1 = match self.get_operand_value(&ins, 1, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let sz = self.get_operand_sz(&ins, 0);
                        let result = value0 ^ value1;

                        if self.cfg.test_mode {
                            if result != inline::xor(value0, value1) {
                                panic!("0x{:x} should be 0x{:x}", result, inline::xor(value0, value1));
                            }
                        }

                        self.flags.calc_flags(result, sz);

                        if !self.set_operand_value(&ins, 0, result) {
                            break;
                        }
                    }

                    Mnemonic::Add => {
                        self.show_instruction(&self.colors.cyan, &ins);

                        assert!(ins.op_count() == 2);

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let value1 = match self.get_operand_value(&ins, 1, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let res:u64 = match self.get_operand_sz(&ins, 1) {
                            64 => self.flags.add64(value0, value1),
                            32 => self.flags.add32(value0, value1),
                            16 => self.flags.add16(value0, value1),
                            8  => self.flags.add8(value0, value1),
                            _  => unreachable!("weird size")
                        };

                        if !self.set_operand_value(&ins, 0, res) {
                            break;
                        }

                    }

                    Mnemonic::Adc => {
                        self.show_instruction(&self.colors.cyan, &ins);

                        assert!(ins.op_count() == 2);

                        let cf:u64;
                        if self.flags.f_cf {
                            cf = 1
                        } else {
                            cf = 0;
                        }

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let value1 = match self.get_operand_value(&ins, 1, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let res:u64;
                        match self.get_operand_sz(&ins, 1) {
                            64 => res = self.flags.add64(value0, value1 + cf),
                            32 => res = self.flags.add32(value0, value1 + cf),
                            16 => res = self.flags.add16(value0, value1 + cf),
                            8  => res = self.flags.add8(value0, value1 + cf),
                            _  => unreachable!("weird size")
                        }

                        if !self.set_operand_value(&ins, 0, res) {
                            break;
                        }                        

                    }

                    Mnemonic::Sbb => {
                        self.show_instruction(&self.colors.cyan, &ins);

                        assert!(ins.op_count() == 2);

                        let cf:u64;
                        if self.flags.f_cf {
                            cf = 1;
                        } else {
                            cf = 0;
                        }

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let value1 = match self.get_operand_value(&ins, 1, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let res:u64;
                        match self.get_operand_sz(&ins, 1) {
                            64 => res = self.flags.sub64(value0, value1 + cf),
                            32 => res = self.flags.sub32(value0, value1 + cf),
                            16 => res = self.flags.sub16(value0, value1 + cf),
                            8  => res = self.flags.sub8(value0, value1 + cf),
                            _  => panic!("weird size")
                        }

                        if !self.set_operand_value(&ins, 0, res) {
                            break;
                        } 

                    }

                    Mnemonic::Sub => {
                        self.show_instruction(&self.colors.cyan, &ins);

                        assert!(ins.op_count() == 2);

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let value1 = match self.get_operand_value(&ins, 1, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let res:u64;
                        match self.get_operand_sz(&ins, 0) {
                            64 => res = self.flags.sub64(value0, value1),
                            32 => res = self.flags.sub32(value0, value1),
                            16 => res = self.flags.sub16(value0, value1),
                            8  => res = self.flags.sub8(value0, value1),
                            _  => panic!("weird size")
                        }

                        if !self.set_operand_value(&ins, 0, res) {
                            break;
                        } 

                    }

                    Mnemonic::Inc => {
                        self.show_instruction(&self.colors.cyan, &ins);

                        assert!(ins.op_count() == 1);

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let res = match self.get_operand_sz(&ins, 0) {
                            64 => self.flags.inc64(value0),
                            32 => self.flags.inc32(value0),
                            16 => self.flags.inc16(value0),
                            8  => self.flags.inc8(value0),
                            _  => panic!("weird size")
                        };

                        if !self.set_operand_value(&ins, 0, res) {
                            break;
                        } 
                    }

                    Mnemonic::Dec => {
                        self.show_instruction(&self.colors.cyan, &ins);

                        assert!(ins.op_count() == 1);

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let res = match self.get_operand_sz(&ins, 0) {
                            64 => self.flags.dec64(value0),
                            32 => self.flags.dec32(value0),
                            16 => self.flags.dec16(value0),
                            8  => self.flags.dec8(value0),
                            _  => panic!("weird size")
                        };

                        if !self.set_operand_value(&ins, 0, res) {
                            break;
                        } 
                    }

                    Mnemonic::Neg => {
                        self.show_instruction(&self.colors.green, &ins);

                        assert!(ins.op_count() == 1);

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let sz = self.get_operand_sz(&ins, 0);
                        let res = match sz {
                            64 => self.flags.neg64(value0),
                            32 => self.flags.neg32(value0),
                            16 => self.flags.neg16(value0),
                            8  => self.flags.neg8(value0),
                            _  => panic!("weird size")
                        };

                        if self.cfg.test_mode {
                            if res != inline::neg(value0, sz) {
                                panic!("0x{:x} should be 0x{:x}", res, inline::neg(value0, sz));
                            }
                        }

                        if !self.set_operand_value(&ins, 0, res) {
                            break;
                        }
                    }

                    Mnemonic::Not => {
                        self.show_instruction(&self.colors.green, &ins);

                        assert!(ins.op_count() == 1);

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let val:u64;

                        /*let mut ival = value0 as i32;
                        ival = !ival;*/

                        let sz = self.get_operand_sz(&ins, 0);
                        match sz {
                            64 => {
                                let mut ival = value0 as i64;
                                ival = !ival;
                                val = ival as u64;
                            }
                            32 => {
                                let mut ival = value0 as u32 as i32;
                                ival = !ival;
                                val = value0 & 0xffffffff_00000000 | ival as u32 as u64;
                            }
                            16 => {
                                let mut ival = value0 as u16 as i16;
                                ival = !ival;
                                val = value0 & 0xffffffff_ffff0000 | ival as u16 as u64;
                            }
                            8 => {
                                let mut ival = value0 as u8 as i8;
                                ival = !ival;
                                val = value0 & 0xffffffff_ffffff00 | ival as u8 as u64;
                            }
                            _ => unimplemented!("weird"),
                        }

                        if self.cfg.test_mode {
                            if val != inline::not(value0, sz) {
                                panic!("0x{:x} should be 0x{:x}", val, inline::not(value0, sz));
                            }
                        }

                        if !self.set_operand_value(&ins, 0, val) {
                            break;
                        }
                    }

                    Mnemonic::And => {  
                        self.show_instruction(&self.colors.green, &ins);

                        assert!(ins.op_count() == 2);

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let value1 = match self.get_operand_value(&ins, 1, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let sz = self.get_operand_sz(&ins, 0);
                        let result1:u64;
                        let result2:u64;

                        match sz {
                            8 => {
                                result1 = (value0 & 0xff) & (value1 & 0xff);
                                result2 = (value0 & 0xffffffffffffff00) + result1;
                            }
                            16 => {
                                result1 = (value0 & 0xffff) & (value1 & 0xffff);
                                result2 = (value0 & 0xffffffffffff0000) + result1;
                            }
                            32 => {
                                result1 = (value0 & 0xffffffff) & (value1 & 0xffffffff);
                                result2 = (value0 & 0xffffffff00000000) + result1;
                            }
                            64 => { 
                                result1 = value0 & value1;
                                result2 = result1;
                            }
                            _ => unreachable!(""),
                        }

                        if self.cfg.test_mode {
                            if result2 != inline::and(value0, value1) {
                                panic!("0x{:x} should be 0x{:x}", result2, inline::and(value0, value1));
                            }
                        }

                        self.flags.calc_flags(result1, self.get_operand_sz(&ins, 0));
                        self.flags.f_of = false;
                        self.flags.f_cf = false;

                        if !self.set_operand_value(&ins, 0, result2) {
                            break;
                        }
                    }

                    Mnemonic::Or => {
                        self.show_instruction(&self.colors.green, &ins);

                        assert!(ins.op_count() == 2);
                        assert!(self.get_operand_sz(&ins, 0) == self.get_operand_sz(&ins, 1));

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let value1 = match self.get_operand_value(&ins, 1, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let sz = self.get_operand_sz(&ins, 0);
                        let result1:u64;
                        let result2:u64;

                        match sz {
                            8 => {
                                result1 = (value0 & 0xff) | (value1 & 0xff);
                                result2 = (value0 & 0xffffffffffffff00) + result1;
                            }
                            16 => {
                                result1 = (value0 & 0xffff) | (value1 & 0xffff);
                                result2 = (value0 & 0xffffffffffff0000) + result1;
                            }
                            32 => {
                                result1 = (value0 & 0xffffffff) | (value1 & 0xffffffff);
                                result2 = (value0 & 0xffffffff00000000) + result1;
                            }
                            64 => { 
                                result1 = value0 | value1;
                                result2 = result1;
                            }
                            _ => unreachable!(""),
                        }

                        if self.cfg.test_mode {
                            if result2 != inline::or(value0, value1) {
                                panic!("0x{:x} should be 0x{:x}", result2, inline::or(value0, value1));
                            }
                        }

                        self.flags.calc_flags(result1, self.get_operand_sz(&ins, 0));
                        self.flags.f_of = false;
                        self.flags.f_cf = false;

                        if !self.set_operand_value(&ins, 0, result2) {
                            break;
                        }
                    }

                    Mnemonic::Sal => {
                        self.show_instruction(&self.colors.green, &ins);

                        assert!(ins.op_count() == 1 || ins.op_count() == 2);

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        if ins.op_count() == 1 { // 1 param

                            let result = match self.get_operand_sz(&ins, 0) {
                                64 => self.flags.sal1p64(value0),
                                32 => self.flags.sal1p32(value0),
                                16 => self.flags.sal1p16(value0),
                                8  => self.flags.sal1p8(value0),
                                _  => panic!("weird size")
                            };

                            if !self.set_operand_value(&ins, 0, result) {
                                break;
                            }


                        } else { // 2 params

                            let value1 = match self.get_operand_value(&ins, 1, true) {
                                Some(v) => v,
                                None => break,
                            };

                            let result = match self.get_operand_sz(&ins, 0) {
                                64 => self.flags.sal2p64(value0, value1),
                                32 => self.flags.sal2p32(value0, value1),
                                16 => self.flags.sal2p16(value0, value1),
                                8  => self.flags.sal2p8(value0, value1),
                                _  => panic!("weird size")
                            };

                            if !self.set_operand_value(&ins, 0, result) {
                                break;
                            }

                        }
                    }

                    Mnemonic::Sar => {
                        self.show_instruction(&self.colors.green, &ins);

                        assert!(ins.op_count() == 1 || ins.op_count() == 2);

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        if ins.op_count() == 1 { // 1 param

                            let result = match self.get_operand_sz(&ins, 0) {
                                64 => self.flags.sar1p64(value0),
                                32 => self.flags.sar1p32(value0),
                                16 => self.flags.sar1p16(value0),
                                8  => self.flags.sar1p8(value0),
                                _  => panic!("weird size")
                            };

                            if !self.set_operand_value(&ins, 0, result) {
                                break;
                            }


                        } else { // 2 params

                            let value1 = match self.get_operand_value(&ins, 1, true) {
                                Some(v) => v,
                                None => break,
                            };

                            let result = match self.get_operand_sz(&ins, 0) {
                                64 => self.flags.sar2p64(value0, value1),
                                32 => self.flags.sar2p32(value0, value1),
                                16 => self.flags.sar2p16(value0, value1),
                                8  => self.flags.sar2p8(value0, value1),
                                _  => panic!("weird size")
                            };

                            if !self.set_operand_value(&ins, 0, result) {
                                break;
                            }

                        }
                    }

                    Mnemonic::Shl => {
                        self.show_instruction(&self.colors.green, &ins);

                        assert!(ins.op_count() == 1 || ins.op_count() == 2);

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        if ins.op_count() == 1 { // 1 param

                            let result = match self.get_operand_sz(&ins, 0) {
                                64 => self.flags.shl1p64(value0),
                                32 => self.flags.shl1p32(value0),
                                16 => self.flags.shl1p16(value0),
                                8  => self.flags.shl1p8(value0),
                                _  => panic!("weird size")
                            };

                            if !self.set_operand_value(&ins, 0, result) {
                                break;
                            }


                        } else { // 2 params

                            let value1 = match self.get_operand_value(&ins, 1, true) {
                                Some(v) => v,
                                None => break,
                            };

                            let result = match self.get_operand_sz(&ins, 0) {
                                64 => self.flags.shl2p64(value0, value1),
                                32 => self.flags.shl2p32(value0, value1),
                                16 => self.flags.shl2p16(value0, value1),
                                8  => self.flags.shl2p8(value0, value1),
                                _  => panic!("weird size")
                            };

                            //println!("0x{:x}: 0x{:x} SHL 0x{:x} = 0x{:x}", ins.ip32(), value0, value1, result);

                            if !self.set_operand_value(&ins, 0, result) {
                                break;
                            }

                        }
                    }

                    Mnemonic::Shr => {
                        self.show_instruction(&self.colors.green, &ins);

                        assert!(ins.op_count() == 1 || ins.op_count() == 2);

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        if ins.op_count() == 1 { // 1 param

                            let result = match self.get_operand_sz(&ins, 0) {
                                64 => self.flags.shr1p64(value0),
                                32 => self.flags.shr1p32(value0),
                                16 => self.flags.shr1p16(value0),
                                8  => self.flags.shr1p8(value0),
                                _  => panic!("weird size")
                            };

                            if !self.set_operand_value(&ins, 0, result) {
                                break;
                            }

                        } else { // 2 params

                            let value1 = match self.get_operand_value(&ins, 1, true) {
                                Some(v) => v,
                                None => break,
                            };

                            let result = match self.get_operand_sz(&ins, 0) {
                                64 => self.flags.shr2p64(value0, value1),
                                32 => self.flags.shr2p32(value0, value1),
                                16 => self.flags.shr2p16(value0, value1),
                                8  => self.flags.shr2p8(value0, value1),
                                _  => panic!("weird size")
                            };

                            //println!("0x{:x} SHR 0x{:x} >> 0x{:x} = 0x{:x}", ins.ip32(), value0, value1, result);

                            if !self.set_operand_value(&ins, 0, result) {
                                break;
                            }

                        }
                    }

                    Mnemonic::Ror => {
                        self.show_instruction(&self.colors.green, &ins);

                        assert!(ins.op_count() == 1 || ins.op_count() == 2);

                        let result:u64;
                        let sz = self.get_operand_sz(&ins, 0);


                        if ins.op_count() == 1 { // 1 param
                            let value0 = match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            result = self.ror(value0, 1, sz);

                            if self.cfg.test_mode {
                                if result != inline::ror(value0, 1, sz) {
                                    panic!("0x{:x} should be 0x{:x}", result, inline::ror(value0, 1, sz))
                                }
                            }

                        } else { // 2 params
                            let value0 = match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            let value1 = match self.get_operand_value(&ins, 1, true) {
                                Some(v) => v,
                                None => break,
                            };

                            result = self.ror(value0, value1, sz);

                            if self.cfg.test_mode {
                                if result != inline::ror(value0, value1, sz) {
                                    panic!("0x{:x} should be 0x{:x}", result, inline::ror(value0, value1, sz))
                                }
                            }

                        }

                        if !self.set_operand_value(&ins, 0, result) {
                            break;
                        }

                        self.flags.calc_flags(result, sz);
                    }

                    Mnemonic::Rcr => {
                        self.show_instruction(&self.colors.green, &ins);

                        assert!(ins.op_count() == 1 || ins.op_count() == 2);

                        let result:u64;
                        let sz = self.get_operand_sz(&ins, 0);


                        if ins.op_count() == 1 { // 1 param
                            let value0 = match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            result = self.rcr(value0, 1, sz);

                        } else { // 2 params
                            let value0 = match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            let value1 = match self.get_operand_value(&ins, 1, true) {
                                Some(v) => v,
                                None => break,
                            };

                            result = self.rcr(value0, value1, sz);
                        }

                        if !self.set_operand_value(&ins, 0, result) {
                            break;
                        }

                        self.flags.calc_flags(result, sz);
                    }

                    Mnemonic::Rol => {
                        self.show_instruction(&self.colors.green, &ins);

                        assert!(ins.op_count() == 1 || ins.op_count() == 2);

                        let result:u64;
                        let sz = self.get_operand_sz(&ins, 0);


                        if ins.op_count() == 1 { // 1 param
                            let value0 = match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            result = self.rol(value0, 1, sz);

                            if self.cfg.test_mode {
                                if result != inline::rol(value0, 1, sz) {
                                    panic!("0x{:x} should be 0x{:x}", result, inline::rol(value0, 1, sz));
                                }
                            }

                        } else { // 2 params
                            let value0 = match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            let value1 = match self.get_operand_value(&ins, 1, true) {
                                Some(v) => v,
                                None => break,
                            };

                            result = self.rol(value0, value1, sz);

                            if self.cfg.test_mode {
                                if result != inline::rol(value0, value1, sz) {
                                    panic!("0x{:x} should be 0x{:x}", result, inline::rol(value0, value1, sz));
                                }
                            }
                        }

                        if !self.set_operand_value(&ins, 0, result) {
                            break;
                        }

                        self.flags.calc_flags(result, sz as u8);
                    }

                    Mnemonic::Rcl => {
                        self.show_instruction(&self.colors.green, &ins);

                        assert!(ins.op_count() == 1 || ins.op_count() == 2);

                        let result:u64;
                        let sz = self.get_operand_sz(&ins, 0) + 1;

                        if ins.op_count() == 1 { // 1 param
                            let value0 = match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            result = self.rcl(value0, 1, sz);

                        } else { // 2 params
                            let value0 = match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            let value1 = match self.get_operand_value(&ins, 1, true) {
                                Some(v) => v,
                                None => break,
                            };

                            result = self.rcl(value0, value1, sz);
                        }

                        if !self.set_operand_value(&ins, 0, result) {
                            break;
                        }

                        self.flags.calc_flags(result, sz as u8 -1);
                    }


                    Mnemonic::Mul => {
                        self.show_instruction(&self.colors.cyan, &ins);

                        assert!(ins.op_count() == 1);

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        match self.get_operand_sz(&ins, 0) {
                            64 => self.mul64(value0),
                            32 => self.mul32(value0),
                            16 => self.mul16(value0),
                            8  => self.mul8(value0),
                            _ => unimplemented!("wrong size"),
                        }
                    }

                    Mnemonic::Div => {
                        self.show_instruction(&self.colors.cyan, &ins);

                        assert!(ins.op_count() == 1);

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        match self.get_operand_sz(&ins, 0) {
                            64 => self.div64(value0),
                            32 => self.div32(value0),
                            16 => self.div16(value0),
                            8  => self.div8(value0),
                            _ => unimplemented!("wrong size"),
                        }
                    }

                    Mnemonic::Idiv => {
                        self.show_instruction(&self.colors.cyan, &ins);

                        assert!(ins.op_count() == 1);

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        match self.get_operand_sz(&ins, 0) {
                            64 => self.idiv64(value0),
                            32 => self.idiv32(value0),
                            16 => self.idiv16(value0),
                            8  => self.idiv8(value0),
                            _ => unimplemented!("wrong size"),
                        }
                    }

                    Mnemonic::Imul => {
                        self.show_instruction(&self.colors.cyan, &ins);

                        assert!(ins.op_count() == 1 || ins.op_count() == 2 || ins.op_count() == 3);

                        if ins.op_count() == 1 { // 1 param

                            let value0 = match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            match self.get_operand_sz(&ins, 0) {
                                64 => self.imul64p1(value0),
                                32 => self.imul32p1(value0),
                                16 => self.imul16p1(value0),
                                8  => self.imul8p1(value0),
                                _ => unimplemented!("wrong size"),
                            }

                        } else if ins.op_count() == 2 { // 2 params
                            let value0 = match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            let value1 = match self.get_operand_value(&ins, 1, true) {
                                Some(v) => v,
                                None => break,
                            };

                            let result = match self.get_operand_sz(&ins, 0) {
                                64 => self.flags.imul64p2(value0, value1),
                                32 => self.flags.imul32p2(value0, value1),
                                16 => self.flags.imul16p2(value0, value1),
                                8  => self.flags.imul8p2(value0, value1),
                                _ => unimplemented!("wrong size"),
                            };

                            if !self.set_operand_value(&ins, 0, result) {
                                break;
                            }

                        } else { // 3 params

                            let value1 = match self.get_operand_value(&ins, 1, true) {
                                Some(v) => v,
                                None => break,
                            };

                            let value2 = match self.get_operand_value(&ins, 2, true) {
                                Some(v) => v,
                                None => break,
                            };

                            let result = match self.get_operand_sz(&ins, 0) {
                                64 => self.flags.imul64p2(value1, value2),
                                32 => self.flags.imul32p2(value1, value2),
                                16 => self.flags.imul16p2(value1, value2),
                                8  => self.flags.imul8p2(value1, value2),
                                _ => unimplemented!("wrong size"),
                            };

                            if !self.set_operand_value(&ins, 0, result) {
                                break;
                            }

                        }
                    }

                    Mnemonic::Bt | Mnemonic::Bts | Mnemonic::Btr | Mnemonic::Btc => {
                        self.show_instruction(&self.colors.green, &ins);
                        assert!(ins.op_count() == 2);

                        let bit = match self.get_operand_value(&ins, 1, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let value = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        self.flags.f_cf = (value & (1 << bit)) == 1;
                    }

                    Mnemonic::Bsf => {
                        self.show_instruction(&self.colors.green, &ins);
                        assert!(ins.op_count() == 2);

                        let src = match self.get_operand_value(&ins, 1, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let sz = self.get_operand_sz(&ins, 0);
                        let mut bitpos: u8 = 0;
                        let mut dest: u64 = 0;

                        while bitpos < sz && get_bit!(src, bitpos) == 0 {
                            dest += 1;
                            bitpos += 1;
                        }
                        dest -= 1;

                        if dest == sz as u64 {
                            self.flags.f_cf = true;
                        } else {
                            self.flags.f_cf = false;
                        }

                        if dest == 0 {
                            self.flags.f_zf = true;
                        } else {
                            self.flags.f_zf = false;
                        }

                        if !self.set_operand_value(&ins, 0, dest) {
                            break;
                        }
                    }

                    Mnemonic::Bsr => {
                        self.show_instruction(&self.colors.green, &ins);
                        assert!(ins.op_count() == 2);

                        let value1 = match self.get_operand_value(&ins, 1, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let sz = self.get_operand_sz(&ins, 0);
                        let mut bitpos: u8 = sz-1;
                        let mut dest: u64 = 0;

                        while bitpos <= 0 && get_bit!(value1, bitpos) == 0 {
                            dest += 1;
                            bitpos -= 1;
                        }

                        if dest != sz as u64 {
                            self.flags.f_cf = true;
                        } else {
                            self.flags.f_cf = false;
                        }

                        if dest == 0 {
                            self.flags.f_zf = true;
                        } else {
                            self.flags.f_zf = false;
                        }

                        if !self.set_operand_value(&ins, 0, dest) {
                            break;
                        }
                    }

                    Mnemonic::Bswap => {
                        self.show_instruction(&self.colors.green, &ins);
                        assert!(ins.op_count() == 1);

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let value1;
                        let sz = self.get_operand_sz(&ins, 0);

                        if sz == 32 {
                            value1 = (value0 & 0x00000000_000000ff) << 24 | (value0 & 0x00000000_0000ff00) << 8 |
                                (value0 & 0x00000000_00ff0000) >> 8 | (value0 & 0x00000000_ff000000) >> 24 |
                                (value0 & 0xffffffff_00000000);

                        } else if sz == 64 {
                            value1 = (value0 & 0xff000000_00000000) >> 56 | (value0 & 0x00ff0000_00000000) >> 40 |
                                (value0 & 0x0000ff00_00000000) >> 24 | (value0 & 0x000000ff_00000000) >> 8 |
                                (value0 & 0x00000000_ff000000) << 8 | (value0 & 0x00000000_00ff0000) << 24 |
                                (value0 & 0x00000000_0000ff00) << 40 | (value0 & 0x00000000_000000ff) << 56;

                        } else if sz == 16 {
                            value1 = (value0 & 0x00000000_000000ff) << 8 | (value0 & 0x00000000_0000ff00) >> 8;

                        } else {
                            unimplemented!("bswap <16bits makes no sense, isn't it?");
                        }

                        /*
                        for i in 0..sz {
                            let bit = get_bit!(value0, i);
                            set_bit!(value1, sz-i-1, bit);
                        }*/

                        if !self.set_operand_value(&ins, 0, value1) {
                            break;
                        }

                    }

                    Mnemonic::Xadd => {
                        self.show_instruction(&self.colors.green, &ins);
                        assert!(ins.op_count() == 2);

                        let value1 = match self.get_operand_value(&ins, 1, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        if !self.set_operand_value(&ins, 1, value0) {
                            break;
                        }

                        let res:u64 = match self.get_operand_sz(&ins, 1) {
                            64 => self.flags.add64(value0, value1),
                            32 => self.flags.add32(value0, value1),
                            16 => self.flags.add16(value0, value1),
                            8  => self.flags.add8(value0, value1),
                            _  => unreachable!("weird size")
                        };

                        if !self.set_operand_value(&ins, 0, res) {
                            break;
                        }
                    }

                    Mnemonic::Movsxd => {
                        self.show_instruction(&self.colors.light_cyan, &ins);

                        assert!(ins.op_count() == 2);

                        let value1 = match self.get_operand_value(&ins, 1, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let result:u64 = value1 as u32 as i32 as i64 as u64;


                        if !self.set_operand_value(&ins, 0, result) {
                            break;
                        }
                    }

                    Mnemonic::Movsx => {
                        self.show_instruction(&self.colors.light_cyan, &ins);

                        assert!(ins.op_count() == 2);


                        let value1 = match self.get_operand_value(&ins, 1, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let sz0 = self.get_operand_sz(&ins, 0);
                        let sz1 = self.get_operand_sz(&ins, 1);

                        assert!((sz0 == 16 && sz1 == 8) || 
                            (sz0 == 32 && sz1 == 8) || 
                            (sz0 == 32 && sz1 == 16) ||
                            (sz0 == 64 && sz1 == 32) ||
                            (sz0 == 64 && sz1 == 16) ||
                            (sz0 == 64 && sz1 == 8));


                        let mut result:u64 = 0;

                        if sz0 == 16 {
                            assert!(sz1 == 8);
                            result = value1 as u8 as i8 as i16 as u16 as u64;
                        } else if sz0 == 32 {
                            if sz1 == 8 {
                                result = value1 as u8 as i8 as i64 as u64;
                            } else if sz1 == 16 {
                                result = value1 as u8 as i8 as i16 as u16 as u64;
                            }
                        } else if sz0 == 64 {
                            if sz1 == 8 {
                                result = value1 as u8 as i8 as i64 as u64;
                            } else if sz1 == 16 {
                                result = value1 as u16 as i16 as i64 as u64;
                            } else if sz1 == 32 {
                                result = value1 as u32 as i32 as i64 as u64;
                            }
                        }

                        if !self.set_operand_value(&ins, 0, result) {
                            break;
                        }

                    }

                    Mnemonic::Movzx => {
                        self.show_instruction(&self.colors.light_cyan, &ins);

                        assert!(ins.op_count() == 2);

                        let value1 = match self.get_operand_value(&ins, 1, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let sz0 = self.get_operand_sz(&ins, 0);
                        let sz1 = self.get_operand_sz(&ins, 1);

                        assert!((sz0 == 16 && sz1 == 8) || 
                            (sz0 == 32 && sz1 == 8) || 
                            (sz0 == 32 && sz1 == 16) ||
                            (sz0 == 64 && sz1 == 32) ||
                            (sz0 == 64 && sz1 == 16) ||
                            (sz0 == 64 && sz1 == 8));


                        let result:u64;


                        result = value1;

                        //println!("0x{:x}: MOVZX 0x{:x}", ins.ip32(), result);

                        if !self.set_operand_value(&ins, 0, result) {
                            break;
                        }

                    }

                    Mnemonic::Movsb => {
                        self.show_instruction(&self.colors.light_cyan, &ins);

                        if self.cfg.is_64bits {
                            if ins.has_rep_prefix() {
                                loop {
                                    let val = self.maps.read_byte(self.regs.rsi).expect("cannot read memory"); 
                                    self.maps.write_byte(self.regs.rdi, val);

                                    if !self.flags.f_df {
                                        self.regs.rsi += 1;
                                        self.regs.rdi += 1;
                                    } else {
                                        self.regs.rsi -= 1;
                                        self.regs.rdi -= 1;
                                    }

                                    self.regs.rcx -= 1;
                                    if self.regs.rcx == 0 { 
                                        break 
                                    }
                                }

                            } else {
                                let val = self.maps.read_byte(self.regs.rsi).expect("cannot read memory"); 
                                self.maps.write_byte(self.regs.rdi, val);
                                if !self.flags.f_df {
                                    self.regs.rsi += 1;
                                    self.regs.rdi += 1;
                                } else {
                                    self.regs.rsi -= 1;
                                    self.regs.rdi -= 1;
                                }
                            }
                        } else { // 32bits

                            if ins.has_rep_prefix() {
                                loop {
                                    let val = self.maps.read_byte(self.regs.get_esi()).expect("cannot read memory"); 
                                    self.maps.write_byte(self.regs.get_edi(), val);

                                    if !self.flags.f_df {
                                        self.regs.set_esi(self.regs.get_esi() + 1);
                                        self.regs.set_edi(self.regs.get_edi() + 1);
                                    } else {
                                        self.regs.set_esi(self.regs.get_esi() - 1);
                                        self.regs.set_edi(self.regs.get_edi() - 1);
                                    }

                                    self.regs.set_ecx(self.regs.get_ecx() - 1);
                                    if self.regs.get_ecx() == 0 { 
                                        break 
                                    }
                                }

                            } else {
                                let val = self.maps.read_byte(self.regs.get_esi()).expect("cannot read memory"); 
                                self.maps.write_byte(self.regs.get_edi(), val);
                                if !self.flags.f_df {
                                    self.regs.set_esi(self.regs.get_esi() + 1);
                                    self.regs.set_edi(self.regs.get_edi() + 1);
                                } else {
                                    self.regs.set_esi(self.regs.get_esi() - 1);
                                    self.regs.set_edi(self.regs.get_edi() - 1);
                                }
                            }
                        }
                    }


                    Mnemonic::Movsw => {
                        self.show_instruction(&self.colors.light_cyan, &ins);

                        if self.cfg.is_64bits {
                            if ins.has_rep_prefix() {
                                loop {
                                    let val = self.maps.read_word(self.regs.rsi).expect("cannot read memory"); 
                                    self.maps.write_word(self.regs.rdi, val);

                                    if !self.flags.f_df {
                                        self.regs.rsi += 2;
                                        self.regs.rdi += 2;
                                    } else {
                                        self.regs.rsi -= 2;
                                        self.regs.rdi -= 2;
                                    }

                                    self.regs.rcx -= 1;
                                    if self.regs.rcx == 0 { 
                                        break 
                                    }
                                }

                            } else {
                                let val = self.maps.read_word(self.regs.rsi).expect("cannot read memory"); 
                                self.maps.write_word(self.regs.rdi, val);
                                if !self.flags.f_df {
                                    self.regs.rsi += 2;
                                    self.regs.rdi += 2;
                                } else {
                                    self.regs.rsi -= 2;
                                    self.regs.rdi -= 2;
                                }
                            }

                        } else { // 32bits

                            if ins.has_rep_prefix() {
                                loop {
                                    let val = self.maps.read_word(self.regs.get_esi()).expect("cannot read memory"); 
                                    self.maps.write_word(self.regs.get_edi(), val);

                                    if !self.flags.f_df {
                                        self.regs.set_esi(self.regs.get_esi() + 2);
                                        self.regs.set_edi(self.regs.get_edi() + 2);
                                    } else {
                                        self.regs.set_esi(self.regs.get_esi() - 2);
                                        self.regs.set_edi(self.regs.get_edi() - 2);
                                    }

                                    self.regs.set_ecx(self.regs.get_ecx() - 1);
                                    if self.regs.get_ecx() == 0 { 
                                        break 
                                    }
                                }

                            } else {
                                let val = self.maps.read_word(self.regs.get_esi()).expect("cannot read memory"); 
                                self.maps.write_word(self.regs.get_edi(), val);
                                if !self.flags.f_df {
                                    self.regs.set_esi(self.regs.get_esi() + 2);
                                    self.regs.set_edi(self.regs.get_edi() + 2);
                                } else {
                                    self.regs.set_esi(self.regs.get_esi() - 2);
                                    self.regs.set_edi(self.regs.get_edi() - 2);
                                }
                            }
                        }
                    }

                    Mnemonic::Movsd => {
                        self.show_instruction(&self.colors.light_cyan, &ins);

                        if self.cfg.is_64bits {
                            if ins.has_rep_prefix() {
                                loop {
                                    let val = self.maps.read_dword(self.regs.rsi).expect("cannot read memory"); 
                                    self.maps.write_dword(self.regs.rdi, val);

                                    if !self.flags.f_df {
                                        self.regs.rsi += 4;
                                        self.regs.rdi += 4;
                                    } else {
                                        self.regs.rsi -= 4;
                                        self.regs.rdi -= 4;
                                    }

                                    self.regs.rcx -= 1;
                                    if self.regs.rcx == 0 { 
                                        break 
                                    }
                                }

                            } else {
                                let val = self.maps.read_dword(self.regs.rsi).expect("cannot read memory"); 
                                self.maps.write_dword(self.regs.rdi, val);
                                if !self.flags.f_df {
                                    self.regs.rsi += 4;
                                    self.regs.rdi += 4;
                                } else {
                                    self.regs.rsi -= 4;
                                    self.regs.rdi -= 4;
                                }
                            }
                        } else { // 32bits

                            if ins.has_rep_prefix() {
                                loop {
                                    let val = self.maps.read_dword(self.regs.get_esi()).expect("cannot read memory"); 
                                    self.maps.write_dword(self.regs.get_edi(), val);

                                    if !self.flags.f_df {
                                        self.regs.set_esi(self.regs.get_esi() + 4);
                                        self.regs.set_edi(self.regs.get_edi() + 4);
                                    } else {
                                        self.regs.set_esi(self.regs.get_esi() - 4);
                                        self.regs.set_edi(self.regs.get_edi() - 4);
                                    }

                                    self.regs.set_ecx(self.regs.get_ecx() - 1);
                                    if self.regs.get_ecx() == 0 { 
                                        break 
                                    }
                                }

                            } else {
                                let val = self.maps.read_dword(self.regs.get_esi()).expect("cannot read memory"); 
                                self.maps.write_dword(self.regs.get_edi(), val);
                                if !self.flags.f_df {
                                    self.regs.set_esi(self.regs.get_esi() + 4);
                                    self.regs.set_edi(self.regs.get_edi() + 4);
                                } else {
                                    self.regs.set_esi(self.regs.get_esi() - 4);
                                    self.regs.set_edi(self.regs.get_edi() - 4);
                                }
                            }
                        }
                    }

                    Mnemonic::Cmova => {
                        self.show_instruction(&self.colors.orange, &ins);

                        if !self.flags.f_cf && !self.flags.f_zf {
                            let value1 = match self.get_operand_value(&ins, 1, true) {
                                Some(v) => v,
                                None => break,
                            };

                            if !self.set_operand_value(&ins, 0, value1) {
                                break;
                            }
                        }
                    }

                    Mnemonic::Cmovae => {
                        self.show_instruction(&self.colors.orange, &ins);

                        if !self.flags.f_cf {
                            let value1 = match self.get_operand_value(&ins, 1, true) {
                                Some(v) => v,
                                None => break,
                            };

                            if !self.set_operand_value(&ins, 0, value1) {
                                break;
                            }
                        }
                    }

                    Mnemonic::Cmovb => {
                        self.show_instruction(&self.colors.orange, &ins);

                        if self.flags.f_cf {
                            let value1 = match self.get_operand_value(&ins, 1, true) {
                                Some(v) => v,
                                None => break,
                            };

                            if !self.set_operand_value(&ins, 0, value1) {
                                break;
                            }
                        }
                    }

                    Mnemonic::Cmovbe => {
                        self.show_instruction(&self.colors.orange, &ins);

                        if self.flags.f_cf || self.flags.f_zf {
                            let value1 = match self.get_operand_value(&ins, 1, true) {
                                Some(v) => v,
                                None => break,
                            };

                            if !self.set_operand_value(&ins, 0, value1) {
                                break;
                            }
                        }
                    }

                    Mnemonic::Cmove => {
                        self.show_instruction(&self.colors.orange, &ins);

                        if self.flags.f_zf {
                            let value1 = match self.get_operand_value(&ins, 1, true) {
                                Some(v) => v,
                                None => break,
                            };

                            if !self.set_operand_value(&ins, 0, value1) {
                                break;
                            }
                        }
                    }

                    Mnemonic::Cmovg => {
                        self.show_instruction(&self.colors.orange, &ins);

                        if !self.flags.f_zf && self.flags.f_sf == self.flags.f_of {
                            let value1 = match self.get_operand_value(&ins, 1, true) {
                                Some(v) => v,
                                None => break,
                            };

                            if !self.set_operand_value(&ins, 0, value1) {
                                break;
                            }
                        }
                    }

                    Mnemonic::Cmovge => {
                        self.show_instruction(&self.colors.orange, &ins);

                        if self.flags.f_sf == self.flags.f_of {
                            let value1 = match self.get_operand_value(&ins, 1, true) {
                                Some(v) => v,
                                None => break,
                            };

                            if !self.set_operand_value(&ins, 0, value1) {
                                break;
                            }
                        }
                    }

                    Mnemonic::Cmovl => {
                        self.show_instruction(&self.colors.orange, &ins);

                        if self.flags.f_sf != self.flags.f_of {
                            let value1 = match self.get_operand_value(&ins, 1, true) {
                                Some(v) => v,
                                None => break,
                            };

                            if !self.set_operand_value(&ins, 0, value1) {
                                break;
                            }
                        }
                    }

                    Mnemonic::Cmovle => {
                        self.show_instruction(&self.colors.orange, &ins);

                        if self.flags.f_zf || self.flags.f_sf != self.flags.f_of {
                            let value1 = match self.get_operand_value(&ins, 1, true) {
                                Some(v) => v,
                                None => break,
                            };

                            if !self.set_operand_value(&ins, 0, value1) {
                                break;
                            }
                        }
                    }

                    Mnemonic::Cmovno => {
                        self.show_instruction(&self.colors.orange, &ins);

                        if !self.flags.f_of {
                            let value1 = match self.get_operand_value(&ins, 1, true) {
                                Some(v) => v,
                                None => break,
                            };

                            if !self.set_operand_value(&ins, 0, value1) {
                                break;
                            }
                        }
                    }

                    // https://hjlebbink.github.io/x86doc/html/CMOVcc.html

                    Mnemonic::Cmovnp => {
                        self.show_instruction(&self.colors.orange, &ins);

                        if !self.flags.f_pf {
                            let value1 = match self.get_operand_value(&ins, 1, true) {
                                Some(v) => v,
                                None => break,
                            };

                            if !self.set_operand_value(&ins, 0, value1) {
                                break;
                            }
                        }
                    }

                    Mnemonic::Cmovs => {
                        self.show_instruction(&self.colors.orange, &ins);

                        if self.flags.f_sf {
                            let value1 = match self.get_operand_value(&ins, 1, true) {
                                Some(v) => v,
                                None => break,
                            };

                            if !self.set_operand_value(&ins, 0, value1) {
                                break;
                            }
                        }
                    }

                    Mnemonic::Cmovo => {
                        self.show_instruction(&self.colors.orange, &ins);

                        if self.flags.f_of {
                            let value1 = match self.get_operand_value(&ins, 1, true) {
                                Some(v) => v,
                                None => break,
                            };

                            if !self.set_operand_value(&ins, 0, value1) {
                                break;
                            }
                        }
                    }

                    Mnemonic::Seta  => {
                        self.show_instruction(&self.colors.orange, &ins);

                        if !self.flags.f_cf && !self.flags.f_zf {
                            if !self.set_operand_value(&ins, 0, 1) {
                                break;
                            }
                        } else  {
                            if !self.set_operand_value(&ins, 0, 0) {
                                break;
                            }
                        }
                    }

                    Mnemonic::Setae  => {
                        self.show_instruction(&self.colors.orange, &ins);

                        if !self.flags.f_cf {
                            if !self.set_operand_value(&ins, 0, 1) {
                                break;
                            }
                        } else  {
                            if !self.set_operand_value(&ins, 0, 0) {
                                break;
                            }
                        }
                    }

                    Mnemonic::Setb => {
                        self.show_instruction(&self.colors.orange, &ins);

                        if self.flags.f_cf {
                            if !self.set_operand_value(&ins, 0, 1) {
                                break;
                            }
                        } else  {
                            if !self.set_operand_value(&ins, 0, 0) {
                                break;
                            }
                        }
                    }

                    Mnemonic::Setbe => {
                        self.show_instruction(&self.colors.orange, &ins);

                        if self.flags.f_cf || self.flags.f_zf {
                            if !self.set_operand_value(&ins, 0, 1) {
                                break;
                            }
                        } else  {
                            if !self.set_operand_value(&ins, 0, 0) {
                                break;
                            }
                        }
                    }

                    Mnemonic::Sete => {
                        self.show_instruction(&self.colors.orange, &ins);

                        if self.flags.f_zf {
                            if !self.set_operand_value(&ins, 0, 1) {
                                break;
                            }
                        } else  {
                            if !self.set_operand_value(&ins, 0, 0) {
                                break;
                            }
                        }
                    }

                    Mnemonic::Setg => {
                        self.show_instruction(&self.colors.orange, &ins);

                        if !self.flags.f_zf && self.flags.f_sf == self.flags.f_of {
                            if !self.set_operand_value(&ins, 0, 1) {
                                break;
                            }
                        } else  {
                            if !self.set_operand_value(&ins, 0, 0) {
                                break;
                            }
                        }
                    }

                    Mnemonic::Setge => {
                        self.show_instruction(&self.colors.orange, &ins);

                        if self.flags.f_sf == self.flags.f_of {
                            if !self.set_operand_value(&ins, 0, 1) {
                                break;
                            }
                        } else  {
                            if !self.set_operand_value(&ins, 0, 0) {
                                break;
                            }
                        }
                    }

                    Mnemonic::Setl => {
                        self.show_instruction(&self.colors.orange, &ins);

                        if self.flags.f_sf != self.flags.f_of {
                            if !self.set_operand_value(&ins, 0, 1) {
                                break;
                            }
                        } else  {
                            if !self.set_operand_value(&ins, 0, 0) {
                                break;
                            }
                        }
                    }

                    Mnemonic::Setle => {
                        self.show_instruction(&self.colors.orange, &ins);

                        if self.flags.f_zf ||  self.flags.f_sf != self.flags.f_of {
                            if !self.set_operand_value(&ins, 0, 1) {
                                break;
                            }
                        } else  {
                            if !self.set_operand_value(&ins, 0, 0) {
                                break;
                            }
                        }
                    }

                    Mnemonic::Setne => {
                        self.show_instruction(&self.colors.orange, &ins);

                        if !self.flags.f_zf {
                            if !self.set_operand_value(&ins, 0, 1) {
                                break;
                            }
                        } else  {
                            if !self.set_operand_value(&ins, 0, 0) {
                                break;
                            }
                        }
                    }   

                    Mnemonic::Setno => {
                        self.show_instruction(&self.colors.orange, &ins);

                        if !self.flags.f_of {
                            if !self.set_operand_value(&ins, 0, 1) {
                                break;
                            }
                        } else  {
                            if !self.set_operand_value(&ins, 0, 0) {
                                break;
                            }
                        }
                    }

                    Mnemonic::Setnp => {
                        self.show_instruction(&self.colors.orange, &ins);

                        if !self.flags.f_pf {
                            if !self.set_operand_value(&ins, 0, 1) {
                                break;
                            }
                        } else  {
                            if !self.set_operand_value(&ins, 0, 0) {
                                break;
                            }
                        }
                    }

                    Mnemonic::Setns => {
                        self.show_instruction(&self.colors.orange, &ins);

                        if !self.flags.f_sf {
                            if !self.set_operand_value(&ins, 0, 1) {
                                break;
                            }
                        } else  {
                            if !self.set_operand_value(&ins, 0, 0) {
                                break;
                            }
                        }
                    }

                    Mnemonic::Seto => {
                        self.show_instruction(&self.colors.orange, &ins);

                        if self.flags.f_of {
                            if !self.set_operand_value(&ins, 0, 1) {
                                break;
                            }
                        } else  {
                            if !self.set_operand_value(&ins, 0, 0) {
                                break;
                            }
                        }
                    }

                    Mnemonic::Setp => {
                        self.show_instruction(&self.colors.orange, &ins);

                        if self.flags.f_pf {
                            if !self.set_operand_value(&ins, 0, 1) {
                                break;
                            }
                        } else  {
                            if !self.set_operand_value(&ins, 0, 0) {
                                break;
                            }
                        }
                    }

                    Mnemonic::Sets => {
                        self.show_instruction(&self.colors.orange, &ins);

                        if self.flags.f_sf {
                            if !self.set_operand_value(&ins, 0, 1) {
                                break;
                            }
                        } else  {
                            if !self.set_operand_value(&ins, 0, 0) {
                                break;
                            }
                        }
                    }


                    Mnemonic::Stosb => {
                        self.show_instruction(&self.colors.light_cyan, &ins);
                        
                        if ins.has_rep_prefix() {
                            loop {
                                if self.regs.rcx == 0 {
                                    break;
                                }

                                if self.cfg.is_64bits {
                                    self.maps.write_byte(self.regs.rdi, self.regs.get_al() as u8);
                                    if self.flags.f_df {
                                        self.regs.rdi -= 1;
                                    } else {
                                        self.regs.rdi += 1;
                                    }
                                } else { // 32bits
                                    self.maps.write_byte(self.regs.get_edi(), self.regs.get_al() as u8);
                                    if self.flags.f_df {
                                        self.regs.set_edi(self.regs.get_edi() - 1);
                                    } else {
                                        self.regs.set_edi(self.regs.get_edi() + 1);
                                    }
                                }

                                self.regs.rcx -= 1;
                            }

                        } else {

                            if self.cfg.is_64bits {
                                self.maps.write_byte(self.regs.rdi, self.regs.get_al() as u8);
                                if self.flags.f_df {
                                    self.regs.rdi -= 1;
                                } else {
                                    self.regs.rdi += 1;
                                }
                            } else { // 32bits
                                self.maps.write_byte(self.regs.get_edi(), self.regs.get_al() as u8);
                                if self.flags.f_df {
                                    self.regs.set_edi(self.regs.get_edi() - 1);
                                } else {
                                    self.regs.set_edi(self.regs.get_edi() + 1);
                                }
                            }
                        }
                    }

                    Mnemonic::Stosw => {
                        self.show_instruction(&self.colors.light_cyan, &ins);

                        if self.cfg.is_64bits {
                            self.maps.write_word(self.regs.rdi, self.regs.get_ax() as u16);

                            if self.flags.f_df {
                                self.regs.rdi -= 2;
                            } else {
                                self.regs.rdi += 2;
                            }
                        } else { // 32bits
                            self.maps.write_word(self.regs.get_edi(), self.regs.get_ax() as u16);

                            if self.flags.f_df {
                                self.regs.set_edi(self.regs.get_edi() - 2);
                            } else {
                                self.regs.set_edi(self.regs.get_edi() + 2);
                            }
                        }
                    }

                    Mnemonic::Stosd => {
                        self.show_instruction(&self.colors.light_cyan, &ins);

                        if ins.has_rep_prefix() {                                             
                            loop {                  
                                if self.regs.rcx == 0 {
                                    break;
                                }                      
                                 
                                if self.cfg.is_64bits {
                                    self.maps.write_dword(self.regs.rdi, self.regs.get_eax() as u32);
                                    if self.flags.f_df {
                                        self.regs.rdi -= 4;                    
                                    } else {
                                        self.regs.rdi += 4;                    
                                    }
                                } else { // 32bits
                                    self.maps.write_dword(self.regs.get_edi(), self.regs.get_eax() as u32);
                     
                                    if self.flags.f_df {
                                        self.regs.set_edi(self.regs.get_edi() - 4);
                                    } else {
                                        self.regs.set_edi(self.regs.get_edi() + 4);
                                    }
                                }

                                self.regs.rcx -= 1;
                            }
                        } else {
                            if self.cfg.is_64bits {
                                self.maps.write_dword(self.regs.rdi, self.regs.get_eax() as u32);

                                if self.flags.f_df {
                                    self.regs.rdi -= 4;
                                } else {
                                    self.regs.rdi += 4;
                                }
                            } else { // 32bits
                                self.maps.write_dword(self.regs.get_edi(), self.regs.get_eax() as u32);

                                if self.flags.f_df {
                                    self.regs.set_edi(self.regs.get_edi() - 4);
                                } else {
                                    self.regs.set_edi(self.regs.get_edi() + 4);
                                }
                            }
                        }
                    }

                    Mnemonic::Stosq => {
                        self.show_instruction(&self.colors.light_cyan, &ins);

                        self.maps.write_qword(self.regs.rdi, self.regs.rax);

                        if self.flags.f_df {
                            self.regs.rdi -= 8;
                        } else {
                            self.regs.rdi += 8;
                        }
                        
                    }

                    Mnemonic::Scasb => {
                        self.show_instruction(&self.colors.light_cyan, &ins);

                        let value0:u64 = match self.maps.read_byte(self.regs.rdi) {
                            Some(value) => value.into(),
                            None => break,
                        };

                        self.flags.sub8(self.regs.get_al(), value0);

                        if self.cfg.is_64bits {
                            if self.flags.f_df {                       
                                self.regs.rdi -= 1;
                            } else {
                                self.regs.rdi += 1;
                            }
                        } else { // 32bits
                            if self.flags.f_df {
                                self.regs.set_edi(self.regs.get_edi() - 1);
                            } else {
                                self.regs.set_edi(self.regs.get_edi() + 1);
                            }
                        }
                    }

                    Mnemonic::Scasw => {
                        self.show_instruction(&self.colors.light_cyan, &ins);

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        self.flags.sub16(self.regs.get_ax(), value0);

                        if self.cfg.is_64bits {
                            if self.flags.f_df {                       
                                self.regs.rdi -= 2;
                            } else {
                                self.regs.rdi += 2;
                            }
                        } else { // 32bits
                            if self.flags.f_df {
                                self.regs.set_edi(self.regs.get_edi() - 2);
                            } else {
                                self.regs.set_edi(self.regs.get_edi() + 2);
                            }
                        }
                    }

                    Mnemonic::Scasd => {
                        self.show_instruction(&self.colors.light_cyan, &ins);

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        self.flags.sub32(self.regs.get_eax(), value0);

                        if self.cfg.is_64bits {
                            if self.flags.f_df {                       
                                self.regs.rdi -= 4;
                            } else {
                                self.regs.rdi += 4;
                            }
                        } else { // 32bits
                            if self.flags.f_df {
                                self.regs.set_edi(self.regs.get_edi() - 4);
                            } else {
                                self.regs.set_edi(self.regs.get_edi() + 4);
                            }
                        }
                    }

                    Mnemonic::Scasq => {
                        self.show_instruction(&self.colors.light_cyan, &ins);

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        self.flags.sub64(self.regs.rax, value0);

                        if self.flags.f_df {                       
                            self.regs.rdi -= 8;
                        } else {
                            self.regs.rdi += 8;
                        }
                    }

                    Mnemonic::Test => {
                        self.show_instruction(&self.colors.orange, &ins);

                        assert!(ins.op_count() == 2);

                        if self.break_on_next_cmp {
                            self.spawn_console();
                            self.break_on_next_cmp = false;
                        }

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let value1 = match self.get_operand_value(&ins, 1, true) {
                            Some(v) => v,
                            None => break,
                        };



                        let sz = self.get_operand_sz(&ins, 0);

                        self.flags.test(value0, value1, sz);
                    }

                    Mnemonic::Cmpxchg => {
                        self.show_instruction(&self.colors.orange, &ins);

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let value1 = match self.get_operand_value(&ins, 1, true) {
                            Some(v) => v,
                            None => break,
                        };

                        if self.cfg.is_64bits {
                            if value0 == self.regs.rax {
                                self.flags.f_zf = true;
                                if !self.set_operand_value(&ins, 0, value1) {
                                    break;
                                }
                            } else {
                                self.flags.f_zf = false;
                                self.regs.rax = value1;
                            }
                        } else { // 32bits
                            if value0 == self.regs.get_eax() {
                                self.flags.f_zf = true;
                                if !self.set_operand_value(&ins, 0, value1) {
                                    break;
                                }
                            } else {
                                self.flags.f_zf = false;
                                self.regs.set_eax(value1);
                            }
                        }
                    }

                    Mnemonic::Cmpxchg8b => {
                        self.show_instruction(&self.colors.orange, &ins);

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let value1 = match self.get_operand_value(&ins, 1, true) {
                            Some(v) => v,
                            None => break,
                        };

                        if value0 as u8 == (self.regs.get_al() as u8) {
                            self.flags.f_zf = true;
                            if !self.set_operand_value(&ins, 0, value1) {
                                break;
                            }
                        } else {
                            self.flags.f_zf = false;
                            self.regs.set_al(value1 & 0xff);
                        }
                    }


                    Mnemonic::Cmpxchg16b => {
                        self.show_instruction(&self.colors.orange, &ins);

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let value1 = match self.get_operand_value(&ins, 1, true) {
                            Some(v) => v,
                            None => break,
                        };

                        if value0 as u16 == (self.regs.get_ax() as u16) {
                            self.flags.f_zf = true;
                            if !self.set_operand_value(&ins, 0, value1) {
                                break;
                            }
                        } else {
                            self.flags.f_zf = false;
                            self.regs.set_ax(value1 & 0xffff);
                        }
                    }

                    Mnemonic::Cmp => {
                        self.show_instruction(&self.colors.orange, &ins);


                        assert!(ins.op_count() == 2);

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let value1 = match self.get_operand_value(&ins, 1, true) {
                            Some(v) => v,
                            None => break,
                        };

                        if !self.step {
                            if value0 > value1 {
                                println!("\tcmp: 0x{:x} > 0x{:x}", value0, value1);
                            } else if value0 < value1 {
                                println!("\tcmp: 0x{:x} < 0x{:x}", value0, value1);
                            } else {
                                println!("\tcmp: 0x{:x} == 0x{:x}", value0, value1);
                            }
                        }
                        
                        if self.break_on_next_cmp {
                            self.spawn_console();
                            self.break_on_next_cmp = false;

                            let value0 = match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            let value1 = match self.get_operand_value(&ins, 1, true) {
                                Some(v) => v,
                                None => break,
                            };

                            if !self.step {
                                if value0 > value1 {
                                    println!("\tcmp: 0x{:x} > 0x{:x}", value0, value1);
                                } else if value0 < value1 {
                                    println!("\tcmp: 0x{:x} < 0x{:x}", value0, value1);
                                } else {
                                    println!("\tcmp: 0x{:x} == 0x{:x}", value0, value1);
                                }
                            }
                        }

                        match self.get_operand_sz(&ins, 0) {
                            64 => { self.flags.sub64(value0, value1); },
                            32 => { self.flags.sub32(value0, value1); },
                            16 => { self.flags.sub16(value0, value1); },
                            8 => { self.flags.sub8(value0, value1); },
                            _  => { panic!("wrong size {}", self.get_operand_sz(&ins, 0)); }
                        }

                    }

                    Mnemonic::Cmpsq => {
                        self.show_instruction(&self.colors.orange, &ins);

                        let mut value0:u64;
                        let mut value1:u64;

                   
                        if ins.has_rep_prefix() {
                            loop {
                                if self.cfg.is_64bits {
                                    value0 = self.maps.read_qword(self.regs.rsi).expect("cannot read esi");
                                    value1 = self.maps.read_qword(self.regs.rdi).expect("cannot read edi");
    
                                    if self.flags.f_df {
                                        self.regs.rsi -= 8;
                                        self.regs.rdi -= 8;
                                    } else {
                                        self.regs.rsi += 8;
                                        self.regs.rdi += 8;
                                    }
    
                                } else { // 32bits
                                    value0 = self.maps.read_qword(self.regs.get_esi()).expect("cannot read esi");
                                    value1 = self.maps.read_qword(self.regs.get_edi()).expect("cannot read edi");
    
                                    if self.flags.f_df {
                                        self.regs.set_esi(self.regs.get_esi() - 8);
                                        self.regs.set_edi(self.regs.get_edi() - 8);
                                    } else {
                                        self.regs.set_esi(self.regs.get_esi() + 8);
                                        self.regs.set_edi(self.regs.get_edi() + 8);
                                    }
                                }
    
                                self.flags.sub64(value0, value1);
    
                                if value0 > value1 {
                                    if !self.step { 
                                        println!("\tcmp: 0x{:x} > 0x{:x}", value0, value1);
                                    }
                                    break;
                                } else if value0 < value1 {
                                    if !self.step { 
                                        println!("\tcmp: 0x{:x} < 0x{:x}", value0, value1);
                                    }
                                    break;
                                } else {
                                    if !self.step {  
                                        println!("\tcmp: 0x{:x} == 0x{:x}", value0, value1);
                                    }
                                }
   

                                self.regs.rcx -= 1;
                                if self.regs.rcx == 0 {
                                    break;
                                }
                            }

                        } else { // not rep

                            if self.cfg.is_64bits {
                                value0 = self.maps.read_qword(self.regs.rsi).expect("cannot read esi");
                                value1 = self.maps.read_qword(self.regs.rdi).expect("cannot read edi");

                                if self.flags.f_df {
                                    self.regs.rsi -= 8;
                                    self.regs.rdi -= 8;
                                } else {
                                    self.regs.rsi += 8;
                                    self.regs.rdi += 8;
                                }

                            } else { // 32bits
                                value0 = self.maps.read_qword(self.regs.get_esi()).expect("cannot read esi");
                                value1 = self.maps.read_qword(self.regs.get_edi()).expect("cannot read edi");

                                if self.flags.f_df {
                                    self.regs.set_esi(self.regs.get_esi() - 8);
                                    self.regs.set_edi(self.regs.get_edi() - 8);
                                } else {
                                    self.regs.set_esi(self.regs.get_esi() + 8);
                                    self.regs.set_edi(self.regs.get_edi() + 8);
                                }
                            }

                            self.flags.sub64(value0, value1);

                            if !self.step {
                                if value0 > value1 {
                                    println!("\tcmp: 0x{:x} > 0x{:x}", value0, value1);
                                } else if value0 < value1 {
                                    println!("\tcmp: 0x{:x} < 0x{:x}", value0, value1);
                                } else {
                                    println!("\tcmp: 0x{:x} == 0x{:x}", value0, value1);
                                }
                            }

                        }
      
                    }

                    Mnemonic::Cmpsd => {
                        self.show_instruction(&self.colors.orange, &ins);

                        let mut value0:u32;
                        let mut value1:u32;

                        if ins.has_rep_prefix() {
                            loop {

                                if self.cfg.is_64bits {
                                    value0 = self.maps.read_dword(self.regs.rsi).expect("cannot read esi");
                                    value1 = self.maps.read_dword(self.regs.rdi).expect("cannot read edi");
    
                                    if self.flags.f_df {
                                        self.regs.rsi -= 4;
                                        self.regs.rdi -= 4;
                                    } else {
                                        self.regs.rsi += 4;
                                        self.regs.rdi += 4;
                                    }
    
                                } else { // 32bits
                                    value0 = self.maps.read_dword(self.regs.get_esi()).expect("cannot read esi");
                                    value1 = self.maps.read_dword(self.regs.get_edi()).expect("cannot read edi");
    
                                    if self.flags.f_df {
                                        self.regs.set_esi(self.regs.get_esi() - 4);
                                        self.regs.set_edi(self.regs.get_edi() - 4);
                                    } else {
                                        self.regs.set_esi(self.regs.get_esi() + 4);
                                        self.regs.set_edi(self.regs.get_edi() + 4);
                                    }
                                }
    
                                self.flags.sub32(value0 as u64, value1 as u64);

                                if value0 > value1 {
                                    if !self.step { 
                                        println!("\tcmp: 0x{:x} > 0x{:x}", value0, value1);
                                    }
                                    break;
                                } else if value0 < value1 {
                                    if !self.step { 
                                        println!("\tcmp: 0x{:x} < 0x{:x}", value0, value1);
                                    }
                                    break;
                                } else {
                                    if !self.step { 
                                        println!("\tcmp: 0x{:x} == 0x{:x}", value0, value1);
                                    }
                                }

                                self.regs.rcx -= 1;
                                if self.regs.rcx == 0 {
                                    break;
                                }
                            }

                        } else { // no rep

                            if self.cfg.is_64bits {
                                value0 = self.maps.read_dword(self.regs.rsi).expect("cannot read esi");
                                value1 = self.maps.read_dword(self.regs.rdi).expect("cannot read edi");

                                if self.flags.f_df {
                                    self.regs.rsi -= 4;
                                    self.regs.rdi -= 4;
                                } else {
                                    self.regs.rsi += 4;
                                    self.regs.rdi += 4;
                                }

                            } else { // 32bits
                                value0 = self.maps.read_dword(self.regs.get_esi()).expect("cannot read esi");
                                value1 = self.maps.read_dword(self.regs.get_edi()).expect("cannot read edi");

                                if self.flags.f_df {
                                    self.regs.set_esi(self.regs.get_esi() - 4);
                                    self.regs.set_edi(self.regs.get_edi() - 4);
                                } else {
                                    self.regs.set_esi(self.regs.get_esi() + 4);
                                    self.regs.set_edi(self.regs.get_edi() + 4);
                                }
                            }

                            self.flags.sub32(value0 as u64, value1 as u64);

                            if !self.step {
                                if value0 > value1 {
                                    println!("\tcmp: 0x{:x} > 0x{:x}", value0, value1);
                                } else if value0 < value1 {
                                    println!("\tcmp: 0x{:x} < 0x{:x}", value0, value1);
                                } else {
                                    println!("\tcmp: 0x{:x} == 0x{:x}", value0, value1);
                                }
                            }
                        }
      
                    }

                    Mnemonic::Cmpsw => {
                        self.show_instruction(&self.colors.orange, &ins);

                        let mut value0:u16;
                        let mut value1:u16;

                        if ins.has_rep_prefix() {
                            loop {
                                if self.cfg.is_64bits {
                                    value0 = self.maps.read_word(self.regs.rsi).expect("cannot read esi");
                                    value1 = self.maps.read_word(self.regs.rdi).expect("cannot read edi");
    
                                    if self.flags.f_df {
                                        self.regs.rsi -= 1;
                                        self.regs.rdi -= 1;
                                    } else {
                                        self.regs.rsi += 1;
                                        self.regs.rdi += 1;
                                    }
    
                                } else { // 32bits
                                    value0 = self.maps.read_word(self.regs.get_esi()).expect("cannot read esi");
                                    value1 = self.maps.read_word(self.regs.get_edi()).expect("cannot read edi");
    
                                    if self.flags.f_df {
                                        self.regs.set_esi(self.regs.get_esi() - 2);
                                        self.regs.set_edi(self.regs.get_edi() - 2);
                                    } else {
                                        self.regs.set_esi(self.regs.get_esi() + 2);
                                        self.regs.set_edi(self.regs.get_edi() + 2);
                                    }
                                }
    
                                self.flags.sub16(value0 as u64, value1 as u64);
    
                                if value0 > value1 {
                                    if !self.step { 
                                        println!("\tcmp: 0x{:x} > 0x{:x}", value0, value1);
                                    }
                                    break;
                                } else if value0 < value1 {
                                    if !self.step { 
                                        println!("\tcmp: 0x{:x} < 0x{:x}", value0, value1);
                                    }
                                    break;
                                } else {
                                    if !self.step { 
                                        println!("\tcmp: 0x{:x} == 0x{:x}", value0, value1);
                                    }
                                }


                                self.regs.rcx -= 1;
                                if self.regs.rcx == 0 {
                                    break;
                                }
                            }


                        } else {  // no rep

                            if self.cfg.is_64bits {
                                value0 = self.maps.read_word(self.regs.rsi).expect("cannot read esi");
                                value1 = self.maps.read_word(self.regs.rdi).expect("cannot read edi");

                                if self.flags.f_df {
                                    self.regs.rsi -= 1;
                                    self.regs.rdi -= 1;
                                } else {
                                    self.regs.rsi += 1;
                                    self.regs.rdi += 1;
                                }

                            } else { // 32bits
                                value0 = self.maps.read_word(self.regs.get_esi()).expect("cannot read esi");
                                value1 = self.maps.read_word(self.regs.get_edi()).expect("cannot read edi");

                                if self.flags.f_df {
                                    self.regs.set_esi(self.regs.get_esi() - 2);
                                    self.regs.set_edi(self.regs.get_edi() - 2);
                                } else {
                                    self.regs.set_esi(self.regs.get_esi() + 2);
                                    self.regs.set_edi(self.regs.get_edi() + 2);
                                }
                            }

                            self.flags.sub16(value0 as u64, value1 as u64);

                            if !self.step {
                                if value0 > value1 {
                                    println!("\tcmp: 0x{:x} > 0x{:x}", value0, value1);
                                } else if value0 < value1 {
                                    println!("\tcmp: 0x{:x} < 0x{:x}", value0, value1);
                                } else {
                                    println!("\tcmp: 0x{:x} == 0x{:x}", value0, value1);
                                }
                            }   
                        }
                    }

                    Mnemonic::Cmpsb => {
                        self.show_instruction(&self.colors.orange, &ins);

                        let mut value0:u8;
                        let mut value1:u8;

                        if ins.has_rep_prefix() {
                            
                            loop {
                                if self.cfg.is_64bits {
                                    value0 = self.maps.read_byte(self.regs.rsi).expect("cannot read esi");
                                    value1 = self.maps.read_byte(self.regs.rdi).expect("cannot read edi");
    
                                    if self.flags.f_df {
                                        self.regs.rsi -= 1;
                                        self.regs.rdi -= 1;
                                    } else {
                                        self.regs.rsi += 1;
                                        self.regs.rdi += 1;
                                    }
    
                                } else { // 32bits
                                    value0 = self.maps.read_byte(self.regs.get_esi()).expect("cannot read esi");
                                    value1 = self.maps.read_byte(self.regs.get_edi()).expect("cannot read edi");
    
                                    if self.flags.f_df {
                                        self.regs.set_esi(self.regs.get_esi() - 1);
                                        self.regs.set_edi(self.regs.get_edi() - 1);
                                    } else {
                                        self.regs.set_esi(self.regs.get_esi() + 1);
                                        self.regs.set_edi(self.regs.get_edi() + 1);
                                    }
                                }
    
                                self.flags.sub8(value0 as u64, value1 as u64);
    
                                if value0 > value1 {
                                    if !self.step { 
                                        println!("\tcmp: 0x{:x} > 0x{:x}", value0, value1);
                                    }
                                    assert!(self.flags.f_zf == false);
                                    break;
                                } else if value0 < value1 {
                                    if !self.step { 
                                        println!("\tcmp: 0x{:x} < 0x{:x}", value0, value1);
                                    }
                                    assert!(self.flags.f_zf == false);
                                    break;
                                } else {
                                    if !self.step { 
                                        println!("\tcmp: 0x{:x} == 0x{:x}", value0, value1); 
                                    }
                                    assert!(self.flags.f_zf == true);
                                }
                                
                                self.regs.rcx -= 1;
                                if self.regs.rcx == 0 {
                                    break;
                                }
                            }

                        } else { // no rep

                            if self.cfg.is_64bits {
                                value0 = self.maps.read_byte(self.regs.rsi).expect("cannot read esi");
                                value1 = self.maps.read_byte(self.regs.rdi).expect("cannot read edi");

                                if self.flags.f_df {
                                    self.regs.rsi -= 1;
                                    self.regs.rdi -= 1;
                                } else {
                                    self.regs.rsi += 1;
                                    self.regs.rdi += 1;
                                }

                            } else { // 32bits
                                value0 = self.maps.read_byte(self.regs.get_esi()).expect("cannot read esi");
                                value1 = self.maps.read_byte(self.regs.get_edi()).expect("cannot read edi");

                                if self.flags.f_df {
                                    self.regs.set_esi(self.regs.get_esi() - 1);
                                    self.regs.set_edi(self.regs.get_edi() - 1);
                                } else {
                                    self.regs.set_esi(self.regs.get_esi() + 1);
                                    self.regs.set_edi(self.regs.get_edi() + 1);
                                }
                            }

                            self.flags.sub8(value0 as u64, value1 as u64);

                            if !self.step {
                                if value0 > value1 {
                                    println!("\tcmp: 0x{:x} > 0x{:x}", value0, value1);
                                } else if value0 < value1 {
                                    println!("\tcmp: 0x{:x} < 0x{:x}", value0, value1);
                                } else {
                                    println!("\tcmp: 0x{:x} == 0x{:x}", value0, value1);
                                }
                            }
                        }
                    }


                    //branches: https://web.itu.edu.tr/kesgin/mul06/intel/instr/jxx.html
                    //          https://c9x.me/x86/html/file_module_x86_id_146.html
                    //          http://unixwiz.net/techtips/x86-jumps.html <---aqui

                    //esquema global -> https://en.wikipedia.org/wiki/X86_instruction_listings
                    // test jnle jpe jpo loopz loopnz int 0x80

                    Mnemonic::Jo => {

                        assert!(ins.op_count() == 1);

                        if self.flags.f_of {
                            self.show_instruction_taken(&self.colors.orange, &ins);

                            let addr =  match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            if self.cfg.is_64bits {
                                self.set_rip(addr, true);
                            } else {
                                self.set_eip(addr, true);
                            }
                            break;
                        } else {
                            self.show_instruction_not_taken(&self.colors.orange, &ins);
                        }
                    }

                    Mnemonic::Jno => {

                        assert!(ins.op_count() == 1);

                        if !self.flags.f_of {
                            self.show_instruction_taken(&self.colors.orange, &ins);

                            let addr =  match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            if self.cfg.is_64bits {
                                self.set_rip(addr, true);
                            } else {
                                self.set_eip(addr, true);
                            }
                            break;
                        } else {
                            self.show_instruction_not_taken(&self.colors.orange, &ins);
                        }
                    }
                    
                    Mnemonic::Js => {

                        assert!(ins.op_count() == 1);

                        if self.flags.f_sf {
                            self.show_instruction_taken(&self.colors.orange, &ins);
                            let addr =  match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            if self.cfg.is_64bits {
                                self.set_rip(addr, true);
                            } else {
                                self.set_eip(addr, true);
                            }
                            break;
                        } else {
                            self.show_instruction_not_taken(&self.colors.orange, &ins);
                        }
                    }

                    Mnemonic::Jns => {

                        assert!(ins.op_count() == 1);

                        if !self.flags.f_sf {
                            self.show_instruction_taken(&self.colors.orange, &ins);
                            let addr =  match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            if self.cfg.is_64bits {
                                self.set_rip(addr, true);
                            } else {
                                self.set_eip(addr, true);
                            }
                            break;
                        } else {
                            self.show_instruction_not_taken(&self.colors.orange, &ins);
                        }
                    }

                    Mnemonic::Je => {

                        assert!(ins.op_count() == 1);

                        if self.flags.f_zf {
                            self.show_instruction_taken(&self.colors.orange, &ins);
                            let addr =  match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            if self.cfg.is_64bits {
                                self.set_rip(addr, true);
                            } else {
                                self.set_eip(addr, true);
                            }
                            break;
                        } else {
                            self.show_instruction_not_taken(&self.colors.orange, &ins);
                        }
                    }

                    Mnemonic::Jne => {

                        assert!(ins.op_count() == 1);

                        if !self.flags.f_zf {
                            self.show_instruction_taken(&self.colors.orange, &ins);
                            let addr =  match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            if self.cfg.is_64bits {
                                self.set_rip(addr, true);
                            } else {
                                self.set_eip(addr, true);
                            }
                            break;
                        } else {
                            self.show_instruction_not_taken(&self.colors.orange, &ins);
                        }
                    }

                    Mnemonic::Jb => {
          
                        assert!(ins.op_count() == 1);

                        if self.flags.f_cf {
                            self.show_instruction_taken(&self.colors.orange, &ins);
                            let addr =  match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            if self.cfg.is_64bits {
                                self.set_rip(addr, true);
                            } else {
                                self.set_eip(addr, true);
                            }
                            break;
                        } else {
                            self.show_instruction_not_taken(&self.colors.orange, &ins);
                        }
                    }

                    Mnemonic::Jae => {
        
                        assert!(ins.op_count() == 1);

                        if !self.flags.f_cf {
                            self.show_instruction_taken(&self.colors.orange, &ins);
                            let addr =  match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            if self.cfg.is_64bits {
                                self.set_rip(addr, true);
                            } else {
                                self.set_eip(addr, true);
                            }
                            break;
                        } else {
                            self.show_instruction_not_taken(&self.colors.orange, &ins);
                        }
                    }

                    Mnemonic::Jbe => {
         
                        assert!(ins.op_count() == 1);

                        if self.flags.f_cf || self.flags.f_zf {
                            self.show_instruction_taken(&self.colors.orange, &ins);
                            let addr =  match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            if self.cfg.is_64bits {
                                self.set_rip(addr, true);
                            } else {
                                self.set_eip(addr, true);
                            }
                            break;
                        } else {
                            self.show_instruction_not_taken(&self.colors.orange, &ins);
                        }
                    }

                    Mnemonic::Ja => {

                        assert!(ins.op_count() == 1);

                        if !self.flags.f_cf && !self.flags.f_zf {
                            self.show_instruction_taken(&self.colors.orange, &ins);
                            let addr =  match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            if self.cfg.is_64bits {
                                self.set_rip(addr, true);
                            } else {
                                self.set_eip(addr, true);
                            }
                            break;
                        } else {
                            self.show_instruction_not_taken(&self.colors.orange, &ins);
                        }
                    }

                    Mnemonic::Jl => {
                
                        assert!(ins.op_count() == 1);

                        if self.flags.f_sf != self.flags.f_of {
                            self.show_instruction_taken(&self.colors.orange, &ins);
                            let addr =  match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            if self.cfg.is_64bits {
                                self.set_rip(addr, true);
                            } else {
                                self.set_eip(addr, true);
                            }
                            break;
                        } else {
                            self.show_instruction_not_taken(&self.colors.orange, &ins);
                        }
                    }

                    Mnemonic::Jge => {
                        
                        assert!(ins.op_count() == 1);

                        if self.flags.f_sf == self.flags.f_of {
                            self.show_instruction_taken(&self.colors.orange, &ins);
                            let addr =  match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            if self.cfg.is_64bits {
                                self.set_rip(addr, true);
                            } else {
                                self.set_eip(addr, true);
                            }
                            break;
                        } else {
                            self.show_instruction_not_taken(&self.colors.orange, &ins);
                        }
                    }

                    Mnemonic::Jle => {
             
                        assert!(ins.op_count() == 1);

                        if self.flags.f_zf || self.flags.f_sf != self.flags.f_of {
                            self.show_instruction_taken(&self.colors.orange, &ins);
                            let addr =  match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            if self.cfg.is_64bits {
                                self.set_rip(addr, true);
                            } else {
                                self.set_eip(addr, true);
                            }
                            break;
                        } else {
                            self.show_instruction_not_taken(&self.colors.orange, &ins);
                        }
                    }

                    Mnemonic::Jg => {
                
                        assert!(ins.op_count() == 1);

                        if !self.flags.f_zf && self.flags.f_sf == self.flags.f_of {
                            self.show_instruction_taken(&self.colors.orange, &ins);
                            let addr =  match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            if self.cfg.is_64bits {
                                self.set_rip(addr, true);
                            } else {
                                self.set_eip(addr, true);
                            }
                            break;
                        } else {
                            self.show_instruction_not_taken(&self.colors.orange, &ins);
                        }
                    }

                    Mnemonic::Jp => {

                        assert!(ins.op_count() == 1);

                        if self.flags.f_pf {
                            self.show_instruction_taken(&self.colors.orange, &ins);
                            let addr =  match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            if self.cfg.is_64bits {
                                self.set_rip(addr, true);
                            } else {
                                self.set_eip(addr, true);
                            }
                            break;
                        } else {
                            self.show_instruction_not_taken(&self.colors.orange, &ins);
                        }
                    }

                    Mnemonic::Jnp => {

                        assert!(ins.op_count() == 1);

                        if !self.flags.f_pf {
                            self.show_instruction_taken(&self.colors.orange, &ins);
                            let addr =  match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            if self.cfg.is_64bits {
                                self.set_rip(addr, true);
                            } else {
                                self.set_eip(addr, true);
                            }
                            break;
                        } else {
                            self.show_instruction_not_taken(&self.colors.orange, &ins);
                        }
                    }

                    Mnemonic::Jcxz => {

                        assert!(ins.op_count() == 1);

                        if self.regs.get_cx() == 0 {
                            self.show_instruction_taken(&self.colors.orange, &ins);
                            let addr =  match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            if self.cfg.is_64bits {
                                self.set_rip(addr, true);
                            } else {
                                self.set_eip(addr, true);
                            }
                            break;
                        } else {
                            self.show_instruction_not_taken(&self.colors.orange, &ins);
                        }
                    }

                    Mnemonic::Jecxz => {

                        assert!(ins.op_count() == 1);

                        if self.regs.get_cx() == 0 {
                            self.show_instruction_taken(&self.colors.orange, &ins);
                            let addr =  match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            if self.cfg.is_64bits {
                                self.set_rip(addr, true);
                            } else {
                                self.set_eip(addr, true);
                            }
                            break;
                        } else {
                            self.show_instruction_not_taken(&self.colors.orange, &ins);
                        }
                    }

                    Mnemonic::Jrcxz => {
                        if self.regs.rcx == 0 {
                            self.show_instruction_taken(&self.colors.orange, &ins);
                            let addr =  match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            if self.cfg.is_64bits {
                                self.set_rip(addr, true);
                            } else {
                                self.set_eip(addr, true);
                            }
                            break;

                        } else {
                            self.show_instruction_not_taken(&self.colors.orange, &ins);
                        }
                    }

                    Mnemonic::Int3 => {
                        self.show_instruction(&self.colors.red, &ins);
                        println!("/!\\ int 3 sigtrap!!!!");
                        self.exception();
                        break;
                    }

                    Mnemonic::Nop => {
                        self.show_instruction(&self.colors.light_purple, &ins);
                    }

                    Mnemonic::Mfence|Mnemonic::Lfence|Mnemonic::Sfence => {
                        self.show_instruction(&self.colors.red, &ins);
                    }

                    Mnemonic::Cpuid => {
                        self.show_instruction(&self.colors.red, &ins);

                        // guloader checks bit31 which is if its hipervisor with command
                        // https://c9x.me/x86/html/file_module_x86_id_45.html
                        // TODO: implement 0x40000000 -> get the virtualization vendor

                        if self.cfg.verbose >= 1 {
                                println!("\tinput value: 0x{:x}", self.regs.rax);
                        }

                        match self.regs.rax {
                            0x00 => {
                                self.regs.rax = 16;
                                self.regs.rbx = 0x756e6547;
                                self.regs.rcx = 0x6c65746e;
                                self.regs.rdx = 0x49656e69;
                            },
                            0x01 => {
                                self.regs.rax = 0x906ed;    // Version Information (Type, Family, Model, and Stepping ID)
                                self.regs.rbx = 0x5100800;
                                self.regs.rcx = 0x7ffafbbf;
                                self.regs.rdx = 0xbfebfbff;  // feature
                            },
                            0x02 => {
                                self.regs.rax = 0x76036301;
                                self.regs.rbx = 0xf0b5ff;
                                self.regs.rcx = 0;
                                self.regs.rdx = 0xc30000;
                            },
                            0x03 => {
                                self.regs.rax = 0;
                                self.regs.rbx = 0;
                                self.regs.rcx = 0;
                                self.regs.rdx = 0;
                            },
                            0x04 => {
                                self.regs.rax = 0;
                                self.regs.rbx = 0x1c0003f;
                                self.regs.rcx = 0x3f;
                                self.regs.rdx = 0;
                            },
                            0x05 => {
                                self.regs.rax = 0x40;
                                self.regs.rbx = 0x40;
                                self.regs.rcx = 3;
                                self.regs.rdx = 0x11142120;
                            },
                            0x06 => {
                                self.regs.rax = 0x27f7;
                                self.regs.rbx = 2;
                                self.regs.rcx = 9;
                                self.regs.rdx = 0;
                            },
                            0x07..=0x6d => {
                                self.regs.rax = 0;
                                self.regs.rbx = 0;
                                self.regs.rcx = 0;
                                self.regs.rdx = 0;
                            },
                            0x6e => {
                                self.regs.rax = 0x960;
                                self.regs.rbx = 0x1388;
                                self.regs.rcx = 0x64;
                                self.regs.rdx = 0;
                            },
                            0x80000000 => {
                                self.regs.rax = 0x80000008;
                                self.regs.rbx = 0;
                                self.regs.rcx = 0;
                                self.regs.rdx = 0;
                            },
                            _ => unimplemented!("unimplemented cpuid call 0x{:x}", self.regs.rax),
                        }
                    }

                    Mnemonic::Clc => {
                        self.show_instruction(&self.colors.light_gray, &ins);
                        self.flags.f_cf = false;
                    }
                    
                    Mnemonic::Rdtsc => {
                        self.show_instruction(&self.colors.red, &ins);
                        self.regs.rdx = 0;
                        self.regs.rax = 0;
                    }

                    Mnemonic::Loop => {
                        self.show_instruction(&self.colors.yellow, &ins);

                        assert!(ins.op_count() == 1);

                        let addr = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        if addr > 0xffffffff {
                            if self.regs.rcx == 0 {
                                self.regs.rcx = 0xffffffffffffffff;
                            } else {
                                self.regs.rcx -= 1;
                            }

                            if self.regs.rcx > 0 {
                                self.set_rip(addr, false);
                                break;
                            }
                            
                        } else if addr > 0xffff {
                            if self.regs.get_ecx() == 0 {
                                self.regs.set_ecx(0xffffffff);
                            } else {
                                self.regs.set_ecx(self.regs.get_ecx() - 1);
                            }

                            if self.regs.get_ecx() > 0 {
                                if self.cfg.is_64bits {
                                    self.set_rip(addr, false);
                                } else {
                                    self.set_eip(addr, false);
                                }
                                break;
                            }

                        } else {
                            if self.regs.get_cx() == 0 {
                                self.regs.set_cx(0xffff);
                            } else {
                                self.regs.set_cx(self.regs.get_cx() -1);
                            }
                
                            if self.regs.get_cx() > 0 {
                                if self.cfg.is_64bits {
                                    self.set_rip(addr, false);
                                } else {
                                    self.set_eip(addr, false);
                                }
                                break;
                            }
                        }
                    }
    
                    Mnemonic::Loope => {
                        self.show_instruction(&self.colors.yellow, &ins);

                        assert!(ins.op_count() == 1);

                        let addr = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        if addr > 0xffffffff {
                            if self.regs.rcx == 0 {
                                self.regs.rcx = 0xffffffffffffffff;
                            } else {
                                self.regs.rcx -= 1;
                            }
                            
                            if self.regs.rcx > 0 && self.flags.f_zf {
                                self.set_rip(addr, false);
                                break;
                            }
                        } else if addr > 0xffff {
                            if self.regs.get_ecx() == 0 {
                                self.regs.set_ecx(0xffffffff);
                            } else {
                                self.regs.set_ecx(self.regs.get_ecx() - 1);
                            }
                            
                            if self.regs.get_ecx() > 0 && self.flags.f_zf {
                                if self.cfg.is_64bits {
                                    self.set_rip(addr, false);
                                } else {
                                    self.set_eip(addr, false);
                                }
                                break;
                            }
                        } else {
                            if self.regs.get_cx() == 0 {
                                self.regs.set_cx(0xffff);
                            } else {
                                self.regs.set_cx(self.regs.get_cx() - 1);
                            }
                            
                            if self.regs.get_cx() > 0 && self.flags.f_zf  {
                                if self.cfg.is_64bits {
                                    self.set_rip(addr, false);
                                } else {
                                    self.set_eip(addr, false);
                                }
                                break;
                            }
                        }
                    }

                    Mnemonic::Loopne => {
                        self.show_instruction(&self.colors.yellow, &ins);

                        assert!(ins.op_count() == 1);

                        let addr = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        if addr > 0xffffffff {
                            if self.regs.rcx == 0 {
                                self.regs.rcx = 0xffffffffffffffff;
                            } else {
                                self.regs.rcx -= 1;
                            }
                            
                            if self.regs.rcx > 0 && !self.flags.f_zf {
                                self.set_rip(addr, false);
                                break;
                            }

                        } else if addr > 0xffff {
                            if self.regs.get_ecx() == 0 {
                                self.regs.set_ecx(0xffffffff);
                            } else {
                                self.regs.set_ecx(self.regs.get_ecx() - 1);
                            }
                            
                            if self.regs.get_ecx() > 0 && !self.flags.f_zf {
                                if self.cfg.is_64bits {
                                    self.set_rip(addr, false);
                                } else {
                                    self.set_eip(addr, false);
                                }
                                break;
                            }

                        } else {
                            if self.regs.get_cx() == 0 {
                                self.regs.set_cx(0xffff);
                            } else {
                                self.regs.set_cx(self.regs.get_cx() -1);
                            }
                            
                            if self.regs.get_cx() > 0 && !self.flags.f_zf  {
                                if self.cfg.is_64bits {
                                    self.set_rip(addr, false);
                                } else {
                                    self.set_eip(addr, false);
                                }
                                break;
                            }
                        }
                    }

                    Mnemonic::Lea => {
                        self.show_instruction(&self.colors.light_cyan, &ins);

                        assert!(ins.op_count() == 2);

                        let value1 = match self.get_operand_value(&ins, 1, false) {
                            Some(v) => v,
                            None => break,
                        };

                        if !self.set_operand_value(&ins, 0, value1) {
                            break;
                        }
                    }

                    Mnemonic::Leave => {
                        self.show_instruction(&self.colors.red, &ins);

                        if self.cfg.is_64bits {
                            self.regs.rsp = self.regs.rbp;
                            self.regs.rbp = self.stack_pop64(true);
                        } else {
                            self.regs.set_esp(self.regs.get_ebp());
                            let val = self.stack_pop32(true);
                            self.regs.set_ebp(val as u64);
                        }
                    }

                    Mnemonic::Int => {
                        self.show_instruction(&self.colors.red, &ins);

                        assert!(ins.op_count() == 1);

                        let interrupt = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        match interrupt {
                            0x80 => syscall32::gateway(self),
                            _ => unimplemented!("interrupt {}", interrupt),
                        }
                    }

                    Mnemonic::Syscall => {
                        self.show_instruction(&self.colors.red, &ins);

                        syscall64::gateway(self);
                    }

                    Mnemonic::Std => {
                        self.show_instruction(&self.colors.blue, &ins);
                        self.flags.f_df = true;
                    }

                    Mnemonic::Stc => {
                        self.show_instruction(&self.colors.blue, &ins);
                        self.flags.f_cf = true;
                    }

                    Mnemonic::Cmc => {
                        self.show_instruction(&self.colors.blue, &ins);
                        self.flags.f_cf = !self.flags.f_cf;
                    }

                    Mnemonic::Cld => {
                        self.show_instruction(&self.colors.blue, &ins);
                        self.flags.f_df = false;
                    }

                    Mnemonic::Lodsq => {
                        self.show_instruction(&self.colors.cyan, &ins);
                        //TODO: crash if arrive to zero or max value
                        
                        if self.cfg.is_64bits {
                            let val = match self.maps.read_qword(self.regs.rsi) {
                                Some(v) => v,
                                None => panic!("lodsq: memory read error"),
                            };

                            self.regs.rax = val;
                            if self.flags.f_df {
                                self.regs.rsi -= 8; 
                            } else {
                                self.regs.rsi += 8;
                            }

                        } else {
                            unreachable!("lodsq dont exists in 32bit");
                        }
                    }

                    Mnemonic::Lodsd => {
                        self.show_instruction(&self.colors.cyan, &ins);
                        //TODO: crash if arrive to zero or max value
                        
                        if self.cfg.is_64bits {
                            let val = match self.maps.read_dword(self.regs.rsi) {
                                Some(v) => v,
                                None => panic!("lodsd: memory read error"),
                            };

                            self.regs.set_eax(val as u64);
                            if self.flags.f_df {
                                self.regs.rsi -= 4; 
                            } else {
                                self.regs.rsi += 4;
                            }

                        } else {

                            let val = match self.maps.read_dword(self.regs.get_esi()) {
                                Some(v) => v,
                                None => panic!("lodsd: memory read error"),
                            };

                            self.regs.set_eax(val as u64);
                            if self.flags.f_df {
                                self.regs.set_esi(self.regs.get_esi() - 4);
                            } else {
                                self.regs.set_esi(self.regs.get_esi() + 4);
                            }
                        }
                    }

                    Mnemonic::Lodsw => {
                        self.show_instruction(&self.colors.cyan, &ins);
                        //TODO: crash if rsi arrive to zero or max value
                        
                        if self.cfg.is_64bits {
                            let val = match self.maps.read_word(self.regs.rsi) {
                                Some(v) => v,
                                None => panic!("lodsw: memory read error 0x{:x}", self.regs.rsi),
                            };

                            self.regs.set_ax(val as u64);
                            if self.flags.f_df {
                                self.regs.rsi -= 2;
                            } else {
                                self.regs.rsi += 2;
                            }

                        } else {

                            let val = match self.maps.read_word(self.regs.get_esi()) {
                                Some(v) => v,
                                None => panic!("lodsw: memory read error"),
                            };

                            self.regs.set_ax(val as u64);
                            if self.flags.f_df {
                                self.regs.set_esi(self.regs.get_esi() - 2);
                            } else {
                                self.regs.set_esi(self.regs.get_esi() + 2);
                            }
                        }
                    }

                    Mnemonic::Lodsb => {
                        self.show_instruction(&self.colors.cyan, &ins);
                        //TODO: crash if arrive to zero or max value
                        
                        if self.cfg.is_64bits {
                            let val = match self.maps.read_byte(self.regs.rsi) {
                                Some(v) => v,
                                None => {
                                    println!("lodsb: memory read error");
                                    self.spawn_console();
                                    0
                                }
                            };

                            self.regs.set_al(val as u64);
                            if self.flags.f_df {
                                self.regs.rsi -= 1;
                            } else {
                                self.regs.rsi += 1;
                            }

                        } else {

                            let val = match self.maps.read_byte(self.regs.get_esi()) {
                                Some(v) => v,
                                None => {   
                                    println!("lodsb: memory read error");
                                    self.spawn_console();
                                    0
                                }
                            };

                            self.regs.set_al(val as u64);
                            if self.flags.f_df {
                                self.regs.set_esi(self.regs.get_esi() - 1);
                            } else {
                                self.regs.set_esi(self.regs.get_esi() + 1);
                            }
                        }
                    }

                    Mnemonic::Cbw => {
                        self.show_instruction(&self.colors.green, &ins);

                        let sigextend = self.regs.get_al() as u8 as i8 as i16 as u16;
                        self.regs.set_ax(sigextend as u64);
                    }

                    Mnemonic::Cwde => {
                        self.show_instruction(&self.colors.green, &ins);

                        let sigextend = self.regs.get_ax() as u16 as i16 as i32 as u32;
                        
                        self.regs.set_eax(sigextend as u64);
                    }

                    Mnemonic::Cwd => {
                        self.show_instruction(&self.colors.green, &ins);

                        let sigextend = self.regs.get_ax() as u16 as i16 as i32 as u32;
                        self.regs.set_ax((sigextend & 0x0000ffff) as u64);
                        self.regs.set_dx(((sigextend & 0xffff0000) >> 16) as u64); 
                    }
        

                    ///// FPU /////  https://github.com/radare/radare/blob/master/doc/xtra/fpu
                     
                    Mnemonic::Ffree => {
                        self.show_instruction(&self.colors.green, &ins);
                  
                        match ins.op_register(0) {
                            Register::ST0 => self.fpu.clear_st(0),
                            Register::ST1 => self.fpu.clear_st(1),
                            Register::ST2 => self.fpu.clear_st(2),
                            Register::ST3 => self.fpu.clear_st(3),
                            Register::ST4 => self.fpu.clear_st(4),
                            Register::ST5 => self.fpu.clear_st(5),
                            Register::ST6 => self.fpu.clear_st(6),
                            Register::ST7 => self.fpu.clear_st(7),
                            _  => unimplemented!("impossible case"),
                        }
                       
                        self.fpu.set_ip(self.regs.rip);
                    }

                    Mnemonic::Fnstenv => {
                        self.show_instruction(&self.colors.green, &ins);

                        let addr = match self.get_operand_value(&ins, 0, false) {
                            Some(v) => v,
                            None => break,
                        };

                        if self.cfg.is_64bits {
                            let env = self.fpu.get_env64();

                            for i in 0..4 {
                                self.maps.write_qword(addr+(i*4), env[i as usize]);
                            }

                        } else {

                            let env = self.fpu.get_env32();
                            for i in 0..4 {
                                self.maps.write_dword(addr+(i*4), env[i as usize]);
                            }
                        }

                        self.fpu.set_ip(self.regs.rip);
                    }
    
                    Mnemonic::Fld => {
                        self.show_instruction(&self.colors.green, &ins);

                        self.fpu.set_ip(self.regs.rip);
                    }

                    Mnemonic::Fldz => {
                        self.show_instruction(&self.colors.green, &ins);

                        self.fpu.push(0.0);
                        self.fpu.set_ip(self.regs.rip);
                    }

                    Mnemonic::Fld1 => {
                        self.show_instruction(&self.colors.green, &ins);

                        self.fpu.push(1.0);
                        self.fpu.set_ip(self.regs.rip);
                    }

                    Mnemonic::Fldpi => {
                        self.show_instruction(&self.colors.green, &ins);

                        self.fpu.push(std::f32::consts::PI);
                        self.fpu.set_ip(self.regs.rip);
                    }

                    Mnemonic::Fldl2t => {
                        self.show_instruction(&self.colors.green, &ins);

                        self.fpu.push(10f32.log2());
                        self.fpu.set_ip(self.regs.rip);
                    }

                    Mnemonic::Fldlg2 => {
                        self.show_instruction(&self.colors.green, &ins);

                        self.fpu.push(2f32.log10());
                        self.fpu.set_ip(self.regs.rip);
                    }

                    Mnemonic::Fldln2 => {
                        self.show_instruction(&self.colors.green, &ins);

                        self.fpu.push(2f32.log(std::f32::consts::E));
                        self.fpu.set_ip(self.regs.rip);
                    }

                    Mnemonic::Fldl2e => {
                        self.show_instruction(&self.colors.green, &ins);

                        self.fpu.push(std::f32::consts::E.log2());
                        self.fpu.set_ip(self.regs.rip);
                    }

                    Mnemonic::Fcmove => {
                        self.show_instruction(&self.colors.green, &ins);

                        if self.flags.f_zf {
                            match ins.op_register(0) {
                                Register::ST0 => self.fpu.move_to_st0(0),
                                Register::ST1 => self.fpu.move_to_st0(1),
                                Register::ST2 => self.fpu.move_to_st0(2),
                                Register::ST3 => self.fpu.move_to_st0(3),
                                Register::ST4 => self.fpu.move_to_st0(4),
                                Register::ST5 => self.fpu.move_to_st0(5),
                                Register::ST6 => self.fpu.move_to_st0(6),
                                Register::ST7 => self.fpu.move_to_st0(7),
                                _  => unimplemented!("impossible case"),
                            }
                        }

                        self.fpu.set_ip(self.regs.rip);
                    }

                    Mnemonic::Fcmovb => {
                        self.show_instruction(&self.colors.green, &ins);

                        if self.flags.f_cf {
                            match ins.op_register(0) {
                                Register::ST0 => self.fpu.move_to_st0(0),
                                Register::ST1 => self.fpu.move_to_st0(1),
                                Register::ST2 => self.fpu.move_to_st0(2),
                                Register::ST3 => self.fpu.move_to_st0(3),
                                Register::ST4 => self.fpu.move_to_st0(4),
                                Register::ST5 => self.fpu.move_to_st0(5),
                                Register::ST6 => self.fpu.move_to_st0(6),
                                Register::ST7 => self.fpu.move_to_st0(7),
                                _  => unimplemented!("impossible case"),
                            }
                        }

                        self.fpu.set_ip(self.regs.rip);
                    }

                    Mnemonic::Fcmovbe => {
                        self.show_instruction(&self.colors.green, &ins);

                        if self.flags.f_cf || self.flags.f_zf {
                            match ins.op_register(0) {
                                Register::ST0 => self.fpu.move_to_st0(0),
                                Register::ST1 => self.fpu.move_to_st0(1),
                                Register::ST2 => self.fpu.move_to_st0(2),
                                Register::ST3 => self.fpu.move_to_st0(3),
                                Register::ST4 => self.fpu.move_to_st0(4),
                                Register::ST5 => self.fpu.move_to_st0(5),
                                Register::ST6 => self.fpu.move_to_st0(6),
                                Register::ST7 => self.fpu.move_to_st0(7),
                                _  => unimplemented!("impossible case"),
                            }
                        }

                        self.fpu.set_ip(self.regs.rip);
                    }

                    Mnemonic::Fcmovu => {
                        self.show_instruction(&self.colors.green, &ins);

                        if self.flags.f_pf {
                            match ins.op_register(0) {
                                Register::ST0 => self.fpu.move_to_st0(0),
                                Register::ST1 => self.fpu.move_to_st0(1),
                                Register::ST2 => self.fpu.move_to_st0(2),
                                Register::ST3 => self.fpu.move_to_st0(3),
                                Register::ST4 => self.fpu.move_to_st0(4),
                                Register::ST5 => self.fpu.move_to_st0(5),
                                Register::ST6 => self.fpu.move_to_st0(6),
                                Register::ST7 => self.fpu.move_to_st0(7),
                                _  => unimplemented!("impossible case"),
                            }
                        }

                        self.fpu.set_ip(self.regs.rip);
                    }

                    Mnemonic::Fcmovnb => {
                        self.show_instruction(&self.colors.green, &ins);

                        if !self.flags.f_cf {
                            match ins.op_register(0) {
                                Register::ST0 => self.fpu.move_to_st0(0),
                                Register::ST1 => self.fpu.move_to_st0(1),
                                Register::ST2 => self.fpu.move_to_st0(2),
                                Register::ST3 => self.fpu.move_to_st0(3),
                                Register::ST4 => self.fpu.move_to_st0(4),
                                Register::ST5 => self.fpu.move_to_st0(5),
                                Register::ST6 => self.fpu.move_to_st0(6),
                                Register::ST7 => self.fpu.move_to_st0(7),
                                _  => unimplemented!("impossible case"),
                            }
                        }

                        self.fpu.set_ip(self.regs.rip);
                    }

                    Mnemonic::Fcmovne => {
                        self.show_instruction(&self.colors.green, &ins);

                        if !self.flags.f_zf {
                            match ins.op_register(0) {
                                Register::ST0 => self.fpu.move_to_st0(0),
                                Register::ST1 => self.fpu.move_to_st0(1),
                                Register::ST2 => self.fpu.move_to_st0(2),
                                Register::ST3 => self.fpu.move_to_st0(3),
                                Register::ST4 => self.fpu.move_to_st0(4),
                                Register::ST5 => self.fpu.move_to_st0(5),
                                Register::ST6 => self.fpu.move_to_st0(6),
                                Register::ST7 => self.fpu.move_to_st0(7),
                                _  => unimplemented!("impossible case"),
                            }
                        }

                        self.fpu.set_ip(self.regs.rip);
                    }

                    Mnemonic::Fcmovnbe => {
                        self.show_instruction(&self.colors.green, &ins);

                        if !self.flags.f_cf && !self.flags.f_zf {
                            match ins.op_register(0) {
                                Register::ST0 => self.fpu.move_to_st0(0),
                                Register::ST1 => self.fpu.move_to_st0(1),
                                Register::ST2 => self.fpu.move_to_st0(2),
                                Register::ST3 => self.fpu.move_to_st0(3),
                                Register::ST4 => self.fpu.move_to_st0(4),
                                Register::ST5 => self.fpu.move_to_st0(5),
                                Register::ST6 => self.fpu.move_to_st0(6),
                                Register::ST7 => self.fpu.move_to_st0(7),
                                _  => unimplemented!("impossible case"),
                            }
                        }

                        self.fpu.set_ip(self.regs.rip);
                    }

                    Mnemonic::Fcmovnu => {
                        self.show_instruction(&self.colors.green, &ins);

                        if !self.flags.f_pf {
                            match ins.op_register(0) {
                                Register::ST0 => self.fpu.move_to_st0(0),
                                Register::ST1 => self.fpu.move_to_st0(1),
                                Register::ST2 => self.fpu.move_to_st0(2),
                                Register::ST3 => self.fpu.move_to_st0(3),
                                Register::ST4 => self.fpu.move_to_st0(4),
                                Register::ST5 => self.fpu.move_to_st0(5),
                                Register::ST6 => self.fpu.move_to_st0(6),
                                Register::ST7 => self.fpu.move_to_st0(7),
                                _  => unimplemented!("impossible case"),
                            }
                        }

                        self.fpu.set_ip(self.regs.rip);
                    }

                    Mnemonic::Fxch => {
                        self.show_instruction(&self.colors.blue, &ins);
                        match ins.op_register(1) {  
                            Register::ST0 => self.fpu.xchg_st(0),  
                            Register::ST1 => self.fpu.xchg_st(1),  
                            Register::ST2 => self.fpu.xchg_st(2),  
                            Register::ST3 => self.fpu.xchg_st(3),  
                            Register::ST4 => self.fpu.xchg_st(4),  
                            Register::ST5 => self.fpu.xchg_st(5),  
                            Register::ST6 => self.fpu.xchg_st(6),  
                            Register::ST7 => self.fpu.xchg_st(7),  
                            _  => unimplemented!("impossible case"),  
                        }

                        self.fpu.set_ip(self.regs.rip);
                    }

                    Mnemonic::Popf => {
                        self.show_instruction(&self.colors.blue, &ins);

                        let flags:u16 = match self.maps.read_word(self.regs.rsp) {
                            Some(v) => v,
                            None => {
                                eprintln!("popf cannot read the stack");
                                self.exception();
                                break;
                            }
                        };

                        let flags2:u32 = (self.flags.dump() & 0xffff0000) + (flags as u32);
                        self.flags.load(flags2);
                        self.regs.rsp += 2;
                    }

                    Mnemonic::Popfd => {
                        self.show_instruction(&self.colors.blue, &ins);
                        
                        let flags = self.stack_pop32(true);
                        self.flags.load(flags);
                    }

                    Mnemonic::Daa => {
                        self.show_instruction(&self.colors.green, &ins);

                        let old_al = self.regs.get_al();
                        let old_cf = self.flags.f_cf;
                        self.flags.f_cf = false;
                        
                        if (self.regs.get_al() & 0x0f > 9) || self.flags.f_af  {
                            let sum = self.regs.get_al() + 6;
                            self.regs.set_al(sum & 0xff);
                            if sum > 0xff {
                                self.flags.f_cf = true;
                            } else {
                                self.flags.f_cf = old_cf;
                            }
                        
                            self.flags.f_af = true;
                        } else {
                            self.flags.f_af = false;
                        }

                        if old_al > 0x99 || old_cf {
                            self.regs.set_al(self.regs.get_al() + 0x60);
                            self.flags.f_cf = true;
                        } else {
                            self.flags.f_cf = false;
                        }

                    }

                    Mnemonic::Shld => {
                        self.show_instruction(&self.colors.green, &ins);

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let value1 = match self.get_operand_value(&ins, 1, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let counter = match self.get_operand_value(&ins, 2, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let sz = self.get_operand_sz(&ins, 0);
                        let result = self.shld(value0, value1, counter, sz);

                        //println!("0x{:x} SHLD 0x{:x}, 0x{:x}, 0x{:x} = 0x{:x}", ins.ip32(), value0, value1, counter, result);

                        if !self.set_operand_value(&ins, 0, result) {
                            break;
                        }
                    }

                    Mnemonic::Shrd => {
                        self.show_instruction(&self.colors.green, &ins);

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let value1 = match self.get_operand_value(&ins, 1, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let counter = match self.get_operand_value(&ins, 2, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let sz = self.get_operand_sz(&ins, 0);
                        let result = self.shrd(value0, value1, counter, sz);
                        
                        //println!("0x{:x} SHRD 0x{:x}, 0x{:x}, 0x{:x} = 0x{:x}", ins.ip32(), value0, value1, counter, result);
                        
                        if !self.set_operand_value(&ins, 0, result) {
                            break;
                        }
                    }


                    Mnemonic::Sysenter => {
                        println!("{}{} 0x{:x}: {}{}", self.colors.red, self.pos, ins.ip(), self.out, self.colors.nc);
                        return;
                    }

                    //// SSE XMM //// 
                    // scalar: only gets the less significative part.
                    // scalar simple: only 32b less significative part.
                    // scalar double: only 54b less significative part.
                    // packed: compute all parts.
                    // packed double: 
                    //


                    Mnemonic::Pxor => {
                        self.show_instruction(&self.colors.green, &ins);

                        assert!(ins.op_count() == 2);

                        let value0 = self.get_operand_xmm_value_128(&ins, 0, true).expect("error getting xmm value0");
                        let value1 = self.get_operand_xmm_value_128(&ins, 0, true).expect("error getting xmm value1");

                        let result:u128 = value0 ^ value1;
                        self.flags.calc_flags(result as u64, 32);

                        self.set_operand_xmm_value_128(&ins, 0, result);
                    }

                    Mnemonic::Xorps => {
                        self.show_instruction(&self.colors.green, &ins);

                        let value0 = self.get_operand_xmm_value_128(&ins, 0, true).expect("error getting value0");
                        let value1 = self.get_operand_xmm_value_128(&ins, 1, true).expect("error getting velue1");

                        let a:u128 = (value0 & 0xffffffff) ^ (value1 & 0xffffffff);
                        let b:u128 = (value0 & 0xffffffff_00000000) ^ (value1 & 0xffffffff_00000000);
                        let c:u128 = (value0 & 0xffffffff_00000000_00000000) ^ (value1 & 0xffffffff_00000000_00000000);
                        let d:u128 = (value0 & 0xffffffff_00000000_00000000_00000000) ^ (value1 & 0xffffffff_00000000_00000000_00000000); 

                        let result:u128 = a | b | c | d;

                        self.set_operand_xmm_value_128(&ins, 0, result);
                    }

                    Mnemonic::Xorpd => {
                        self.show_instruction(&self.colors.green, &ins);

                        let value0 = self.get_operand_xmm_value_128(&ins, 0, true).expect("error getting value0");
                        let value1 = self.get_operand_xmm_value_128(&ins, 1, true).expect("error getting velue1");

                        let a:u128 = (value0 & 0xffffffff_ffffffff) ^ (value1 & 0xffffffff_ffffffff);
                        let b:u128 = (value0 & 0xffffffff_ffffffff_00000000_00000000) ^ (value1 & 0xffffffff_ffffffff_00000000_00000000);
                        let result:u128 = a | b;

                        self.set_operand_xmm_value_128(&ins, 0, result);
                    }
                   
                    // movlpd: packed double, movlps: packed simple, cvtsi2sd: int to scalar double 32b to 64b,
                    // cvtsi2ss: int to scalar single copy 32b to 32b, movd: doubleword move
                    Mnemonic::Movlpd | Mnemonic::Movlps | Mnemonic::Cvtsi2sd | Mnemonic::Cvtsi2ss | Mnemonic::Movd => {
                        self.show_instruction(&self.colors.cyan, &ins);

                        let sz0 = self.get_operand_sz(&ins, 0);
                        let sz1 = self.get_operand_sz(&ins, 1);

                        if sz0 == 128 && sz1 == 128 {
                           let value1 = self.get_operand_xmm_value_128(&ins, 1, true).expect("error getting xmm value1"); 
                           self.set_operand_xmm_value_128(&ins, 0, value1);

                        } else if sz0 == 128 && sz1 == 32 {
                            let value1 = self.get_operand_value(&ins, 1, true).expect("error getting value1");
                            self.set_operand_xmm_value_128(&ins, 0, value1 as u128);

                        } else if sz0 == 32 && sz1 == 128 {
                            let value1 = self.get_operand_xmm_value_128(&ins, 1, true).expect("error getting xmm value1"); 
                            self.set_operand_value(&ins, 0, value1 as u64);

                        } else if sz0 == 128 && sz1 == 64 {
                            let addr = self.get_operand_value(&ins, 1, false).expect("error getting the address");
                            let value1 = self.maps.read_qword(addr).expect("error getting qword");
                            self.set_operand_xmm_value_128(&ins, 0, value1 as u128);

                        } else if sz0 == 64 && sz1 == 128 {
                            let value1 = self.get_operand_xmm_value_128(&ins, 1, true).expect("error getting xmm value");
                            self.set_operand_value(&ins, 0, value1 as u64);

                        } else {
                            panic!("SSE with other size combinations sz0:{} sz1:{}", sz0, sz1);
                        }
                    }


                    Mnemonic::Movdqa => {
                        self.show_instruction(&self.colors.green, &ins);

                        assert!(ins.op_count() == 2);

                        let sz0 = self.get_operand_sz(&ins, 0);
                        let sz1 = self.get_operand_sz(&ins, 1);

                        if sz0 == 32 && sz1 == 128 {
                            let xmm = self.get_operand_xmm_value_128(&ins, 1, true).expect("error getting xmm value");
                            let addr = self.get_operand_value(&ins, 0, false).expect("error getting address");
                            //println!("addr: 0x{:x} value: 0x{:x}", addr, xmm);
                            self.maps.write_dword(addr, ((xmm & 0xffffffff_00000000_00000000_00000000) >> (12*8)) as u32 );
                            self.maps.write_dword(addr+4, ((xmm & 0xffffffff_00000000_00000000) >> (8*8)) as u32 );
                            self.maps.write_dword(addr+8, ((xmm & 0xffffffff_00000000) >> (4*8)) as u32 );
                            self.maps.write_dword(addr+12, (xmm & 0xffffffff) as u32 );

                        } else if sz0 == 128 && sz1 == 32 {
                            let addr = self.get_operand_value(&ins, 1, false).expect("error reading address in movdqa");
                            let b1 = match self.maps.read_dword(addr) {
                                Some(v) => v,
                                None => panic!("error reading b1 in movdqa"),
                            };
                            let b2 = match self.maps.read_dword(addr+4) {
                                Some(v) => v,
                                None => panic!("error reading b2 in movdqa"),
                            };
                            let b3 = match self.maps.read_dword(addr+8) {
                                Some(v) => v,
                                None => panic!("error reading b3 in movdqa"),
                            };
                            let b4 = match self.maps.read_dword(addr+12) {
                                Some(v) => v,
                                None => panic!("error reading b4 in movdqa"),
                            };

                            let r1 :u128 = b1 as u128;
                            let r2 :u128 = b2 as u128;
                            let r3 :u128 = b3 as u128;
                            let r4 :u128 = b4 as u128;

                            self.set_operand_xmm_value_128(&ins, 0, r1 << (12*8) | r2 << (8*8) | r3 << (4*8) | r4);

                        } else {
                            println!("sz0: {}  sz1: {}\n", sz0, sz1);
                            unimplemented!("movdqa");
                        }
                    }
                    

                    Mnemonic::Andpd => {
                        self.show_instruction(&self.colors.green, &ins);

                        let value0 = self.get_operand_xmm_value_128(&ins, 0, true).expect("error getting value0");
                        let value1 = self.get_operand_xmm_value_128(&ins, 1, true).expect("error getting velue1");

                        let result:u128 = value0 & value1;

                        self.set_operand_xmm_value_128(&ins, 0, result);
                    }

                    Mnemonic::Orpd => {
                        self.show_instruction(&self.colors.green, &ins);

                        let value0 = self.get_operand_xmm_value_128(&ins, 0, true).expect("error getting value0");
                        let value1 = self.get_operand_xmm_value_128(&ins, 1, true).expect("error getting velue1");

                        let result:u128 = value0 | value1;

                        self.set_operand_xmm_value_128(&ins, 0, result);
                    }

                    Mnemonic::Addps => {
                        self.show_instruction(&self.colors.green, &ins);

                        let value0 = self.get_operand_xmm_value_128(&ins, 0, true).expect("error getting value0");
                        let value1 = self.get_operand_xmm_value_128(&ins, 1, true).expect("error getting velue1");

                        let a:u128 = (value0 & 0xffffffff) + (value1 & 0xffffffff);
                        let b:u128 = (value0 & 0xffffffff_00000000) + (value1 & 0xffffffff_00000000);
                        let c:u128 = (value0 & 0xffffffff_00000000_00000000) + (value1 & 0xffffffff_00000000_00000000);
                        let d:u128 = (value0 & 0xffffffff_00000000_00000000_00000000) + (value1 & 0xffffffff_00000000_00000000_00000000); 

                        let result:u128 = a | b | c | d;

                        self.set_operand_xmm_value_128(&ins, 0, result);
                    }

                    Mnemonic::Addpd => {
                        self.show_instruction(&self.colors.green, &ins);

                        let value0 = self.get_operand_xmm_value_128(&ins, 0, true).expect("error getting value0");
                        let value1 = self.get_operand_xmm_value_128(&ins, 1, true).expect("error getting velue1");

                        let a:u128 = (value0 & 0xffffffff_ffffffff) + (value1 & 0xffffffff_ffffffff);
                        let b:u128 = (value0 & 0xffffffff_ffffffff_00000000_00000000) + (value1 & 0xffffffff_ffffffff_00000000_00000000);
                        let result:u128 = a | b;

                        self.set_operand_xmm_value_128(&ins, 0, result);
                    }

                    Mnemonic::Addsd => {
                        self.show_instruction(&self.colors.green, &ins);

                        let value0 = self.get_operand_xmm_value_128(&ins, 0, true).expect("error getting value0");
                        let value1 = self.get_operand_xmm_value_128(&ins, 1, true).expect("error getting velue1");

                        let result:u64 = value0 as u64 + value1 as u64;
                        let r128:u128 = (value0 & 0xffffffffffffffff0000000000000000) + result as u128; 
                        self.set_operand_xmm_value_128(&ins, 0, r128);
                    }

                    Mnemonic::Addss => {
                        self.show_instruction(&self.colors.green, &ins);

                        let value0 = self.get_operand_xmm_value_128(&ins, 0, true).expect("error getting value0");
                        let value1 = self.get_operand_xmm_value_128(&ins, 1, true).expect("error getting velue1");

                        let result:u32 = value0 as u32 + value1 as u32;
                        let r128:u128 = (value0 & 0xffffffffffffffffffffffff00000000) + result as u128; 
                        self.set_operand_xmm_value_128(&ins, 0, r128);
                    }

                    Mnemonic::Subps => {
                        self.show_instruction(&self.colors.green, &ins);

                        let value0 = self.get_operand_xmm_value_128(&ins, 0, true).expect("error getting value0");
                        let value1 = self.get_operand_xmm_value_128(&ins, 1, true).expect("error getting velue1");

                        let a:u128 = (value0 & 0xffffffff) - (value1 & 0xffffffff);
                        let b:u128 = (value0 & 0xffffffff_00000000) - (value1 & 0xffffffff_00000000);
                        let c:u128 = (value0 & 0xffffffff_00000000_00000000) - (value1 & 0xffffffff_00000000_00000000);
                        let d:u128 = (value0 & 0xffffffff_00000000_00000000_00000000) - (value1 & 0xffffffff_00000000_00000000_00000000); 

                        let result:u128 = a | b | c | d;

                        self.set_operand_xmm_value_128(&ins, 0, result);
                    }

                    Mnemonic::Subpd => {
                        self.show_instruction(&self.colors.green, &ins);

                        let value0 = self.get_operand_xmm_value_128(&ins, 0, true).expect("error getting value0");
                        let value1 = self.get_operand_xmm_value_128(&ins, 1, true).expect("error getting velue1");

                        let a:u128 = (value0 & 0xffffffff_ffffffff) - (value1 & 0xffffffff_ffffffff);
                        let b:u128 = (value0 & 0xffffffff_ffffffff_00000000_00000000) - (value1 & 0xffffffff_ffffffff_00000000_00000000);
                        let result:u128 = a | b;

                        self.set_operand_xmm_value_128(&ins, 0, result);
                    }

                    Mnemonic::Subsd => {
                        self.show_instruction(&self.colors.green, &ins);

                        let value0 = self.get_operand_xmm_value_128(&ins, 0, true).expect("error getting value0");
                        let value1 = self.get_operand_xmm_value_128(&ins, 1, true).expect("error getting velue1");

                        let result:u64 = value0 as u64 - value1 as u64;
                        let r128:u128 = (value0 & 0xffffffffffffffff0000000000000000) + result as u128; 
                        self.set_operand_xmm_value_128(&ins, 0, r128);
                    }

                    Mnemonic::Subss => {
                        self.show_instruction(&self.colors.green, &ins);

                        let value0 = self.get_operand_xmm_value_128(&ins, 0, true).expect("error getting value0");
                        let value1 = self.get_operand_xmm_value_128(&ins, 1, true).expect("error getting velue1");

                        let result:u32 = value0 as u32 - value1 as u32;
                        let r128:u128 = (value0 & 0xffffffffffffffffffffffff00000000) + result as u128; 
                        self.set_operand_xmm_value_128(&ins, 0, r128);
                    }

                    Mnemonic::Mulpd => {
                        self.show_instruction(&self.colors.green, &ins);

                        let value0 = self.get_operand_xmm_value_128(&ins, 0, true).expect("error getting value0");
                        let value1 = self.get_operand_xmm_value_128(&ins, 1, true).expect("error getting velue1");

                        let left:u128 = ((value0 & 0xffffffffffffffff0000000000000000)>>64) * ((value1 & 0xffffffffffffffff0000000000000000)>>64);
                        let right:u128 = (value0 & 0xffffffffffffffff) * (value1 & 0xffffffffffffffff);
                        let result:u128 = left << 64 | right; 

                        self.set_operand_xmm_value_128(&ins, 0, result);
                    }

                    Mnemonic::Mulps => {
                        self.show_instruction(&self.colors.green, &ins);

                        let value0 = self.get_operand_xmm_value_128(&ins, 0, true).expect("error getting value0");
                        let value1 = self.get_operand_xmm_value_128(&ins, 1, true).expect("error getting velue1");

                        let a:u128 = (value0 & 0xffffffff) * (value1 & 0xffffffff);
                        let b:u128 = (value0 & 0xffffffff00000000) * (value1 & 0xffffffff00000000);
                        let c:u128 = (value0 & 0xffffffff0000000000000000) * (value1 & 0xffffffff0000000000000000);
                        let d:u128 = (value0 & 0xffffffff000000000000000000000000) * (value1 & 0xffffffff000000000000000000000000);

                        let result:u128 = a | b | c | d; 

                        self.set_operand_xmm_value_128(&ins, 0, result);
                    }

                    Mnemonic::Mulsd => {
                        self.show_instruction(&self.colors.green, &ins);

                        let value0 = self.get_operand_xmm_value_128(&ins, 0, true).expect("error getting value0");
                        let value1 = self.get_operand_xmm_value_128(&ins, 1, true).expect("error getting velue1");

                        let result:u64 = value0 as u64 * value1 as u64;
                        let r128:u128 = (value0 & 0xffffffffffffffff0000000000000000) + result as u128; 
                        self.set_operand_xmm_value_128(&ins, 0, r128);
                    }

                    Mnemonic::Mulss => {
                        self.show_instruction(&self.colors.green, &ins);

                        let value0 = self.get_operand_xmm_value_128(&ins, 0, true).expect("error getting value0");
                        let value1 = self.get_operand_xmm_value_128(&ins, 1, true).expect("error getting velue1");

                        let result:u32 = value0 as u32 * value1 as u32;
                        let r128:u128 = (value0 & 0xffffffffffffffffffffffff00000000) + result as u128; 
                        self.set_operand_xmm_value_128(&ins, 0, r128);
                    }

                    // end SSE


                    Mnemonic::Arpl => {
                        self.show_instruction(&self.colors.green, &ins);

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let value1 = match self.get_operand_value(&ins, 1, true) {
                            Some(v) => v,
                            None => break,
                        };

                        self.flags.f_zf = value1 < value0;

                        self.set_operand_value(&ins, 1, value0);
                    }

                    Mnemonic::Pushf => {
                        self.show_instruction(&self.colors.blue, &ins);

                        let val:u16 = (self.flags.dump() & 0xffff) as u16;

                        self.regs.rsp -= 2;

                        if !self.maps.write_word(self.regs.rsp, val) {
                            println!("/!\\ exception writing word at rsp 0x{:x}", self.regs.rsp);
                            self.exception();
                            break;
                        }
                    }

                    Mnemonic::Pushfd => {
                        self.show_instruction(&self.colors.blue, &ins);

                        let flags = self.flags.dump();
                        self.stack_push32(flags); // 32bits only instruction
                    }

                    Mnemonic::Pushfq => {
                        self.show_instruction(&self.colors.blue, &ins);

                        // internal reserved register RFLAGS not very documented 
                        if self.cfg.is_64bits { // 64bits only instruction
                            self.stack_push64(0x00000346);
                        } else {
                            self.stack_push32(0x00000346);
                        }
                    }

                    Mnemonic::Bound => {
                        self.show_instruction(&self.colors.red, &ins);

                        let val0_src = self.get_operand_value(&ins, 0, true);

                    }

                    Mnemonic::Lahf => {
                        self.show_instruction(&self.colors.red, &ins);

                        self.regs.set_ah((self.flags.dump() & 0xff).into());
                    }


                    Mnemonic::Salc => {
                        self.show_instruction(&self.colors.red, &ins);

                        if self.flags.f_cf {
                            self.regs.set_al(1);
                        } else {
                            self.regs.set_al(0);
                        }
                    }


                    ////   Ring0  ////
                    
                    Mnemonic::Rdmsr => {
                        self.show_instruction(&self.colors.red, &ins);

                        match self.regs.rcx {
                            0x176 => {
                                self.regs.rdx = 0;
                                self.regs.rax = self.cfg.code_base_addr + 0x42;
                            },
                            _ => unimplemented!("/!\\ unimplemented rdmsr with value {}", self.regs.rcx),
                        }

                    }                    

                    _ =>  {
                        if self.cfg.is_64bits {
                            println!("{}{} 0x{:x}: {}{}", self.colors.red, self.pos, ins.ip(), self.out, self.colors.nc);
                        } else {
                            println!("{}{} 0x{:x}: {}{}", self.colors.red, self.pos, ins.ip32(), self.out, self.colors.nc);
                        }
                        
                        println!("unimplemented or invalid instruction.");
                        self.spawn_console();
                        //unimplemented!("unimplemented instruction");
                    },

                } // end mnemonics

                if self.cfg.is_64bits {
                    self.regs.rip += sz as u64;
                } else {
                    self.regs.set_eip(self.regs.get_eip() + sz as u64);
                }
                
                if self.force_break {
                    self.force_break = false;
                    break;
                }

            } // end decoder loop
        }  // end running loop
           
        self.is_running.store(1, atomic::Ordering::Relaxed);
        self.spawn_console();

        }  // end infinite loop, the unique way of exit is console quit `q` 

    } // end run

}
