
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_must_use)]

             
mod flags; 
mod eflags;
pub mod maps;
pub mod regs32;
mod console;
pub mod colors;
pub mod constants;
mod winapi;
mod fpu;
pub mod context32;
pub mod syscall32;
mod breakpoint;
pub mod endpoint;
pub mod structures;
mod exception;

use flags::Flags;
use eflags::Eflags;
use fpu::FPU;
use maps::Maps;
use regs32::Regs32;
use console::Console;
use colors::Colors;
use breakpoint::Breakpoint;
use crate::config::Config;


use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter, Mnemonic, OpKind, 
    InstructionInfoFactory, Register, MemorySize};

pub struct Emu {
    regs: Regs32,
    flags: Flags,
    eflags: Eflags,
    fpu: FPU,
    maps: Maps,
    exp: u64,
    break_on_alert: bool,
    bp: Breakpoint,
    seh: u32,
    veh: u32,
    eh_ctx: u32,
    cfg: Config,
    colors: Colors,
    pos: u64,
    force_break: bool,
    tls: Vec<u32>,
}

impl Emu {
    pub fn new() -> Emu {
        Emu{
            regs: Regs32::new(),
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
            tls: Vec::new(),
        }
    }

    pub fn init_stack(&mut self) {
        let stack = self.maps.get_mem("stack");
        stack.set_base(0x22d000); 
        stack.set_size(0x020000);
        self.regs.esp = 0x22e000;
        self.regs.ebp = 0x22f000;

        assert!(self.regs.esp < self.regs.ebp);
        assert!(self.regs.esp > stack.get_base());
        assert!(self.regs.esp < stack.get_bottom());
        assert!(self.regs.ebp > stack.get_base());
        assert!(self.regs.ebp < stack.get_bottom());
        assert!(stack.inside(self.regs.esp));
        assert!(stack.inside(self.regs.ebp));
    }

    pub fn init(&mut self) {
        println!("initializing regs");
        self.regs.clear();
        //self.regs.esp = 0x22f000;
        //self.regs.ebp = 0x00100f00;
        self.regs.eip = self.cfg.entry_point;
        //TODO: randomize initial register for avoid targeted anti-amulation
        self.regs.eax = 0;
        self.regs.ebx = 0x0022ee88;
        self.regs.ecx = 0x0022ee9c;
        self.regs.edx = 0x36b32038;
        self.regs.esi = 0x0022f388;
        self.regs.edi = 0;

        println!("loading memory maps");

        self.maps.create_map("10000");
        self.maps.create_map("20000");
        self.maps.create_map("stack");
        self.maps.create_map("code");
        self.maps.create_map("peb");
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

        self.init_stack();


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


        let peb = self.maps.get_mem("peb");
        peb.set_base(  0x7ffdf000);
        peb.load("peb.bin");

        let teb = self.maps.get_mem("teb");
        teb.set_base(  0x7ffde000);
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



        // xloader initial state hack
        //self.memory_write("dword ptr [esp + 4]", 0x22a00);
        //self.maps.get_mem("kernel32_xloader").set_base(0x75e40000) 


        std::env::set_current_dir(orig_path);



        // some tests

        assert!(self.get_bit(0xffffff00, 0) == 0);
        assert!(self.get_bit(0xffffffff, 5) == 1);
        assert!(self.get_bit(0xffffff00, 5) == 0);
        assert!(self.get_bit(0xffffff00, 7) == 0);
        assert!(self.get_bit(0xffffff00, 8) == 1);

        let mut a = 0xffffff00;
        self.set_bit(&mut a, 0, 1);
        self.set_bit(&mut a, 1, 1);
        self.set_bit(&mut a, 2, 1);
        self.set_bit(&mut a, 3, 1);
        self.set_bit(&mut a, 4, 1);
        self.set_bit(&mut a, 5, 1);
        self.set_bit(&mut a, 6, 1);
        self.set_bit(&mut a, 7, 1);

        assert!(a == 0xffffffff);

        self.set_bit(&mut a, 0, 0);
        self.set_bit(&mut a, 1, 0);
        self.set_bit(&mut a, 2, 0);
        self.set_bit(&mut a, 3, 0);
        self.set_bit(&mut a, 4, 0);
        self.set_bit(&mut a, 5, 0);
        self.set_bit(&mut a, 6, 0);
        self.set_bit(&mut a, 7, 0);

        assert!(a == 0xffffff00);

        assert!(self.shrd(0x9fd88893, 0x1b, 0x6, 32) == 0x6e7f6222);
        assert!(self.shrd(0x6fdcb03, 0x0, 0x6, 32) == 0x1bf72c);
        assert!(self.shrd(0x91545f1d, 0x6fe2, 0x6, 32) == 0x8a45517c);
        assert!(self.shld(0x1b, 0xf1a7eb1d, 0xa, 32) == 0x6fc6);

        if self.maps.mem_test() {
            println!("memory test Ok.");
        } else {
            eprintln!("It doesn't pass the memory tests!!");
            std::process::exit(1);
        }

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

    pub fn load_code(&mut self, filename: &String) {
        if !self.maps.get_mem("code").load(filename) {
            println!("shellcode not found, select the file with -f");
            std::process::exit(1);
        }
    }

    pub fn stack_push(&mut self, value:u32) {
        self.regs.esp -= 4;
        let stack = self.maps.get_mem("stack");
        if stack.inside(self.regs.esp) {
            stack.write_dword(self.regs.esp, value);
        } else {
            let mem = match self.maps.get_mem_by_addr(self.regs.esp) {
                Some(m) => m,
                None =>  {
                    panic!("pushing stack outside maps esp: 0x{:x}", self.regs.esp);
                }
            };
            mem.write_dword(self.regs.esp, value);
        }
    }

    pub fn stack_pop(&mut self, pop_instruction:bool) -> u32 {
        let stack = self.maps.get_mem("stack");
        if stack.inside(self.regs.esp) {
            let value = stack.read_dword(self.regs.esp);
            if self.cfg.verbose >= 1 && pop_instruction && self.maps.get_mem("code").inside(value) {
                println!("/!\\ poping a code address 0x{:x}", value);
            }
            self.regs.esp += 4;
            return value;
        }

        let mem = match self.maps.get_mem_by_addr(self.regs.esp) {
            Some(m) => m,
            None => panic!("poping stack outside map  esp: 0x{:x}", self.regs.esp),
        };

        let value = mem.read_dword(self.regs.esp);
        self.regs.esp += 4;
        value
    }

    // this is not used on the emulation
    pub fn memory_operand_to_address(&mut self, operand:&str) -> u32 {
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
                let num = u32::from_str_radix(spl2[1].trim_start_matches("0x"),16).expect("bad num conversion");

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
            let disp:u32;
            if self.is_reg(spl[2]) {
                disp = self.regs.get_by_name(spl[2]);
            } else {
                disp = u32::from_str_radix(spl[2].trim_start_matches("0x"),16).expect("bad disp");
            }


            if sign != "+" && sign != "-" {
                panic!("weird sign {}", sign);
            }

            if sign == "+" {
                let r:u64 = self.regs.get_by_name(reg) as u64 + disp as u64;
                return (r & 0xffffffff) as u32;
            } else {
                return self.regs.get_by_name(reg) - disp;
            }

        }

        if spl.len() == 1 { //ie [eax]
            let reg = spl[0];

            if reg.contains("0x") {
                let addr:u32 = usize::from_str_radix(reg.trim_start_matches("0x"),16).expect("bad disp2") as u32;
                return addr;
                // weird but could be a hardcoded address [0x11223344]
            }

            let reg_val = self.regs.get_by_name(reg);
            return reg_val;

        }

        0
    }

    // this is not used on the emulation
    pub fn memory_read(&mut self, operand:&str) -> Option<u32> {
        if operand.contains("fs:[0]") {
            if self.cfg.verbose >= 1 {
                println!("{} Reading SEH fs:[0] 0x{:x}", self.pos, self.seh);
            }
            return Some(self.seh);
        }

        let addr:u32 = self.memory_operand_to_address(operand);

        if operand.contains("fs:[") || operand.contains("gs:[") {
            return Some(addr);
        }

        let bits = self.get_size(operand);
        // check integrity of eip, esp and ebp registers


        let stack = self.maps.get_mem("stack");

        // could be normal using part of code as stack
        if !stack.inside(self.regs.esp) {
            //hack: redirect stack
            self.regs.esp = stack.get_base() + 0x1ff;
            panic!("/!\\ fixing stack.")
        }

        match bits {
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
                        return Some(v);
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
                        return Some((v as u32) & 0xffff);
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
                        return Some((v as u32) & 0xff);
                    },
                    None => return None,
                }
            },
            _ => panic!("weird size: {}", operand),
        };

    }

    // this is not used on the emulation
    pub fn memory_write(&mut self, operand:&str, value:u32) -> bool {
        if operand.contains("fs:[0]") {
            println!("Setting SEH fs:[0]  0x{:x}", value);
            self.seh = value;
            return true;
        }

        let addr:u32 = self.memory_operand_to_address(operand);

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
            32 => self.maps.write_dword(addr, value),
            16 => self.maps.write_word(addr, (value & 0x0000ffff) as u16),
            8 => self.maps.write_byte(addr, (value & 0x000000ff) as u8),
            _ => panic!("weird size: {}", operand)
        };

        ret
    }


    pub fn set_eip(&mut self, addr:u32, is_branch:bool) {

        let name = match self.maps.get_addr_name(addr) {
            Some(n) => n,
            None => { 
                eprintln!("/!\\ setting eip to non mapped addr 0x{:x}", addr);
                self.exception();
                return;
            }
        };

        if name == "code" || addr < 0x70000000 {
            self.regs.eip = addr;
        } else {
            if self.cfg.verbose >= 1 {
                println!("/!\\ changing EIP to {} ", name);
            }

            let retaddr = self.stack_pop(false);

            winapi::gateway(addr, name, self);

            //self.regs.eip += 2; 
            self.regs.eip = retaddr;
        }


        //TODO: lanzar memory scan code.scan() y stack.scan()
        // escanear en cambios de eip pero no en bucles, evitar escanear en bucles!
    }

    //this is not used on the emulation
    pub fn is_reg(&self, operand:&str) -> bool {
        match operand {
            "eax"|"ebx"|"ecx"|"edx"|"esi"|"edi"|"esp"|"ebp"|"eip"|"ax"|"bx"|"cx"|"dx"|"si"|"di"|"al"|"ah"|"bl"|"bh"|"cl"|"ch"|"dl"|"dh" => true,
            &_ => false,
        }
    }

    /*
       pub fn get_inmediate(&self, operand:&str) -> u32 {

       if operand.contains("0x") {
       return u32::from_str_radix(operand.get(2..).unwrap(), 16).unwrap();
       } else if operand.contains("-") {
       let num = u32::from_str_radix(operand.get(1..).unwrap(), 16).unwrap();
       return 0xffffffff - num + 1;
       } else {
       return u32::from_str_radix(operand, 16).unwrap();
       }
       }*/

    // this is not used on the emulation
    pub fn get_size(&self, operand:&str) -> u8 {
        if operand.contains("byte ptr") {
            return 8;

        } else if operand.contains("dword ptr") {
            return 32;

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

    fn mul32(&mut self, value0:u32) {
        let value1:u32 = self.regs.eax;
        let value2:u32 = value0;
        let res:u64 = value1 as u64 * value2 as u64;
        self.regs.edx = ((res & 0xffffffff00000000) >> 32) as u32;
        self.regs.eax = (res & 0x00000000ffffffff) as u32;
        self.flags.f_pf = (res & 0xff) % 2 == 0;
        self.flags.f_of = self.regs.edx != 0;
        self.flags.f_cf = self.regs.edx != 0;
    }

    fn mul16(&mut self, value0:u32) {
        let value1:u32 = self.regs.get_ax();
        let value2:u32 = value0;
        let res:u32 = value1 * value2;
        self.regs.set_dx((res & 0xffff0000) >> 16);
        self.regs.set_ax(res & 0xffff);
        self.flags.f_pf = (res & 0xff) % 2 == 0;
        self.flags.f_of = self.regs.get_dx() != 0;
        self.flags.f_cf = self.regs.get_dx() != 0;
    }

    fn mul8(&mut self, value0:u32) {
        let value1:u32 = self.regs.get_al();
        let value2:u32 = value0;
        let res:u32 = value1 * value2;
        self.regs.set_ax(res & 0xffff);
        self.flags.f_pf = (res & 0xff) % 2 == 0;
        self.flags.f_of = self.regs.get_ah() != 0;
        self.flags.f_cf = self.regs.get_ah() != 0;
    }

    fn imul32p1(&mut self, value0:u32) {
        let value1:i32 = self.regs.eax as i32;
        let value2:i32 = value0 as i32;
        let res:i64 = value1 as i64 * value2 as i64;
        let ures:u64 = res as u64;
        self.regs.edx = ((ures & 0xffffffff00000000) >> 32) as u32;
        self.regs.eax = (ures & 0x00000000ffffffff) as u32;
        self.flags.f_pf = (ures & 0xff) % 2 == 0;
        self.flags.f_of = self.regs.edx != 0;
        self.flags.f_cf = self.regs.edx != 0;
    }

    fn imul16p1(&mut self, value0:u32) {
        let value1:i32 = self.regs.get_ax() as i32;
        let value2:i32 = value0 as i32;
        let res:i32 = value1 * value2;
        let ures:u32 = res as u32;
        self.regs.set_dx((ures & 0xffff0000) >> 16);
        self.regs.set_ax(ures & 0xffff);
        self.flags.f_pf = (ures & 0xff) % 2 == 0;
        self.flags.f_of = self.regs.get_dx() != 0;
        self.flags.f_cf = self.regs.get_dx() != 0;
    }

    fn imul8p1(&mut self, value0:u32) {
        let value1:i32 = self.regs.get_al() as i32;
        let value2:i32 = value0 as i32;
        let res:i32 = value1 * value2;
        let ures:u32 = res as u32;
        self.regs.set_ax(ures & 0xffff);
        self.flags.f_pf = (ures & 0xff) % 2 == 0;
        self.flags.f_of = self.regs.get_ah() != 0;
        self.flags.f_cf = self.regs.get_ah() != 0;
    }

    fn div32(&mut self, value0:u32) {
        let mut value1:u64 = self.regs.edx as u64;
        value1 <<= 32;
        value1 += self.regs.eax as u64;
        let value2:u64 = value0 as u64;

        if value2 == 0 {
            self.flags.f_tf = true;
            println!("/!\\ division by 0 exception");
            self.exception();
            self.force_break = true;
            return;
        }

        let resq:u64 = value1 / value2;
        let resr:u64 = value1 % value2;
        self.regs.eax = resq as u32;
        self.regs.edx = resr as u32;
        self.flags.f_pf = (resq & 0xff) % 2 == 0;
        self.flags.f_of = resq > 0xffffffff;
        if self.flags.f_of {
            println!("/!\\ int overflow on division");
        }
    }

    fn div16(&mut self, value0:u32) {
        let value1:u32 = (self.regs.get_dx() << 16) + self.regs.get_ax();
        let value2:u32 = value0;

        if value2 == 0 {
            self.flags.f_tf = true;
            println!("/!\\ division by 0 exception");
            self.exception();
            self.force_break = true;
            return;
        } 

        let resq:u32 = value1 / value2;
        let resr:u32 = value1 % value2;
        self.regs.set_ax(resq);
        self.regs.set_dx(resr);
        self.flags.f_pf = (resq & 0xff) % 2 == 0;
        self.flags.f_of = resq > 0xffff;
        self.flags.f_tf = false;
        if self.flags.f_of {
            println!("/!\\ int overflow on division");
        }

    }

    fn div8(&mut self, value0:u32) {
        let value1:u32 = self.regs.get_ax();
        let value2:u32 = value0;
        if value2 == 0 {
            self.flags.f_tf = true;
            println!("/!\\ division by 0 exception");
            self.exception();
            self.force_break = true;
            return;
        } 

        let resq:u32 = value1 / value2;
        let resr:u32 = value1 % value2;
        self.regs.set_al(resq);
        self.regs.set_ah(resr);
        self.flags.f_pf = (resq & 0xff) % 2 == 0;
        self.flags.f_of = resq > 0xff;
        self.flags.f_tf = false;
        if self.flags.f_of {
            println!("/!\\ int overflow");
        }
    }

    fn idiv32(&mut self, value0:u32) {
        let mut value1:u64 = self.regs.edx as u64;
        value1 <<= 32;
        value1 += self.regs.eax as u64;
        let value2:u64 = value0 as u64;
        if value2 == 0 {
            self.flags.f_tf = true;
            println!("/!\\ division by 0 exception");
            self.exception();
            self.force_break = true;
            return;
        } 

        let resq:u64 = value1 / value2;
        let resr:u64 = value1 % value2;
        self.regs.eax = resq as u32;
        self.regs.edx = resr as u32;
        self.flags.f_pf = (resq & 0xff) % 2 == 0;
        if resq > 0xffffffff {
            println!("/!\\ int overflow exception on division");
            if self.break_on_alert {
                panic!();
            }
        } else {

            if ((value1 as i64) > 0 && (resq as i32) < 0) || ((value1 as i64) < 0 && (resq as i32) > 0) {
                println!("/!\\ sign change exception on division");
                self.exception();
                self.force_break = true;
            }
        } 
    }

    fn idiv16(&mut self, value0:u32) {
        let value1:u32 = (self.regs.get_dx() << 16) + self.regs.get_ax();
        let value2:u32 = value0;
        if value2 == 0 {
            self.flags.f_tf = true;
            println!("/!\\ division by 0 exception");
            self.exception();
            self.force_break = true;
            return;
        }

        let resq:u32 = value1 / value2;
        let resr:u32 = value1 % value2;
        self.regs.set_ax(resq);
        self.regs.set_dx(resr);
        self.flags.f_pf = (resq & 0xff) % 2 == 0;
        self.flags.f_tf = false;
        if resq > 0xffff {
            println!("/!\\ int overflow exception on division");
            if self.break_on_alert {
                panic!();
            }
        } else {
            if ((value1 as i32) > 0 && (resq as i16) < 0) || ((value1 as i32) < 0 && (resq as i16) > 0) {
                println!("/!\\ sign change exception on division");
                self.exception();
                self.force_break = true;
            } 
        }
    }

    fn idiv8(&mut self, value0:u32) {
        let value1:u32 = self.regs.get_ax();
        let value2:u32 = value0;
        if value2 == 0 {
            self.flags.f_tf = true;
            println!("/!\\ division by 0 exception");
            self.exception();
            self.force_break = true;
            return;
        } 

        let resq:u32 = value1 / value2;
        let resr:u32 = value1 % value2;
        self.regs.set_al(resq);
        self.regs.set_ah(resr);
        self.flags.f_pf = (resq & 0xff) % 2 == 0;
        self.flags.f_tf = false;
        if  resq > 0xff {
            println!("/!\\ int overflow exception on division");
            if self.break_on_alert {
                panic!();
            }
        } else {
            if ((value1 as i16) > 0 && (resq as i8) < 0) || ((value1 as i16) < 0 && (resq as i8) > 0) {
                println!("/!\\ sign change exception on division");
                self.exception();
                self.force_break = true;
            } 
        }
    }


    pub fn rotate_left(&self, val:u32, rot:u32, bits:u32) -> u32 {
        (val << rot) | (val >> (bits-rot))
    }

    pub fn rotate_right(&self, val:u32, rot:u32, bits:u32) -> u32 {
        //TODO: care with overflow
        (val >> rot) | (val << (bits-rot))
    }


    fn get_bit(&self, val:u32, count:u32) -> u32 {
        (val & (1 << count )) >> count
    }

    fn set_bit(&self, val:&mut u32, count:u32, bit:u32)  {
        if bit == 1 {
            *val |= 1 << count;
        } else {
            *val &= !(1 << count);
        }
    }

    pub fn shrd(&mut self, value0:u32, value1:u32, counter:u16, size:u32) -> u32 {
        let mut storage0:u32 = value0;
        self.flags.f_cf = self.get_bit(value0, counter as u32 - 1) == 1;

        if counter == 0 {
            return storage0;
        }

        if counter as u32 > size {
            println!("SHRD bad params.");
            return 0;
        }

        for i in 0..=(size-1-counter as u32) {
            let bit = self.get_bit(storage0, i as u32 + counter as u32);
            self.set_bit(&mut storage0, i as u32, bit);
        }

        for i in (size-counter as u32)..size {
            let bit = self.get_bit(value1, i as u32 + counter as u32 - 32);
            self.set_bit(&mut storage0, i as u32, bit);
        }

        self.flags.calc_flags(storage0, size as u8);
        storage0
    }

    pub fn shld(&mut self, value0:u32, value1:u32, counter:u16, size:u32) -> u32 {
        let mut storage0:u32 = value0;

        self.flags.f_cf = self.get_bit(value0, size - counter as u32) == 1;

        if counter == 0 {
            return storage0;
        }

        if counter as u32 > size {
            println!("SHLD bad params.");
            return 0;
        }

        for i in ((counter as u32)..=(size-1)).rev() {
            let bit = self.get_bit(storage0, i - counter as u32);
            self.set_bit(&mut storage0, i, bit);
        }

        for i in (0..=(counter as u32 - 1)).rev() {
            let bit = self.get_bit(value1, i - counter as u32 + size);
            self.set_bit(&mut storage0, i, bit);
        }

        self.flags.calc_flags(storage0, size as u8);
        storage0
    }

    pub fn spawn_console(&mut self) {
        let con = Console::new();
        loop {
            let cmd = con.cmd();
            match cmd.as_str() {
                "q" => std::process::exit(1),
                "h" => con.help(),
                "r" => self.featured_regs(),
                "r eax" => self.regs.show_eax(&self.maps, 0),
                "r ebx" => self.regs.show_ebx(&self.maps, 0),
                "r ecx" => self.regs.show_ecx(&self.maps, 0),
                "r edx" => self.regs.show_edx(&self.maps, 0),
                "r esi" => self.regs.show_esi(&self.maps, 0),
                "r edi" => self.regs.show_edi(&self.maps, 0),
                "r esp" => println!("\tesp: 0x{:x}", self.regs.esp),
                "r ebp" => println!("\tebp: 0x{:x}", self.regs.ebp),
                "r eip" => println!("\teip: 0x{:x}", self.regs.eip),
                "r xmm0" => println!("\txmm0: 0x{:x}", self.regs.xmm0),
                "r xmm1" => println!("\txmm1: 0x{:x}", self.regs.xmm1),
                "r xmm2" => println!("\txmm2: 0x{:x}", self.regs.xmm2),
                "r xmm3" => println!("\txmm3: 0x{:x}", self.regs.xmm3),
                "r xmm4" => println!("\txmm4: 0x{:x}", self.regs.xmm4),
                "r xmm5" => println!("\txmm5: 0x{:x}", self.regs.xmm5),
                "r xmm6" => println!("\txmm6: 0x{:x}", self.regs.xmm6),
                "r xmm7" => println!("\txmm7: 0x{:x}", self.regs.xmm7),

                "rc" => {
                    con.print("register name");
                    let reg = con.cmd();
                    con.print("value");
                    let svalue = con.cmd();
                    let value = u32::from_str_radix(svalue.as_str().trim_start_matches("0x"), 16).expect("bad num conversion");
                    self.regs.set_by_name(reg.as_str(), value);
                },
                "mr"|"rm" => {
                    con.print("memory argument");
                    let operand = con.cmd();
                    let addr:u32 = self.memory_operand_to_address(operand.as_str());
                    let value = match self.memory_read(operand.as_str()) {
                        Some(v) => v,
                        None => {
                            println!("bad address.");
                            continue;
                        },
                    };
                    println!("0x{:x}: 0x{:x}", addr, value);
                },
                "mw"|"wm" => {
                    con.print("memory argument");
                    let operand = con.cmd();
                    con.print("value");
                    let value = match con.cmd_hex() {
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
                "ba" => {
                    con.print("address");
                    let addr = match con.cmd_hex() {
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
                    let addr = match con.cmd_hex() {
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
                    let addr = match con.cmd_hex() {
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
                    let num = match con.cmd_hex64() {
                        Ok(v) => v,
                        Err(_) => {
                            println!("bad hex value.");
                            continue;
                        }
                    };
                    self.exp = num;
                },
                "bc" => {
                    self.bp.clear_bp();
                    self.exp = self.pos+1;
                },
                "cls" => println!("{}", self.colors.clear_screen),
                "s" => self.maps.dump_dwords(self.regs.esp),
                "v" => self.maps.get_mem("stack").print_dwords_from_to(self.regs.ebp, self.regs.ebp+0x100),
                "c" => return,
                "f" => self.flags.print(),
                "fc" => self.flags.clear(),
                "fz" => self.flags.f_zf = !self.flags.f_zf,
                "fs" => self.flags.f_sf = !self.flags.f_sf,
                "mc" => {
                    con.print("name ");
                    let name = con.cmd();
                    con.print("base address ");
                    let addr = match con.cmd_hex() {
                        Ok(v) => v,
                        Err(_) => {
                            println!("bad hex value.");
                            continue;
                        }
                    };
                    self.maps.create_map(name.as_str());
                    self.maps.get_mem(name.as_str()).set_base(addr);
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
                    let addr = match con.cmd_hex() {
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
                    println!("map: {} 0x{:x}-0x{:x} ({})", name, mem.get_base(), mem.get_bottom(), mem.size());

                },
                "ma" => {
                    self.maps.show_allocs();
                },
                "md" => {
                    con.print("address");
                    let addr = match con.cmd_hex() {
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
                    let addr = match con.cmd_hex() {
                        Ok(v) => v,
                        Err(_) => {
                            println!("bad hex value.");
                            continue;
                        }
                    };
                    self.maps.dump_dwords(addr);

                },
                "mds" => {
                    con.print("address");
                    let addr = match con.cmd_hex() {
                        Ok(v) => v,
                        Err(_) => {
                            println!("bad hex value.");
                            continue;
                        }
                    };
                    println!("0x{:x}: '{}'", addr, self.maps.read_string(addr));
                },
                "mdw" => {
                    con.print("address");
                    let addr = match con.cmd_hex() {
                        Ok(v) => v,
                        Err(_) => {
                            println!("bad hex value.");
                            continue;
                        }
                    };
                    println!("0x{:x}: '{}'", addr, self.maps.read_wide_string(addr));
                },
                "mdd" => {
                    con.print("address");
                    let addr = match con.cmd_hex() {
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
                "mt" => {
                    if self.maps.mem_test() {
                        println!("mem test passed ok.");
                    } else {
                        println!("memory errors.");
                    }
                }
                "eip" => {
                    con.print("=");
                    let addr = match con.cmd_hex() {
                        Ok(v) => v,
                        Err(_) => {
                            println!("bad hex value");
                            continue;
                        }
                    };
                    self.force_break = true;
                    self.regs.eip = addr;
                },
                "push" => {
                    con.print("value");
                    let value = match con.cmd_hex() {
                        Ok(v) => v,
                        Err(_) => {
                            println!("bad hex value");
                            continue;
                        }
                    };
                    self.stack_push(value);
                    println!("pushed.");
                },
                "pop" => {
                    let value = self.stack_pop(false);
                    println!("poped value 0x{:x}", value);
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
                    let kw = con.cmd();
                    let result = match self.maps.search_string(&kw, &mem_name) {
                        Some(v) => v,
                        None => { 
                            println!("not found.");
                            continue;
                        }
                    };
                    for addr in result.iter() {
                        println!("found 0x{:x} '{}'", addr, self.maps.read_string(*addr));
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
                    for addr in results.iter() {
                        println!("found at 0x{:x}", addr);
                    }
                },
                "ssa" => {
                    con.print("string");
                    let kw = con.cmd();
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
                    let ptr1:u32 = match con.cmd_hex() {
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
                            Some(v) => v,
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
                "d" => {
                    con.print("address");
                    let addr = match con.cmd_hex() {
                        Ok(v) => v,
                        Err(_) => {
                            println!("bad hex value");
                            continue;
                        }
                    };
                    self.disasemble(addr, 10);
                },
                "dt" => {
                    con.print("structure");
                    let struc = con.cmd();
                    con.print("address");
                    let addr = match con.cmd_hex() {
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

                        _  => println!("unrecognized structure."),
                    }


                }

                _ => println!("command not found, type h"),
            }
        }
    }

    fn featured_regs(&self) {
        self.regs.show_eax(&self.maps, 0);
        self.regs.show_ebx(&self.maps, 0);
        self.regs.show_ecx(&self.maps, 0);
        self.regs.show_edx(&self.maps, 0);
        self.regs.show_esi(&self.maps, 0);
        self.regs.show_edi(&self.maps, 0);
        println!("\tesp: 0x{:x}", self.regs.esp);
        println!("\tebp: 0x{:x}", self.regs.ebp);
        println!("\teip: 0x{:x}", self.regs.eip);
    }

    fn exception(&mut self) {
        let addr:u32;
        let next:u32;

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
                Some(value) => value,
                None => panic!("exception wihout correct SEH"),
            };

            addr = match self.maps.read_dword(self.seh + 4) {
                Some(value) => value,
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

    pub fn disasemble(&mut self, addr:u32, amount:u32) {
        let map_name = self.maps.get_addr_name(addr).expect("address not mapped");
        let code = self.maps.get_mem(map_name.as_str());
        let block = code.read_from(addr);
        let mut decoder = Decoder::with_ip(32, block, addr as u64, DecoderOptions::NONE);
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
            println!("0x{:x}: {}", instruction.ip32(), output);
            count += 1;
            if count == amount {
                break;
            }
        }
    }


    pub fn get_operand_value(&mut self, ins:&Instruction, noperand:u32, do_derref:bool) -> Option<u32> {

        assert!(ins.op_count() > noperand);

        let value:u32 = match ins.op_kind(noperand) {
            OpKind::NearBranch32 => ins.near_branch32(),
            OpKind::NearBranch16 => ins.near_branch16() as u32,
            OpKind::FarBranch32 => ins.far_branch32(),
            OpKind::FarBranch16 => ins.far_branch16() as u32,
            OpKind::Immediate8 => ins.immediate8() as u32,
            OpKind::Immediate16 => ins.immediate16() as u32,
            OpKind::Immediate32 => ins.immediate32(),
            OpKind::Immediate8to32 => ins.immediate8to32() as u32,
            OpKind::Immediate8to16 => ins.immediate8to16() as u32,
            OpKind::Register => self.regs.get_reg(ins.op_register(noperand)),
            OpKind::Memory => {
                let mut derref = do_derref;
                let mut fs = false;

                let mut mem_addr = ins.virtual_address(noperand, 0, |reg,idx,_sz| {
                    if reg == Register::FS || reg == Register::GS {
                        derref = false;
                        fs = true;

                        Some(0)
                    } else {
                        Some(self.regs.get_reg(reg) as u64)
                    }
                }).expect("error reading memory") as u32;

                if fs {
                    let value:u32 = match mem_addr {
                        0x30 => {
                            let peb = self.maps.get_mem("peb");
                            if self.cfg.verbose >= 1 {
                                println!("{} Reading PEB 0x{:x}", self.pos, peb.get_base());
                            }
                            peb.get_base()
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

                let value:u32;
                if derref {

                    let sz = self.get_operand_sz(ins, noperand);

                    value = match sz {

                        32 => match self.maps.read_dword(mem_addr) {
                            Some(v) => v,
                            None =>  { self.exception(); return None; }
                        }

                        16 => match self.maps.read_word(mem_addr) {
                            Some(v) => v as u32,
                            None =>  { self.exception(); return None; }
                        }

                        8 => match self.maps.read_byte(mem_addr) {
                            Some(v) => v as u32,
                            None =>  { self.exception(); return None; }
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

    pub fn set_operand_value(&mut self, ins:&Instruction, noperand:u32, value:u32) -> bool {

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
                }).unwrap() as u32;

                if write {
                    let sz = self.get_operand_sz(ins, noperand);

                    match sz {
                        64 => {
                            if !self.maps.write_dword(mem_addr, value) {
                                println!("exception dereferencing bad address. 0x{:x}", mem_addr);
                                self.exception();
                                return false;
                            }
                            if !self.maps.write_dword(mem_addr+4, value) { //TODO: this value should be the other dword
                                println!("exception dereferencing bad address. 0x{:x}", mem_addr);
                                self.exception();
                                return false;
                            }
                        }
                        32 => {
                            if !self.maps.write_dword(mem_addr, value) {
                                println!("exception dereferencing bad address. 0x{:x}", mem_addr);
                                self.exception();
                                return false;
                            }
                        }
                        16  => {
                            if !self.maps.write_word(mem_addr, value as  u16) {
                                println!("exception dereferencing bad address. 0x{:x}", mem_addr);
                                self.exception();
                                return false;
                            }
                        }
                        8  => {
                            if !self.maps.write_byte(mem_addr, value as u8) {
                                println!("exception dereferencing bad address. 0x{:x}", mem_addr);
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
                        self.exception();
                        return None
                    }
                };

                if do_derref {
                    let value:u128 = match self.maps.read_128bits_le(mem_addr as u32) {
                        Some(v) => v,
                        None => { 
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
                        self.exception();
                        return;
                    }
                };

                for (i,b) in value.to_le_bytes().iter().enumerate() {
                    self.maps.write_byte(mem_addr as u32 + i as u32, *b);
                }

            }
            _ => unimplemented!("unimplemented operand type {:?}", ins.op_kind(noperand)),
        };
    }

    fn get_operand_sz(&self, ins:&Instruction, noperand:u32) -> usize {
        let reg:Register = ins.op_register(noperand);
        if reg.is_xmm() {
            return 128;
        }

        let size:usize = match ins.op_kind(noperand) {
            OpKind::NearBranch32 => 32,
            OpKind::NearBranch16 => 16,
            OpKind::FarBranch32 => 32,
            OpKind::FarBranch16 => 16,
            OpKind::Immediate8 => 8,
            OpKind::Immediate16 => 16,
            OpKind::Immediate32 => 32,
            OpKind::Immediate8to32 => 32,
            OpKind::Immediate8to16 => 16,
            OpKind::Register => self.regs.get_size(ins.op_register(noperand)),
            OpKind::Memory => {                
                let mut info_factory = InstructionInfoFactory::new();
                let info = info_factory.info(ins);
                let mem = info.used_memory()[0];

                let size2:usize = match mem.memory_size() {
                    MemorySize::Float16 => 16,
                    MemorySize::Float32 => 32,
                    MemorySize::Float64 => 64,
                    MemorySize::FpuEnv28 => 32,
                    MemorySize::UInt32 => 32,
                    MemorySize::UInt16 => 16,
                    MemorySize::UInt8 => 8,
                    MemorySize::Int32 => 32,
                    MemorySize::Int16 => 16,
                    MemorySize::Int8 => 8,
                    MemorySize::DwordOffset => 32,
                    MemorySize::WordOffset => 16,
                    _  => 0,
                };

                if size2 == 0 {
                    unimplemented!("weird size {:?}", mem.memory_size());
                } 

                size2
            }
            _  => unimplemented!("operand type {:?}", ins.op_kind(noperand)),
        };

        size
    }



    ///  RUN ENGINE ///

    pub fn run(&mut self) {        
        println!(" ----- emulation -----");
        let mut looped:Vec<u64> = Vec::new();
        let mut out = String::new();
        //let ins = Instruction::default();
        let mut formatter = IntelFormatter::new();
        formatter.options_mut().set_digit_separator("");
        formatter.options_mut().set_first_operand_char_index(6);

        self.pos = 0;

        loop {
            let code = match self.maps.get_mem_by_addr(self.regs.eip) {
                Some(c) => c,
                None => panic!("redirecting code flow to non maped address 0x{:x}", self.regs.eip),
            };
            let block = code.read_from(self.regs.eip).to_vec();
            let mut decoder = Decoder::with_ip(32,  &block, self.regs.eip as u64, DecoderOptions::NONE);


            for ins in decoder.iter() {

                let sz = ins.len();
                let addr = ins.ip32() as u32;
                let mut step = false;
                out.clear();
                formatter.format(&ins, &mut out);

                self.pos += 1;

                if self.exp == self.pos || self.bp.get_bp() == addr || (self.cfg.console2 && self.cfg.console_addr == addr) {
                    self.cfg.console2 = false;
                    step = true;
                    println!("-------");
                    println!("{} 0x{:x}: {}", self.pos, ins.ip32(), out);
                    self.spawn_console();
                    if self.force_break {
                        self.force_break = false;
                        break;
                    }
                }

                if self.cfg.loops {
                    // loop detector
                    looped.push(addr as u64);
                    let mut count:u32 = 0;
                    for a in looped.iter() {
                        if addr as u64 == *a {
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
                    println!("\teax: 0x{:x} ebx: 0x{:x} ecx: 0x{:x} edx: 0x{:x} esi: 0x{:x} edi: 0x{:x} ebp: 0x{:x}", self.regs.eax, self.regs.ebx, self.regs.ecx, self.regs.edx, self.regs.esi, self.regs.edi, self.regs.ebp);
                }

                if self.cfg.trace_reg {
                    match self.cfg.reg_name.as_str() {
                        "eax" => self.regs.show_eax(&self.maps, self.pos),
                        "ebx" => self.regs.show_ebx(&self.maps, self.pos),
                        "ecx" => self.regs.show_ecx(&self.maps, self.pos),
                        "edx" => self.regs.show_edx(&self.maps, self.pos),
                        "esi" => self.regs.show_esi(&self.maps, self.pos),
                        "edi" => self.regs.show_edi(&self.maps, self.pos),
                        "esp" => println!("\t{} esp: 0x{:}", self.pos, self.regs.esp),
                        "ebp" => println!("\t{} ebp: 0x{:}", self.pos, self.regs.ebp),
                        "eip" => println!("\t{} eip: 0x{:}", self.pos, self.regs.eip),
                        _ => panic!("invalid register."),
                    }
                }

                if self.cfg.verbose < 2 {
                    step = true;
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
                    let addr:u32 = self.memory_operand_to_address(self.cfg.inspect_seq.clone().as_str());
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
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.yellow, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        if ins.op_count() != 1 {
                            unimplemented!("weird variant of jmp");
                        }

                        let addr = match self.get_operand_value(&ins, 0, true) {
                            Some(a) => a,
                            None => break
                        };
                        self.set_eip(addr, false);
                        break;
                    }

                    Mnemonic::Call => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.yellow, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        if ins.op_count() != 1 {
                            unimplemented!("weird variant of call");
                        }

                        let addr = match self.get_operand_value(&ins, 0, true) {
                            Some(a) => a,
                            None => break
                        };

                        self.stack_push(self.regs.eip + sz as u32);
                        self.set_eip(addr, false);
                        break;
                    }

                    Mnemonic::Push => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.blue, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        let value = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break
                        };
                        self.stack_push(value);
                    }

                    Mnemonic::Pop => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.blue, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        let value = self.stack_pop(true);
                        if !self.set_operand_value(&ins, 0, value) {
                            break;
                        }
                    }

                    Mnemonic::Pushad => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.blue, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        let tmp_esp = self.regs.esp;
                        self.stack_push(self.regs.eax);
                        self.stack_push(self.regs.ecx);
                        self.stack_push(self.regs.edx);
                        self.stack_push(self.regs.ebx);
                        self.stack_push(tmp_esp);
                        self.stack_push(self.regs.ebp);
                        self.stack_push(self.regs.esi);
                        self.stack_push(self.regs.edi);
                    }

                    Mnemonic::Popad => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.blue, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        self.regs.edi = self.stack_pop(false);
                        self.regs.esi = self.stack_pop(false);
                        self.regs.ebp = self.stack_pop(false);
                        self.regs.esp += 4; // skip esp
                        self.regs.ebx = self.stack_pop(false);
                        self.regs.edx = self.stack_pop(false);
                        self.regs.ecx = self.stack_pop(false);
                        self.regs.eax = self.stack_pop(false);
                    }

                    Mnemonic::Cdq => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.blue, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        let num:i64 = self.regs.eax as i32 as i64; // sign-extend
                        let unum:u64 = num as u64;
                        self.regs.edx = ((unum & 0xffffffff00000000) >> 32) as u32;
                        self.regs.eax = (unum & 0xffffffff) as u32;
                    }

                    Mnemonic::Ret => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.yellow, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        let ret_addr = self.stack_pop(false); // return address

                        if ins.op_count() > 0 {
                            let mut arg = self.get_operand_value(&ins, 0, true).expect("weird crash on ret");
                            // apply stack compensation of ret operand

                            if arg % 4 != 0 {
                                panic!("weird ret argument!");
                            }

                            arg /= 4;

                            for _ in 0..arg {
                                self.stack_pop(false);
                            }
                        }

                        if self.eh_ctx != 0 {
                            exception::exit(self);
                            break;
                        }

                        self.set_eip(ret_addr, false);                        
                        break;
                    }

                    Mnemonic::Xchg => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.light_cyan, self.pos, ins.ip32(), out, self.colors.nc);
                        }

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
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.light_cyan, self.pos, ins.ip32(), out, self.colors.nc);
                        }

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
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

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
                        let result = value0 ^ value1;

                        self.flags.calc_flags(result, sz as u8);

                        if !self.set_operand_value(&ins, 0, result) {
                            break;
                        }
                    }

                    Mnemonic::Add => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.cyan, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        assert!(ins.op_count() == 2);

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let value1 = match self.get_operand_value(&ins, 1, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let res:u32;
                        match self.get_operand_sz(&ins, 1) {
                            32 => res = self.flags.add32(value0, value1),
                            16 => res = self.flags.add16(value0, value1),
                            8  => res = self.flags.add8(value0, value1),
                            _  => panic!("weird size")
                        }

                        if !self.set_operand_value(&ins, 0, res) {
                            break;
                        }

                    }

                    Mnemonic::Adc => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.cyan, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        assert!(ins.op_count() == 2);

                        let cf:u32;
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

                        let res:u32;
                        match self.get_operand_sz(&ins, 1) {
                            32 => res = self.flags.add32(value0, value1+cf),
                            16 => res = self.flags.add16(value0, value1+cf),
                            8  => res = self.flags.add8(value0, value1+cf),
                            _  => panic!("weird size")
                        }

                        if !self.set_operand_value(&ins, 0, res) {
                            break;
                        }                        

                    }

                    Mnemonic::Sbb => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.cyan, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        assert!(ins.op_count() == 2);

                        let cf:u32;
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

                        let res:u32;
                        match self.get_operand_sz(&ins, 1) {
                            32 => res = self.flags.sub32(value0, value1+cf),
                            16 => res = self.flags.sub16(value0, value1+cf),
                            8  => res = self.flags.sub8(value0, value1+cf),
                            _  => panic!("weird size")
                        }

                        if !self.set_operand_value(&ins, 0, res) {
                            break;
                        } 

                    }

                    Mnemonic::Sub => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.cyan, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        assert!(ins.op_count() == 2);

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let value1 = match self.get_operand_value(&ins, 1, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let res:u32;
                        match self.get_operand_sz(&ins, 1) {
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
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.cyan, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        assert!(ins.op_count() == 1);

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let res:u32 = match self.get_operand_sz(&ins, 0) {
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
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.cyan, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        assert!(ins.op_count() == 1);

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let res:u32 = match self.get_operand_sz(&ins, 0) {
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
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        assert!(ins.op_count() == 1);

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let res:u32 = match self.get_operand_sz(&ins, 0) {
                            32 => self.flags.neg32(value0),
                            16 => self.flags.neg16(value0),
                            8  => self.flags.neg8(value0),
                            _  => panic!("weird size")
                        };

                        if !self.set_operand_value(&ins, 0, res) {
                            break;
                        }
                    }

                    Mnemonic::Not => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        assert!(ins.op_count() == 1);

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let mut ival = value0 as i32;
                        ival = !ival;

                        if !self.set_operand_value(&ins, 0, ival as u32) {
                            break;
                        }
                    }

                    Mnemonic::And => {  
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        assert!(ins.op_count() == 2);

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let value1 = match self.get_operand_value(&ins, 1, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let result = value0 & value1;

                        self.flags.calc_flags(result, self.get_operand_sz(&ins, 0) as u8);
                        self.flags.f_of = false;
                        self.flags.f_cf = false;

                        if !self.set_operand_value(&ins, 0, result) {
                            break;
                        }

                    }

                    Mnemonic::Or => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        assert!(ins.op_count() == 2);

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let value1 = match self.get_operand_value(&ins, 1, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let result = value0 | value1;

                        //println!("0x{:x} or 0x{:x} = 0x{:x}", value0, value1, result);


                        self.flags.calc_flags(result, self.get_operand_sz(&ins, 0) as u8);
                        self.flags.f_of = false;
                        self.flags.f_cf = false;

                        if !self.set_operand_value(&ins, 0, result) {
                            break;
                        }
                    }

                    Mnemonic::Sal => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        assert!(ins.op_count() == 1 || ins.op_count() == 2);

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        if ins.op_count() == 1 { // 1 param

                            let result:u32 = match self.get_operand_sz(&ins, 0) {
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

                            let result:u32 = match self.get_operand_sz(&ins, 0) {
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
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        assert!(ins.op_count() == 1 || ins.op_count() == 2);

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        if ins.op_count() == 1 { // 1 param

                            let result:u32 = match self.get_operand_sz(&ins, 0) {
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

                            let result:u32 = match self.get_operand_sz(&ins, 0) {
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
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        assert!(ins.op_count() == 1 || ins.op_count() == 2);

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        if ins.op_count() == 1 { // 1 param

                            let result:u32 = match self.get_operand_sz(&ins, 0) {
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

                            let result:u32 = match self.get_operand_sz(&ins, 0) {
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
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        assert!(ins.op_count() == 1 || ins.op_count() == 2);

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        if ins.op_count() == 1 { // 1 param

                            let result:u32 = match self.get_operand_sz(&ins, 0) {
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

                            let result:u32 = match self.get_operand_sz(&ins, 0) {
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
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        assert!(ins.op_count() == 1 || ins.op_count() == 2);

                        let result:u32;
                        let sz = self.get_operand_sz(&ins, 0);


                        if ins.op_count() == 1 { // 1 param
                            let value0 = match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            result = self.rotate_right(value0, 1, sz as u32);

                        } else { // 2 params
                            let value0 = match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            let value1 = match self.get_operand_value(&ins, 1, true) {
                                Some(v) => v,
                                None => break,
                            };


                            result = self.rotate_right(value0, value1, sz as u32);
                        }

                        if !self.set_operand_value(&ins, 0, result) {
                            break;
                        }

                        self.flags.calc_flags(result, sz as u8);
                    }

                    Mnemonic::Rol => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        assert!(ins.op_count() == 1 || ins.op_count() == 2);

                        let result:u32;
                        let sz = self.get_operand_sz(&ins, 0);


                        if ins.op_count() == 1 { // 1 param
                            let value0 = match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            result = self.rotate_left(value0, 1, sz as u32);

                        } else { // 2 params
                            let value0 = match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            let value1 = match self.get_operand_value(&ins, 1, true) {
                                Some(v) => v,
                                None => break,
                            };


                            result = self.rotate_left(value0, value1, sz as u32);
                        }

                        if !self.set_operand_value(&ins, 0, result) {
                            break;
                        }

                        self.flags.calc_flags(result, sz as u8);
                    }

                    Mnemonic::Mul => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.cyan, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        assert!(ins.op_count() == 1);

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        match self.get_operand_sz(&ins, 0) {
                            32 => self.mul32(value0),
                            16 => self.mul16(value0),
                            8  => self.mul8(value0),
                            _ => unimplemented!("wrong size"),
                        }
                    }

                    Mnemonic::Div => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.cyan, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        assert!(ins.op_count() == 1);

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        match self.get_operand_sz(&ins, 0) {
                            32 => self.div32(value0),
                            16 => self.div16(value0),
                            8  => self.div8(value0),
                            _ => unimplemented!("wrong size"),
                        }
                    }

                    Mnemonic::Idiv => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.cyan, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        assert!(ins.op_count() == 1);

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        match self.get_operand_sz(&ins, 0) {
                            32 => self.idiv32(value0),
                            16 => self.idiv16(value0),
                            8  => self.idiv8(value0),
                            _ => unimplemented!("wrong size"),
                        }
                    }

                    Mnemonic::Imul => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.cyan, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        assert!(ins.op_count() == 1 || ins.op_count() == 2 || ins.op_count() == 3);

                        if ins.op_count() == 1 { // 1 param

                            let value0 = match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            match self.get_operand_sz(&ins, 0) {
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
                                32 => self.flags.imul32p2(value0, value1),
                                16 => self.flags.imul16p2(value0 as u16, value1 as u16),
                                8  => self.flags.imul8p2(value0 as u8, value1 as u8),
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
                                32 => self.flags.imul32p2(value1, value2),
                                16 => self.flags.imul16p2(value1 as u16, value2 as u16),
                                8  => self.flags.imul8p2(value1 as u8, value2 as u8),
                                _ => unimplemented!("wrong size"),
                            };

                            if !self.set_operand_value(&ins, 0, result) {
                                break;
                            }

                        }
                    }

                    Mnemonic::Movsx => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.light_cyan, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        assert!(ins.op_count() == 2);


                        let value1 = match self.get_operand_value(&ins, 1, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let sz0 = self.get_operand_sz(&ins, 0);
                        let sz1 = self.get_operand_sz(&ins, 1);

                        assert!((sz0 == 16 && sz1 == 8) || 
                            (sz0 == 32 && sz1 == 8) || 
                            (sz0 == 32 && sz1 == 16));


                        let mut result:u32 = 0;

                        if sz0 == 16 {
                            assert!(sz1 == 8);
                            result = value1 as u8 as i8 as i16 as u16 as u32;
                        } else if sz0 == 32 {
                            if sz1 == 8 {
                                result = value1 as u8 as i8 as i32 as u32;
                            } else if sz1 == 16 {
                                result = value1 as u8 as i8 as i16 as u16 as u32;
                            }
                        } 

                        if !self.set_operand_value(&ins, 0, result) {
                            break;
                        }

                    }

                    Mnemonic::Movzx => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.light_cyan, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        assert!(ins.op_count() == 2);

                        let value1 = match self.get_operand_value(&ins, 1, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let sz0 = self.get_operand_sz(&ins, 0);
                        let sz1 = self.get_operand_sz(&ins, 1);

                        assert!((sz0 == 16 && sz1 == 8) || 
                            (sz0 == 32 && sz1 == 8) || 
                            (sz0 == 32 && sz1 == 16));


                        let result:u32;

                        /*
                           if sz0 == 16 && sz1 == 8 {
                           value0 = value0 & 0x0000ff00;
                           value1 = value1 & 0x000000ff;

                           } else if sz0 == 32 && sz1 == 8 {
                           value0 = value0 & 0xffffff00;
                           value1 = value1 & 0x000000ff;

                           } else if sz0 == 32 && sz1 == 16 {
                           value0 = value0 & 0xffff0000;
                           value1 = value1 & 0x0000ffff;

                           } else {
                           unreachable!("impossible");
                           }*/

                        result = value1;

                        //println!("0x{:x}: MOVZX 0x{:x}", ins.ip32(), result);

                        if !self.set_operand_value(&ins, 0, result) {
                            break;
                        }

                    }

                    Mnemonic::Movsb => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.light_cyan, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        if ins.has_rep_prefix() {
                            loop {
                                let val = self.maps.read_byte(self.regs.esi).expect("cannot read memory"); 
                                self.maps.write_byte(self.regs.edi, val);

                                if !self.flags.f_df {
                                    self.regs.esi += 1;
                                    self.regs.edi += 1;
                                } else {
                                    self.regs.esi -= 1;
                                    self.regs.edi -= 1;
                                }

                                self.regs.ecx -= 1;
                                if self.regs.ecx == 0 { 
                                    break 
                                }
                            }

                        } else {
                            let val = self.maps.read_byte(self.regs.esi).expect("cannot read memory"); 
                            self.maps.write_byte(self.regs.edi, val);
                            if !self.flags.f_df {
                                self.regs.esi += 1;
                                self.regs.edi += 1;
                            } else {
                                self.regs.esi -= 1;
                                self.regs.edi -= 1;
                            }
                        }
                    }


                    Mnemonic::Movsw => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.light_cyan, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        if ins.has_rep_prefix() {
                            loop {
                                let val = self.maps.read_word(self.regs.esi).expect("cannot read memory"); 
                                self.maps.write_word(self.regs.edi, val);

                                if !self.flags.f_df {
                                    self.regs.esi += 2;
                                    self.regs.edi += 2;
                                } else {
                                    self.regs.esi -= 2;
                                    self.regs.edi -= 2;
                                }

                                self.regs.ecx -= 1;
                                if self.regs.ecx == 0 { 
                                    break 
                                }
                            }

                        } else {
                            let val = self.maps.read_word(self.regs.esi).expect("cannot read memory"); 
                            self.maps.write_word(self.regs.edi, val);
                            if !self.flags.f_df {
                                self.regs.esi += 2;
                                self.regs.edi += 2;
                            } else {
                                self.regs.esi -= 2;
                                self.regs.edi -= 2;
                            }
                        }
                    }


                    Mnemonic::Movsd => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.light_cyan, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        if ins.has_rep_prefix() {
                            loop {
                                let val = self.maps.read_dword(self.regs.esi).expect("cannot read memory"); 
                                self.maps.write_dword(self.regs.edi, val);

                                if !self.flags.f_df {
                                    self.regs.esi += 4;
                                    self.regs.edi += 4;
                                } else {
                                    self.regs.esi -= 4;
                                    self.regs.edi -= 4;
                                }

                                self.regs.ecx -= 1;
                                if self.regs.ecx == 0 { 
                                    break 
                                }
                            }

                        } else {
                            let val = self.maps.read_dword(self.regs.esi).expect("cannot read memory"); 
                            self.maps.write_dword(self.regs.edi, val);
                            if !self.flags.f_df {
                                self.regs.esi += 4;
                                self.regs.edi += 4;
                            } else {
                                self.regs.esi -= 4;
                                self.regs.edi -= 4;
                            }
                        }
                    }


                    Mnemonic::Stosb => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.light_cyan, self.pos, ins.ip32(), out, self.colors.nc);
                        }                       

                        self.maps.write_byte(self.regs.edi, self.regs.get_al() as u8);

                        if self.flags.f_df {
                            self.regs.edi -= 1;
                        } else {
                            self.regs.edi += 1;
                        }
                    }

                    Mnemonic::Stosw => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.light_cyan, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        self.maps.write_word(self.regs.edi, self.regs.get_ax() as u16);

                        if self.flags.f_df {
                            self.regs.edi -= 2;
                        } else {
                            self.regs.edi += 2;
                        }
                    }

                    Mnemonic::Stosd => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.light_cyan, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        self.maps.write_dword(self.regs.edi, self.regs.eax);

                        if self.flags.f_df {
                            self.regs.edi -= 4;
                        } else {
                            self.regs.edi += 4;
                        }
                    }

                    Mnemonic::Test => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                        }

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

                        self.flags.test(value0, value1, sz);
                    }

                    Mnemonic::Cmpxchg => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let value1 = match self.get_operand_value(&ins, 1, true) {
                            Some(v) => v,
                            None => break,
                        };

                        if value0 == self.regs.eax {
                            self.flags.f_zf = true;
                            if !self.set_operand_value(&ins, 0, value1) {
                                break;
                            }
                        } else {
                            self.flags.f_zf = false;
                            self.regs.eax = value1;
                        }
                    }

                    Mnemonic::Cmpxchg8b => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                        }

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
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                        }

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
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        assert!(ins.op_count() == 2);

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let value1 = match self.get_operand_value(&ins, 1, true) {
                            Some(v) => v,
                            None => break,
                        };

                        if !step {
                            if value0 > value1 {
                                println!("\tcmp: 0x{:x} > 0x{:x}", value0, value1);
                            } else if value0 < value1 {
                                println!("\tcmp: 0x{:x} < 0x{:x}", value0, value1);
                            } else {
                                println!("\tcmp: 0x{:x} == 0x{:x}", value0, value1);
                            }
                        }

                        match self.get_operand_sz(&ins, 0) {
                            32 => { self.flags.sub32(value0, value1); },
                            16 => { self.flags.sub16(value0, value1); },
                            8 => { self.flags.sub8(value0, value1); },
                            _  => { panic!("wrong size {}", self.get_operand_sz(&ins, 0)); }
                        }

                    }

                    Mnemonic::Cmpsd => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        let value0 = self.maps.read_dword(self.regs.esi).expect("cannot read esi");
                        let value1 = self.maps.read_dword(self.regs.edi).expect("cannot read edi");

                        if !step {
                            if value0 > value1 {
                                println!("\tcmp: 0x{:x} > 0x{:x}", value0, value1);
                            } else if value0 < value1 {
                                println!("\tcmp: 0x{:x} < 0x{:x}", value0, value1);
                            } else {
                                println!("\tcmp: 0x{:x} == 0x{:x}", value0, value1);
                            }
                        }
      
                        self.flags.sub32(value0, value1);
                    }

                    Mnemonic::Cmpsw => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        let value0 = self.maps.read_dword(self.regs.esi).expect("cannot read esi");
                        let value1 = self.maps.read_dword(self.regs.edi).expect("cannot read edi");

                        if !step {
                            if value0 > value1 {
                                println!("\tcmp: 0x{:x} > 0x{:x}", value0, value1);
                            } else if value0 < value1 {
                                println!("\tcmp: 0x{:x} < 0x{:x}", value0, value1);
                            } else {
                                println!("\tcmp: 0x{:x} == 0x{:x}", value0, value1);
                            }
                        }
      
                        self.flags.sub16(value0, value1);
                    }

                    Mnemonic::Cmpsb => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        let value0 = self.maps.read_dword(self.regs.esi).expect("cannot read esi");
                        let value1 = self.maps.read_dword(self.regs.edi).expect("cannot read edi");

                        if !step {
                            if value0 > value1 {
                                println!("\tcmp: 0x{:x} > 0x{:x}", value0, value1);
                            } else if value0 < value1 {
                                println!("\tcmp: 0x{:x} < 0x{:x}", value0, value1);
                            } else {
                                println!("\tcmp: 0x{:x} == 0x{:x}", value0, value1);
                            }
                        }


                        self.flags.sub8(value0, value1);
                    }


                    //branches: https://web.itu.edu.tr/kesgin/mul06/intel/instr/jxx.html
                    //          https://c9x.me/x86/html/file_module_x86_id_146.html
                    //          http://unixwiz.net/techtips/x86-jumps.html <---aqui

                    //esquema global -> https://en.wikipedia.org/wiki/X86_instruction_listings
                    // test jnle jpe jpo loopz loopnz int 0x80

                    Mnemonic::Jo => {

                        assert!(ins.op_count() == 1);

                        if self.flags.f_of {
                            if !step {
                                println!("{}{} 0x{:x}: {} taken {}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                            }
                            let addr =  match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            self.set_eip(addr, true);
                            break;
                        } else if !step {
                            println!("{}{} 0x{:x}: {} not taken {}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                        }
                    }

                    Mnemonic::Jno => {

                        assert!(ins.op_count() == 1);

                        if !self.flags.f_of {
                            if !step {
                                println!("{}{} 0x{:x}: {} taken {}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                            }
                            let addr =  match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} 0x{:x}: {} not taken {}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                            }
                        }
                    }
                    
                    Mnemonic::Js => {

                        assert!(ins.op_count() == 1);

                        if self.flags.f_sf {
                            if !step {
                                println!("{}{} 0x{:x}: {} taken {}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                            }
                            let addr =  match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} 0x{:x}: {} not taken {}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                            }
                        }
                    }

                    Mnemonic::Jns => {

                        assert!(ins.op_count() == 1);

                        if !self.flags.f_sf {
                            if !step {
                                println!("{}{} 0x{:x}: {} taken {}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                            }
                            let addr =  match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} 0x{:x}: {} not taken {}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                            }
                        }
                    }

                    Mnemonic::Je => {

                        assert!(ins.op_count() == 1);

                        if self.flags.f_zf {
                            if !step {
                                println!("{}{} 0x{:x}: {} taken {}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                            }
                            let addr =  match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} 0x{:x}: {} not taken {}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                            }
                        }
                    }

                    Mnemonic::Jne => {

                        assert!(ins.op_count() == 1);

                        if !self.flags.f_zf {
                            if !step {
                                println!("{}{} 0x{:x}: {} taken {}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                            }
                            let addr =  match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} 0x{:x}: {} not taken {}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                            }
                        }
                    }

                    Mnemonic::Jb => {
          
                        assert!(ins.op_count() == 1);

                        if self.flags.f_cf {
                            if !step {
                                println!("{}{} 0x{:x}: {} taken {}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                            }
                            let addr =  match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} 0x{:x}: {} not taken {}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                            }
                        }
                    }

                    Mnemonic::Jae => {
        
                        assert!(ins.op_count() == 1);

                        if !self.flags.f_cf {
                            if !step {
                                println!("{}{} 0x{:x}: {} taken {}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                            }
                            let addr =  match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} 0x{:x}: {} not taken {}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                            }
                        }
                    }

                    Mnemonic::Jbe => {
         
                        assert!(ins.op_count() == 1);

                        if self.flags.f_cf || self.flags.f_zf {
                            if !step {
                                println!("{}{} 0x{:x}: {} taken {}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                            }
                            let addr =  match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} 0x{:x}: {} not taken {}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                            }
                        }
                    }

                    Mnemonic::Ja => {

                        assert!(ins.op_count() == 1);

                        if !self.flags.f_cf && !self.flags.f_zf {
                            if !step {
                                println!("{}{} 0x{:x}: {} taken {}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                            }
                            let addr =  match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} 0x{:x}: {} not taken {}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                            }
                        }
                    }

                    Mnemonic::Jl => {
                
                        assert!(ins.op_count() == 1);

                        if self.flags.f_sf != self.flags.f_of {
                            if !step {
                                println!("{}{} 0x{:x}: {} taken {}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                            }
                            let addr =  match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} 0x{:x}: {} not taken {}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                            }
                        }
                    }

                    Mnemonic::Jge => {
                        
                        assert!(ins.op_count() == 1);

                        if self.flags.f_sf == self.flags.f_of {
                            if !step {
                                println!("{}{} 0x{:x}: {} taken {}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                            }
                            let addr =  match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} 0x{:x}: {} not taken {}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                            }
                        }
                    }

                    Mnemonic::Jle => {
             
                        assert!(ins.op_count() == 1);

                        if self.flags.f_zf || self.flags.f_sf != self.flags.f_of {
                            if !step {
                                println!("{}{} 0x{:x}: {} taken {}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                            }
                            let addr =  match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} 0x{:x}: {} not taken {}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                            }
                        }
                    }

                    Mnemonic::Jg => {
                
                        assert!(ins.op_count() == 1);

                        if !self.flags.f_zf && self.flags.f_sf == self.flags.f_of {
                            if !step {
                                println!("{}{} 0x{:x}: {} taken {}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                            }
                            let addr =  match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} 0x{:x}: {} not taken {}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                            }
                        }
                    }

                    Mnemonic::Jp => {

                        assert!(ins.op_count() == 1);

                        if self.flags.f_pf {
                            if !step {
                                println!("{}{} 0x{:x}: {} taken {}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                            }
                            let addr =  match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} 0x{:x}: {} not taken {}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                            }
                        }
                    }

                    Mnemonic::Jnp => {

                        assert!(ins.op_count() == 1);

                        if !self.flags.f_pf {
                            if !step {
                                println!("{}{} 0x{:x}: {} taken {}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                            }
                            let addr =  match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} 0x{:x}: {} not taken {}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                            }
                        }
                    }

                    Mnemonic::Jcxz => {

                        assert!(ins.op_count() == 1);

                        if self.regs.get_cx() == 0 {
                            if !step {
                                println!("{}{} 0x{:x}: {} taken {}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                            }
                            let addr =  match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} 0x{:x}: {} not taken {}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                            }
                        }
                    }

                    Mnemonic::Jecxz => {

                        assert!(ins.op_count() == 1);

                        if self.regs.get_cx() == 0 {
                            if !step {
                                println!("{}{} 0x{:x}: {} taken {}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                            }
                            let addr =  match self.get_operand_value(&ins, 0, true) {
                                Some(v) => v,
                                None => break,
                            };

                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} 0x{:x}: {} not taken {}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                            }
                        }
                    }

                    Mnemonic::Int3 => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.red, self.pos, ins.ip32(), out, self.colors.nc);
                        }
                        println!("/!\\ int 3 sigtrap!!!!");
                        self.exception();
                        break;
                    }

                    Mnemonic::Nop => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.light_gray, self.pos, ins.ip32(), out, self.colors.nc);
                        }
                    }

                    Mnemonic::Mfence|Mnemonic::Lfence|Mnemonic::Sfence => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.red, self.pos, ins.ip32(), out, self.colors.nc);
                        }
                    }

                    Mnemonic::Cpuid => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.red, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        // guloader checks bit31 which is if its hipervisor with command
                        // https://c9x.me/x86/html/file_module_x86_id_45.html
                        // TODO: implement 0x40000000 -> get the virtualization vendor

                        match self.regs.eax {
                            0x00 => {
                                self.regs.eax = 16;
                                self.regs.ebx = 0x756e6547;
                                self.regs.ecx = 0x6c65746e;
                                self.regs.edx = 0x49656e69;
                            },
                            0x01 => {
                                self.regs.eax = 0x906ed;
                                self.regs.ebx = 0x5100800;
                                self.regs.ecx = 0x7ffafbbf;
                                self.regs.edx = 0xbfebfbff;
                            },
                            0x02 => {
                                self.regs.eax = 0x76036301;
                                self.regs.ebx = 0xf0b5ff;
                                self.regs.ecx = 0;
                                self.regs.edx = 0xc30000;
                            },
                            0x03 => {
                                self.regs.eax = 0;
                                self.regs.ebx = 0;
                                self.regs.ecx = 0;
                                self.regs.edx = 0;
                            },
                            0x04 => {
                                self.regs.eax = 0;
                                self.regs.ebx = 0x1c0003f;
                                self.regs.ecx = 0x3f;
                                self.regs.edx = 0;
                            },
                            0x05 => {
                                self.regs.eax = 0x40;
                                self.regs.ebx = 0x40;
                                self.regs.ecx = 3;
                                self.regs.edx = 0x11142120;
                            },
                            0x06 => {
                                self.regs.eax = 0x27f7;
                                self.regs.ebx = 2;
                                self.regs.ecx = 9;
                                self.regs.edx = 0;
                            },
                            0x07..=0x6d => {
                                self.regs.eax = 0;
                                self.regs.ebx = 0;
                                self.regs.ecx = 0;
                                self.regs.edx = 0;
                            },
                            0x6e => {
                                self.regs.eax = 0x960;
                                self.regs.ebx = 0x1388;
                                self.regs.ecx = 0x64;
                                self.regs.edx = 0;
                            },
                            0x80000000 => {
                                self.regs.eax = 0x80000008;
                                self.regs.ebx = 0;
                                self.regs.ecx = 0;
                                self.regs.edx = 0;
                            },
                            _ => unimplemented!("unimplemented cpuid call 0x{:x}", self.regs.eax),
                        }
                    }

                    Mnemonic::Clc => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.light_gray, self.pos, ins.ip32(), out, self.colors.nc);
                        }
                        self.flags.f_cf = false;
                    }
                    
                    Mnemonic::Rdtsc => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.red, self.pos, ins.ip32(), out, self.colors.nc);
                        }
                        self.regs.edx = 0;
                        self.regs.eax = 0;
                    }

                    Mnemonic::Loop => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.yellow, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        assert!(ins.op_count() == 1);

                        let addr = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        if addr > 0xffff {
                            if self.regs.ecx == 0 {
                                self.regs.ecx = 0xffffffff;
                            } else {
                                self.regs.ecx -= 1;
                            }

                            if self.regs.ecx > 0 {
                                self.set_eip(addr, false);
                                break;
                            }

                        } else {
                            if self.regs.get_cx() == 0 {
                                self.regs.set_cx(0xffff);
                            } else {
                                self.regs.set_cx(self.regs.get_cx() -1);
                            }
                
                            if self.regs.get_cx() > 0 {
                                self.set_eip(addr, false);
                                break;
                            }
                        }
                    }
    
                    Mnemonic::Loope => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.yellow, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        assert!(ins.op_count() == 1);

                        let addr = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        if addr > 0xffff {
                            if self.regs.ecx == 0 {
                                self.regs.ecx = 0xffffffff;
                            } else {
                                self.regs.ecx -= 1;
                            }
                            
                            if self.regs.ecx > 0 && self.flags.f_zf {
                                self.set_eip(addr, false);
                                break;
                            }
                        } else {
                            if self.regs.get_cx() == 0 {
                                self.regs.set_cx(0xffff);
                            } else {
                                self.regs.set_cx(self.regs.get_cx() -1);
                            }
                            
                            if self.regs.get_cx() > 0 && self.flags.f_zf  {
                                self.set_eip(addr, false);
                                break;
                            }
                        }
                    }

                    Mnemonic::Loopne => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.yellow, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        assert!(ins.op_count() == 1);

                        let addr = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };
                        
                        if addr > 0xffff {
                            if self.regs.ecx == 0 {
                                self.regs.ecx = 0xffffffff;
                            } else {
                                self.regs.ecx -= 1;
                            }
                            
                            if self.regs.ecx > 0 && !self.flags.f_zf {
                                self.set_eip(addr, false);
                                break;
                            }
                        } else {
                            if self.regs.get_cx() == 0 {
                                self.regs.set_cx(0xffff);
                            } else {
                                self.regs.set_cx(self.regs.get_cx() -1);
                            }
                            
                            if self.regs.get_cx() > 0 && !self.flags.f_zf  {
                                self.set_eip(addr, false);
                                break;
                            }
                        }
                    }

                    Mnemonic::Lea => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.light_cyan, self.pos, ins.ip32(), out, self.colors.nc);
                        }

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
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.red, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        self.regs.esp = self.regs.ebp;
                        self.regs.ebp = self.stack_pop(true);
                    }

                    Mnemonic::Int => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.red, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        assert!(ins.op_count() == 1);

                        let interrupt = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        match interrupt {
                            0x80 => syscall32::gateway(self),
                            _ => unimplemented!("unknown interrupt {}", interrupt),
                        }
                    }

                    Mnemonic::Std => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.blue, self.pos, ins.ip32(), out, self.colors.nc);
                        }
                        self.flags.f_df = true;
                    }

                    Mnemonic::Cld => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.blue, self.pos, ins.ip32(), out, self.colors.nc);
                        }
                        self.flags.f_df = false;
                    }

                    Mnemonic::Lodsd => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.cyan, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        let val = match self.maps.read_dword(self.regs.esi) {
                            Some(v) => v,
                            None => panic!("lodsw: memory read error"),
                        };

                        self.regs.eax = val;
                        if self.flags.f_df {
                            self.regs.esi -= 4;
                        } else {
                            self.regs.esi += 4;
                        }

                    }

                    Mnemonic::Lodsw => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.cyan, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        let val = match self.maps.read_word(self.regs.esi) {
                            Some(v) => v,
                            None => panic!("lodsw: memory read error"),
                        };

                        self.regs.eax = val as u32;
                        if self.flags.f_df {
                            self.regs.esi -= 2;
                        } else {
                            self.regs.esi += 2;
                        }
                    }

                    Mnemonic::Lodsb => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.cyan, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        let val = match self.maps.read_byte(self.regs.esi) {
                            Some(v) => v,
                            None => panic!("lodsw: memory read error"),
                        };

                        self.regs.set_ax(val as u32);
                        if self.flags.f_df {
                            self.regs.esi -= 1;
                        } else {
                            self.regs.esi += 1;
                        }
                    }

                    ///// FPU /////  https://github.com/radare/radare/blob/master/doc/xtra/fpu
                     
                    Mnemonic::Ffree => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }
          
                  
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
                       
                        self.fpu.set_eip(self.regs.eip);
                    }

                    Mnemonic::Fnstenv => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        let addr = match self.get_operand_value(&ins, 0, false) {
                            Some(v) => v,
                            None => break,
                        };

                        let env = self.fpu.get_env();
                        for i in 0..4 {
                            self.maps.write_dword(addr+(i*4), env[i as usize]);
                        }

                        self.fpu.set_eip(self.regs.eip);
                    }
    
                    Mnemonic::Fld => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        self.fpu.set_eip(self.regs.eip);
                    }

                    Mnemonic::Fldz => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        self.fpu.push(0.0);
                        self.fpu.set_eip(self.regs.eip);
                    }

                    Mnemonic::Fld1 => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        self.fpu.push(1.0);
                        self.fpu.set_eip(self.regs.eip);
                    }

                    Mnemonic::Fldpi => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        self.fpu.push(std::f32::consts::PI);
                        self.fpu.set_eip(self.regs.eip);
                    }

                    Mnemonic::Fldl2t => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        self.fpu.push(10f32.log2());
                        self.fpu.set_eip(self.regs.eip);
                    }

                    Mnemonic::Fldlg2 => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        self.fpu.push(2f32.log10());
                        self.fpu.set_eip(self.regs.eip);
                    }

                    Mnemonic::Fldln2 => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        self.fpu.push(2f32.log(std::f32::consts::E));
                        self.fpu.set_eip(self.regs.eip);
                    }

                    Mnemonic::Fldl2e => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        self.fpu.push(std::f32::consts::E.log2());
                        self.fpu.set_eip(self.regs.eip);
                    }

                    Mnemonic::Fcmove => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

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

                        self.fpu.set_eip(self.regs.eip);
                    }

                    Mnemonic::Fcmovb => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

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

                        self.fpu.set_eip(self.regs.eip);
                    }

                    Mnemonic::Fcmovbe => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

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

                        self.fpu.set_eip(self.regs.eip);
                    }

                    Mnemonic::Fcmovu => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

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

                        self.fpu.set_eip(self.regs.eip);
                    }

                    Mnemonic::Fcmovnb => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

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

                        self.fpu.set_eip(self.regs.eip);
                    }

                    Mnemonic::Fcmovne => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

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

                        self.fpu.set_eip(self.regs.eip);
                    }

                    Mnemonic::Fcmovnbe => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

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

                        self.fpu.set_eip(self.regs.eip);
                    }

                    Mnemonic::Fcmovnu => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

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

                        self.fpu.set_eip(self.regs.eip);
                    }

                    Mnemonic::Popf => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.blue, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        let flags:u16 = match self.maps.read_word(self.regs.esp) {
                            Some(v) => v,
                            None => {
                                eprintln!("popf cannot read the stack");
                                self.exception();
                                break;
                            }
                        };

                        let flags2:u32 = (self.flags.dump() & 0xffff0000) + (flags as u32);
                        self.flags.load(flags2);
                        self.regs.esp += 2;
                    }

                    Mnemonic::Popfd => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.blue, self.pos, ins.ip32(), out, self.colors.nc);
                        }


                        let flags = self.stack_pop(true);
                        self.flags.load(flags);
                    }

                    Mnemonic::Sete => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        if self.flags.f_zf {
                            self.set_operand_value(&ins, 0, 1);
                        }
                    }

                    Mnemonic::Daa => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

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
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let value1 = match self.get_operand_value(&ins, 1, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let counter = match self.get_operand_value(&ins, 2, true) {
                            Some(v) => v as u16,
                            None => break,
                        };

                        let sz = self.get_operand_sz(&ins, 0);
                        let result = self.shld(value0, value1, counter, sz as u32);

                        //println!("0x{:x} SHLD 0x{:x}, 0x{:x}, 0x{:x} = 0x{:x}", ins.ip32(), value0, value1, counter, result);

                        if !self.set_operand_value(&ins, 0, result) {
                            break;
                        }
                    }

                    Mnemonic::Shrd => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        let value0 = match self.get_operand_value(&ins, 0, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let value1 = match self.get_operand_value(&ins, 1, true) {
                            Some(v) => v,
                            None => break,
                        };

                        let counter = match self.get_operand_value(&ins, 2, true) {
                            Some(v) => v as u16,
                            None => break,
                        };

                        let sz = self.get_operand_sz(&ins, 0);
                        let result = self.shrd(value0, value1, counter, sz as u32);
                        
                        //println!("0x{:x} SHRD 0x{:x}, 0x{:x}, 0x{:x} = 0x{:x}", ins.ip32(), value0, value1, counter, result);
                        
                        if !self.set_operand_value(&ins, 0, result) {
                            break;
                        }
                    }


                    Mnemonic::Sysenter => {
                        println!("{}{} 0x{:x}: {}{}", self.colors.red, self.pos, ins.ip32(), out, self.colors.nc);
                        return;
                    }

                    //// SSE XMM //// 
                    // scalar: only gets the less significative part.
                    // scalar simple: only 32b less significative part.
                    // scalar double: only 54b less significative part.
                    // packed: compute all parts.
                    // packed double: 
                    

                    Mnemonic::Pxor => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        assert!(ins.op_count() == 2);

                        let value0 = self.get_operand_xmm_value_128(&ins, 0, true).expect("error getting xmm value0");
                        let value1 = self.get_operand_xmm_value_128(&ins, 0, true).expect("error getting xmm value1");

                        let result:u128 = value0 ^ value1;
                        self.flags.calc_flags(result as u32, 32);

                        self.set_operand_xmm_value_128(&ins, 0, result);
                    }

                    Mnemonic::Xorps => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

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
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

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
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.cyan, self.pos, ins.ip32(), out, self.colors.nc);
                        }

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
                            self.set_operand_value(&ins, 0, value1 as u32);

                        } else if sz0 == 128 && sz1 == 64 {
                            let addr = self.get_operand_value(&ins, 1, false).expect("error getting the address");
                            let value1 = self.maps.read_qword(addr).expect("error getting qword");
                            self.set_operand_xmm_value_128(&ins, 0, value1 as u128);

                        } else if sz0 == 64 && sz1 == 128 {
                            let value1 = self.get_operand_xmm_value_128(&ins, 1, true).expect("error getting xmm value");
                            self.set_operand_value(&ins, 0, value1 as u32);

                        } else {
                            panic!("SSE with other size combinations sz0:{} sz1:{}", sz0, sz1);
                        }
                    }

                    Mnemonic::Andpd => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        let value0 = self.get_operand_xmm_value_128(&ins, 0, true).expect("error getting value0");
                        let value1 = self.get_operand_xmm_value_128(&ins, 1, true).expect("error getting velue1");

                        let result:u128 = value0 & value1;

                        self.set_operand_xmm_value_128(&ins, 0, result);
                    }

                    Mnemonic::Orpd => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        let value0 = self.get_operand_xmm_value_128(&ins, 0, true).expect("error getting value0");
                        let value1 = self.get_operand_xmm_value_128(&ins, 1, true).expect("error getting velue1");

                        let result:u128 = value0 | value1;

                        self.set_operand_xmm_value_128(&ins, 0, result);
                    }

                    Mnemonic::Addps => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

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
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        let value0 = self.get_operand_xmm_value_128(&ins, 0, true).expect("error getting value0");
                        let value1 = self.get_operand_xmm_value_128(&ins, 1, true).expect("error getting velue1");

                        let a:u128 = (value0 & 0xffffffff_ffffffff) + (value1 & 0xffffffff_ffffffff);
                        let b:u128 = (value0 & 0xffffffff_ffffffff_00000000_00000000) + (value1 & 0xffffffff_ffffffff_00000000_00000000);
                        let result:u128 = a | b;

                        self.set_operand_xmm_value_128(&ins, 0, result);
                    }

                    Mnemonic::Addsd => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        let value0 = self.get_operand_xmm_value_128(&ins, 0, true).expect("error getting value0");
                        let value1 = self.get_operand_xmm_value_128(&ins, 1, true).expect("error getting velue1");

                        let result:u64 = value0 as u64 + value1 as u64;
                        let r128:u128 = (value0 & 0xffffffffffffffff0000000000000000) + result as u128; 
                        self.set_operand_xmm_value_128(&ins, 0, r128);
                    }

                    Mnemonic::Addss => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        let value0 = self.get_operand_xmm_value_128(&ins, 0, true).expect("error getting value0");
                        let value1 = self.get_operand_xmm_value_128(&ins, 1, true).expect("error getting velue1");

                        let result:u32 = value0 as u32 + value1 as u32;
                        let r128:u128 = (value0 & 0xffffffffffffffffffffffff00000000) + result as u128; 
                        self.set_operand_xmm_value_128(&ins, 0, r128);
                    }

                    Mnemonic::Subps => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

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
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        let value0 = self.get_operand_xmm_value_128(&ins, 0, true).expect("error getting value0");
                        let value1 = self.get_operand_xmm_value_128(&ins, 1, true).expect("error getting velue1");

                        let a:u128 = (value0 & 0xffffffff_ffffffff) - (value1 & 0xffffffff_ffffffff);
                        let b:u128 = (value0 & 0xffffffff_ffffffff_00000000_00000000) - (value1 & 0xffffffff_ffffffff_00000000_00000000);
                        let result:u128 = a | b;

                        self.set_operand_xmm_value_128(&ins, 0, result);
                    }

                    Mnemonic::Subsd => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        let value0 = self.get_operand_xmm_value_128(&ins, 0, true).expect("error getting value0");
                        let value1 = self.get_operand_xmm_value_128(&ins, 1, true).expect("error getting velue1");

                        let result:u64 = value0 as u64 - value1 as u64;
                        let r128:u128 = (value0 & 0xffffffffffffffff0000000000000000) + result as u128; 
                        self.set_operand_xmm_value_128(&ins, 0, r128);
                    }

                    Mnemonic::Subss => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        let value0 = self.get_operand_xmm_value_128(&ins, 0, true).expect("error getting value0");
                        let value1 = self.get_operand_xmm_value_128(&ins, 1, true).expect("error getting velue1");

                        let result:u32 = value0 as u32 - value1 as u32;
                        let r128:u128 = (value0 & 0xffffffffffffffffffffffff00000000) + result as u128; 
                        self.set_operand_xmm_value_128(&ins, 0, r128);
                    }

                    Mnemonic::Mulpd => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        let value0 = self.get_operand_xmm_value_128(&ins, 0, true).expect("error getting value0");
                        let value1 = self.get_operand_xmm_value_128(&ins, 1, true).expect("error getting velue1");

                        let left:u128 = ((value0 & 0xffffffffffffffff0000000000000000)>>64) * ((value1 & 0xffffffffffffffff0000000000000000)>>64);
                        let right:u128 = (value0 & 0xffffffffffffffff) * (value1 & 0xffffffffffffffff);
                        let result:u128 = left << 64 | right; 

                        self.set_operand_xmm_value_128(&ins, 0, result);
                    }

                    Mnemonic::Mulps => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

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
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        let value0 = self.get_operand_xmm_value_128(&ins, 0, true).expect("error getting value0");
                        let value1 = self.get_operand_xmm_value_128(&ins, 1, true).expect("error getting velue1");

                        let result:u64 = value0 as u64 * value1 as u64;
                        let r128:u128 = (value0 & 0xffffffffffffffff0000000000000000) + result as u128; 
                        self.set_operand_xmm_value_128(&ins, 0, r128);
                    }

                    Mnemonic::Mulss => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        let value0 = self.get_operand_xmm_value_128(&ins, 0, true).expect("error getting value0");
                        let value1 = self.get_operand_xmm_value_128(&ins, 1, true).expect("error getting velue1");

                        let result:u32 = value0 as u32 * value1 as u32;
                        let r128:u128 = (value0 & 0xffffffffffffffffffffffff00000000) + result as u128; 
                        self.set_operand_xmm_value_128(&ins, 0, r128);
                    }

                    // end SSE


                    Mnemonic::Arpl => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.orange, self.pos, ins.ip32(), out, self.colors.nc);
                        }

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
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.blue, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        let val:u16 = (self.flags.dump() & 0xffff) as u16;

                        self.regs.esp -= 2;

                        if !self.maps.write_word(self.regs.esp, val) {
                            self.exception();
                            break;
                        }
                    }

                    Mnemonic::Pushfd => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.blue, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        let flags = self.flags.dump();
                        self.stack_push(flags);
                    }

                    Mnemonic::Bound => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.red, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        let val0_src = self.get_operand_value(&ins, 0, true);

                    }

                    Mnemonic::Lahf => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.red, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        self.regs.set_ah(self.flags.dump() & 0xff);
                    }


                    Mnemonic::Salc => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.red, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        if self.flags.f_cf {
                            self.regs.set_al(1);
                        } else {
                            self.regs.set_al(0);
                        }
                    }


                    ////   Ring0  ////
                    
                    Mnemonic::Rdmsr => {
                        if !step {
                            println!("{}{} 0x{:x}: {}{}", self.colors.green, self.pos, ins.ip32(), out, self.colors.nc);
                        }

                        match self.regs.ecx {
                            0x176 => {
                                self.regs.edx = 0;
                                self.regs.eax = self.cfg.code_base_addr + 0x42;
                            },
                            _ => unimplemented!("/!\\ unimplemented rdmsr with value {}", self.regs.ecx),
                        }

                    }                    

                    _ =>  { 
                        println!("{}{} 0x{:x}: {}{}", self.colors.red, self.pos, ins.ip32(), out, self.colors.nc);
                        self.exception();
                        //unimplemented!("unimplemented instruction");
                    },
                }

                self.regs.eip += sz as u32;
                
                if self.force_break {
                    self.force_break = false;
                    break;
                }
            }
        }   

        

    }

}
