/*
    TODO:
        - scripting
        - console dissasembler option
        - intead of panic spawn console
        - set the code base addr
        - refactor and improve winapi
        - set the entry point
        - randomize initial register for avoid targeted anti-amulation
        - show registers pointing strings, or pops
        - on every set_eip of a non branch dump stack to log file
        - implement scas & rep
        - implement imul
        - check pf flag bug
        - save state to disk and continue
        - command to exit the bucle or to see  next instruction
        - optimize loop counter
        - configuration file with:
            - break_on_alert
            - show loop, loop limit and loop print
            - disable colors
            - log to file
            - dont print instruction
        - search in all the maps 


    there is an er-ror, error in the ror implementation:
        mov eax, 0x54
        ror eax, 0xd

        eax should be 0x02a00000



    metasploit:

    13 0x3c000b: mov edx, dword ptr fs:[edx + 0x30]   <-- poor detection of  fs:[0x30] or fs:[0]

        poner bp en 0x3c006b

        7915429 0x3c0020: lodsb al, byte ptr [esi]
        --- console ---
        =>r esi
        esi: 0x3b3000
        =>mn
        address=>0x3b3000
        address at 'reserved2' map
        =>md
        address=>0x3b3000
        thread 'main' panicked at 'index out of bounds: the len is 983040 but the index is 983040', src/emu32/maps/mem32.rs:76:11



    guloader:
        8273 --> exit the loop

                        9911 0xc794: mov dword ptr [ebp + 4], eax ---> has to point to kernel32 base address
        9911 0x3ccfa1: movzx ebx, byte ptr [esi]

        8500 0x3ccfc6: ret 4 ---> since here all ok

        0x3cca37: ret 4 ---> iterating api names


        747332 0x3cca37: ret 4 --> LoadLibraryA

        747358 0x3cc73d: call dword ptr [ebp + 0xc] --> jump to kernel32


        747505 0x775c2c11: push dword ptr fs:[0] ---> SEH  (debugger stop by here?)


        ** ntdll_NtGetContextThread   ctx flags:0x0 
        ** ntdll_RtlVectoredExceptionHandler   callback:0x3cff59 

        int3
        jump the exception pointer (y/n)?=>
        1937615 0x3cff59: mov eax, dword ptr [esp + 4]                (debuger has this ptrs?)
        1937616 0x3cff5d: mov eax, dword ptr [eax + 4]
        1937617 0x3cff60: mov edx, dword ptr [eax + 0xb8]



*/

#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(unused_variables)]

extern crate capstone;

mod winapi;
mod flags; 
mod eflags;
mod maps;
mod regs32;
mod console;
mod colors;
mod constants;

use flags::Flags;
use eflags::Eflags;
use maps::Maps;
use regs32::Regs32;
use console::Console;
use colors::Colors;

use capstone::prelude::*;


pub struct Emu32 {
    regs: Regs32,
    flags: Flags,
    eflags: Eflags,
    maps: Maps,
    exp: u32,
    break_on_alert: bool,
    loop_print: u32,
    loop_limit: u32,
    bp: u32,
    detailed: bool,
    seh: u32,
    veh: u32,
    showregs: bool,
    iter: bool,
    quick: bool,
    tracemem: bool,
}

impl Emu32 {
    pub fn new() -> Emu32 {
        Emu32{
            regs: Regs32::new(),
            flags: Flags::new(),
            eflags: Eflags::new(),
            maps: Maps::new(),
            exp: 0,
            break_on_alert: false,
            loop_print: 2,
            loop_limit: 1000000,
            bp: 0,
            detailed: false,
            seh: 0,
            veh: 0,
            showregs: false,
            iter: false,
            quick: false,
            tracemem: false,
        }
    }

    pub fn init_stack(&mut self) {
        let stack = self.maps.get_mem("stack");
        stack.set_base(0x22d000);
        stack.set_size(0x3000);
        self.regs.esp = 0x22e000;
        self.regs.ebp = 0x22f000;

        assert!(self.regs.esp < self.regs.ebp);
        assert!(self.regs.esp > stack.get_base());
        assert!(self.regs.esp < stack.get_bottom());
        assert!(self.regs.ebp > stack.get_base());
        assert!(self.regs.ebp < stack.get_bottom());
        assert!(stack.inside(self.regs.esp));
        assert!(stack.inside(self.regs.ebp));
        //let q = (stack.size() as u32) / 4;
    }

    pub fn init(&mut self) {
        println!("initializing regs");
        self.regs.clear();
        //self.regs.esp = 0x22f000;
        //self.regs.ebp = 0x00100f00;
        self.regs.eip = 0x003c0000;
        //TODO: randomize initial register for avoid targeted anti-amulation
        self.regs.eax = 0;
        self.regs.ebx = 0x0022ee88;
        self.regs.ecx = 0x0022ee9c;
        self.regs.edx = 0x36b32038;
        self.regs.esi = 0x0022f388;
        self.regs.edi = 0;

        println!("initializing code and stack");

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
        self.maps.create_map("reserved2");


        //self.maps.write_byte(0x2c3000, 0x61); // metasploit trick

        self.init_stack();

        let m10000 = self.maps.get_mem("10000");
        m10000.set_base(0x10000);
        m10000.set_size(0x10000);
        
        let m20000 = self.maps.get_mem("20000");
        m20000.set_base(0x20000);
        m20000.set_size(0x10000);

        self.maps.get_mem("code").set_base(self.regs.eip);
        let kernel32 = self.maps.get_mem("kernel32");
        kernel32.set_base(0x75e40000);
        kernel32.load("maps/kernel32.bin");

        let kernel32_text = self.maps.get_mem("kernel32_text");
        kernel32_text.set_base(0x75e41000);
        kernel32_text.load("maps/kernel32_text.bin");

        let kernel32_data = self.maps.get_mem("kernel32_data");
        kernel32_data.set_base(0x75f06000);
        kernel32_data.load("maps/kernel32_data.bin");

        let kernelbase = self.maps.get_mem("kernelbase");
        kernelbase.set_base(0x75940000);
        kernelbase.load("maps/kernelbase.bin");

        let kernelbase_text = self.maps.get_mem("kernelbase_text");
        kernelbase_text.set_base(0x75941000);
        kernelbase_text.load("maps/kernelbase_text.bin");

        let kernelbase_data = self.maps.get_mem("kernelbase_data");
        kernelbase_data.set_base(0x75984000);
        kernelbase_data.load("maps/kernelbase_data.bin");

        let msvcrt = self.maps.get_mem("msvcrt");
        msvcrt.set_base(0x761e0000);
        msvcrt.load("maps/msvcrt.bin");

        let msvcrt_text = self.maps.get_mem("msvcrt_text");
        msvcrt_text.set_base(0x761e1000);
        msvcrt_text.load("maps/msvcrt_text.bin");

        let reserved = self.maps.get_mem("reserved");
        reserved.set_base(0x002c0000);
        reserved.load("maps/reserved.bin");

        let peb = self.maps.get_mem("peb");
        peb.set_base(  0x7ffdf000);
        peb.load("maps/peb.bin");

        let teb = self.maps.get_mem("teb");
        teb.set_base(  0x7ffde000);
        teb.load("maps/teb.bin");

        let ntdll = self.maps.get_mem("ntdll");
        ntdll.set_base(0x77570000);
        ntdll.load("maps/ntdll.bin");

        let ntdll_text = self.maps.get_mem("ntdll_text");
        ntdll_text.set_base(0x77571000);
        ntdll_text.load("maps/ntdll_text.bin");

        let ntdll_data = self.maps.get_mem("ntdll_data");
        ntdll_data.set_base(0x77647000);
        ntdll_data.load("maps/ntdll_data.bin");

        let kuser_shared_data = self.maps.get_mem("kuser_shared_data");
        kuser_shared_data.set_base(0x7ffe0000);
        kuser_shared_data.load("maps/kuser_shared_data.bin");

        let binary = self.maps.get_mem("binary");
        binary.set_base(0x400000);
        binary.set_size(0x1000);

        let reserved2 = self.maps.get_mem("reserved2");
        reserved2.set_base(0x2c3000);
        reserved2.set_size(0xfd000);

        // xloader initial state hack
        //self.memory_write("dword ptr [esp + 4]", 0x22a00);
        //self.maps.get_mem("kernel32_xloader").set_base(0x75e40000);
    }

    pub fn explain(&mut self, line: &str) {
        self.exp = u32::from_str_radix(line, 10).expect("bad num conversion");
        println!("explaining line {}", self.exp);
    }

    pub fn mode_quick(&mut self) {
        self.quick = true;
    }

    pub fn mode_loop(&mut self) {
        self.iter = true;
    }

    pub fn mode_regs(&mut self) {
        self.showregs = true;
    }

    pub fn mode_tracemem(&mut self) {
        self.tracemem = true;
    }

    pub fn load_code(&mut self, filename: &String) {
        self.maps.get_mem("code").load(filename);
    }

    pub fn stack_push(&mut self, value:u32) {
        self.regs.esp -= 4;
        self.maps.get_mem("stack").write_dword(self.regs.esp, value);
    }

    pub fn stack_pop(&mut self, pop_instruction:bool) -> u32 {
        let value = self.maps.get_mem("stack").read_dword(self.regs.esp);
        if pop_instruction && self.maps.get_mem("code").inside(value) {
            if self.break_on_alert {
                panic!("/!\\ poping a code address 0x{:x}", value);
            } else {
                println!("/!\\ poping a code address 0x{:x}", value);
            }
        }
        self.regs.esp += 4;
        return value;
    }

    pub fn memory_operand_to_address(&mut self, operand:&str) -> u32 {

        let spl:Vec<&str> = operand.split("[").collect::<Vec<&str>>()[1].split("]").collect::<Vec<&str>>()[0].split(" ").collect();

        if operand.contains("fs:[") || operand.contains("gs:[") {
            let mem = operand.split(":").collect::<Vec<&str>>()[1];
            let value = self.memory_operand_to_address(mem);

            /*
                fs:[0x30]
                fs:[ecx + 0x30]  ecx:0  <-- TODO: implement this


                FS:[0x00] : Current SEH Frame
                FS:[0x18] : TEB (Thread Environment Block)
                FS:[0x20] : PID
                FS:[0x24] : TID
                FS:[0x30] : PEB (Process Environment Block)
                FS:[0x34] : Last Error Value
            */

            //let inm = self.get_inmediate(spl[0]);
            println!("FS ACCESS TO 0x{:x}", value);

            if value == 0x30 { // PEB
                println!("ACCESS TO PEB");
                let peb = self.maps.get_mem("peb");
                return peb.get_base();
            }

            if value == 0x18 {
                println!("ACCESS TO TEB");
                let teb = self.maps.get_mem("teb");
                return teb.get_base();
            }

            panic!("not implemented: {}", operand);
        }

        if spl.len() == 3 { //ie eax + 0xc
            let sign = spl[1];

            // weird case: [esi + eax*4]
            if spl[2].contains("*") {
                let spl2:Vec<&str> = spl[2].split("*").collect();
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

                panic!("weird situation");
                
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

        return 0
    }
    
    pub fn memory_read(&mut self, operand:&str) -> Option<u32> {
        if operand.contains("fs:[0]") {
            println!("Reading SEH fs:[0] 0x{:x}", self.seh);
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
                        if self.tracemem {
                            let name = match self.maps.get_addr_name(addr) {
                                Some(n) => n,
                                None => "error".to_string(),
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
                        if self.tracemem {
                            let name = match self.maps.get_addr_name(addr) {
                                Some(n) => n,
                                None => "error".to_string(),
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
                        if self.tracemem {
                            let name = match self.maps.get_addr_name(addr) {
                                Some(n) => n,
                                None => "error".to_string(),
                            };
                            println!("mem trace read -> '{}' 0x{:x}: 0x{:x}  map:'{}'", operand, addr, v, name);
                        }
                        return Some((v as u32) & 0xff);
                    },
                    None => return None,
                }
            },
             _ => panic!("weird precision: {}", operand),
        };

    }

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

        if self.tracemem {
            let name = match self.maps.get_addr_name(addr) {
                Some(n) => n,
                None => "error".to_string(),
            };
            println!("mem trace write -> '{}' 0x{:x}: 0x{:x}  map:'{}'", operand, addr, value, name);
        }

        let bits = self.get_size(operand);
        let ret = match bits {
            32 => self.maps.write_dword(addr, value),
            16 => self.maps.write_word(addr, (value & 0x0000ffff) as u16),
             8 => self.maps.write_byte(addr, (value & 0x000000ff) as u8),
             _ => panic!("weird precision: {}", operand)
        };

        return ret;
    }

    pub fn set_eip(&mut self, addr:u32, is_branch:bool) {

        let name = self.maps.get_addr_name(addr).expect("setting eip to non mapped addr");

        if name == "code" || addr < 0x70000000 {
            self.regs.eip = addr;
        } else {
            println!("/!\\ changing EIP to {} ", name);

            let retaddr = self.stack_pop(false);

            //TODO: centralize this, is repeated on call
            if name == "kernel32_text" {
                self.kernel32_api(addr);
            } else if name == "ntdll_text" {
                self.ntdll_api(addr);
            } else if name == "user32_text" {
                self.user32_api(addr);
            }

            self.regs.eip += 2; 
            //self.regs.eip = retaddr;
        }


        //TODO: lanzar memory scan code.scan() y stack.scan()
        // escanear en cambios de eip pero no en bucles, evitar escanear en bucles!
    }

    pub fn is_reg(&self, operand:&str) -> bool {
        match operand {
            "eax"|"ebx"|"ecx"|"edx"|"esi"|"edi"|"esp"|"ebp"|"eip"|"ax"|"bx"|"cx"|"dx"|"si"|"di"|"al"|"ah"|"bl"|"bh"|"cl"|"ch"|"dl"|"dh" => return true,
            &_ => return false,
        }
    }

    pub fn get_inmediate(&self, operand:&str) -> u32 {
        
        if operand.contains("0x") {
            return u32::from_str_radix(operand.get(2..).unwrap(), 16).unwrap();
        } else if operand.contains("-") {
            let num = u32::from_str_radix(operand.get(1..).unwrap(), 16).unwrap();
            return 0xffffffff - num + 1;
        } else {
            return u32::from_str_radix(operand, 16).unwrap();
        }
    }

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

        panic!("weird precision: {}", operand);
    }


    /// FLAGS ///
    /// 
    /// overflow 0xffffffff + 1     
    /// carry    0x7fffffff + 1     o  0x80000000 - 1       o    0 - 1
    

    pub fn flags_add32(&mut self, value1:u32, value2:u32) -> u32 {
        let unsigned:u64 = value1 as u64 + value2 as u64;

        self.flags.f_sf = (unsigned as i32) < 0;
        self.flags.f_zf = unsigned == 0;
        self.flags.f_pf = (unsigned & 0xff) % 2 == 0;
        self.flags.f_of = (value1 as i32) > 0 && (unsigned as i32) < 0;
        self.flags.f_cf = unsigned > 0xffffffff;

        return (unsigned & 0xffffffff) as u32;
    }

    pub fn flags_add16(&mut self, value1:u32, value2:u32) -> u32 {
        if value1 > 0xffff || value2 > 0xffff {
            panic!("flags_add16 with a bigger precision");
        }

        let unsigned:u32 = value1 as u32 + value2 as u32;

        self.flags.f_sf = (unsigned as i16) < 0;
        self.flags.f_zf = unsigned == 0;
        self.flags.f_pf = (unsigned & 0xff) % 2 == 0;
        self.flags.f_of = (value1 as i16) > 0 && (unsigned as i16) < 0;
        self.flags.f_cf = unsigned > 0xffff;

        return (unsigned & 0xffff) as u32;
    }

    pub fn flags_add8(&mut self, value1:u32, value2:u32) -> u32 {
        if value1 > 0xff || value2 > 0xff {
            panic!("flags_add8 with a bigger precision");
        }

        let unsigned:u16 = value1 as u16 + value2 as u16;

        self.flags.f_sf = (unsigned as i8) < 0;
        self.flags.f_zf = unsigned == 0;
        self.flags.f_pf = unsigned % 2 == 0;
        self.flags.f_of = (value1 as i8) > 0 && (unsigned as i8) < 0;
        self.flags.f_cf = unsigned > 0xff;

        return (unsigned & 0xff) as u32;
    }

    pub fn flags_sub32(&mut self, value1:u32, value2:u32) -> u32 {
        let r:i32;


        self.flags.check_carry_sub_dword(value1, value2);
        r = self.flags.check_overflow_sub_dword(value1, value2);
        self.flags.f_zf = value1 == value2;

        self.flags.f_sf = r < 0;
        self.flags.f_pf = ((r as u32) & 0xff) % 2 == 0;

        return r as u32;
    }

    pub fn flags_sub16(&mut self, value1:u32, value2:u32) -> u32 {
        let r:i16;


        self.flags.check_carry_sub_word(value1, value2);
        r = self.flags.check_overflow_sub_word(value1, value2);
        self.flags.f_zf = value1 == value2;

        self.flags.f_sf = r < 0;
        self.flags.f_pf = ((r as u16) & 0xff) % 2 == 0;

        return (r as u16) as u32;
    }

    pub fn flags_sub8(&mut self, value1:u32, value2:u32) -> u32 {
        let r:i8;

        self.flags.check_carry_sub_byte(value1, value2);
        r = self.flags.check_overflow_sub_byte(value1, value2);
        self.flags.f_zf = value1 == value2;

        self.flags.f_sf = r < 0;
        self.flags.f_pf = ((r as u8) & 0xff) % 2 == 0;
        return (r as u8) as u32;
    }






    pub fn flags_inc32(&mut self, value:u32) -> u32 { 
        if value == 0xffffffff {
            self.flags.f_zf = true;
            self.flags.f_pf = true;
            self.flags.f_af = true;
            return 0;
        }
        self.flags.f_of = value == 0x7fffffff;
        self.flags.f_sf = value > 0x7fffffff;
        self.flags.f_pf = (((value as i32) +1) & 0xff) % 2 == 0;
        self.flags.f_zf = false;
        return value + 1;
    }

    pub fn flags_inc16(&mut self, value:u32) -> u32 {
        if value == 0xffff {
            self.flags.f_zf = true;
            self.flags.f_pf = true;
            self.flags.f_af = true;
            return 0;
        }
        self.flags.f_of = value == 0x7fff;
        self.flags.f_sf = value > 0x7fff;
        self.flags.f_pf = (((value as i32) +1) & 0xff) % 2 == 0;
        self.flags.f_zf = false;
        return value + 1;
    }

    pub fn flags_inc8(&mut self, value:u32) -> u32 {
        if value == 0xff {
            self.flags.f_zf = true;
            self.flags.f_pf = true;
            self.flags.f_af = true;
            return 0;
        }
        self.flags.f_of = value == 0x7f;
        self.flags.f_sf = value > 0x7f;
        self.flags.f_pf = (((value as i32) +1) & 0xff) % 2 == 0;
        self.flags.f_zf = false;
        return value + 1;
    }

    pub fn flags_dec32(&mut self, value:u32) -> u32 { 
        if value == 0 {
            self.flags.f_pf = true;
            self.flags.f_af = true;
            self.flags.f_sf = true;
            return 0xffffffff;
        }
        self.flags.f_of = value == 0x80000000;
        self.flags.f_pf = (((value as i32) -1) & 0xff) % 2 == 0;
        self.flags.f_af = false;
        self.flags.f_sf = false;

        self.flags.f_zf = value == 1;

        return value - 1;
    }

    pub fn flags_dec16(&mut self, value:u32) -> u32 { 
        if value == 0 {
            self.flags.f_pf = true;
            self.flags.f_af = true;
            self.flags.f_sf = true;
            return 0xffff;
        }
        self.flags.f_of = value == 0x8000;
        self.flags.f_pf = (((value as i32) -1) & 0xff) % 2 == 0;
        self.flags.f_af = false;
        self.flags.f_sf = false;

        self.flags.f_zf = value == 1;

        return value - 1;
    }

    pub fn flags_dec8(&mut self, value:u32) -> u32 { 
        if value == 0 {
            self.flags.f_pf = true;
            self.flags.f_af = true;
            self.flags.f_sf = true;
            return 0xff;
        }
        self.flags.f_of = value == 0x80;
        self.flags.f_pf = (((value as i32) -1) & 0xff) % 2 == 0;
        self.flags.f_af = false;
        self.flags.f_sf = false;

        self.flags.f_zf = value == 1;

        return value - 1;
    }

    pub fn calc_flags(&mut self, final_value:u32, bits:u8) {
        
        match bits {
            32 => self.flags.f_sf = (final_value as i32) < 0,
            16 => self.flags.f_sf = (final_value as i16) < 0,
            8  => self.flags.f_sf = (final_value as i8) < 0,
            _ => panic!("weird precision")
        }
        
        self.flags.f_zf = final_value == 0;
        self.flags.f_pf = (final_value & 0xff) % 2 == 0;
        self.flags.f_tf = false;        
    }

    pub fn rotate_left(&self, val:u32, rot:u32, bits:u32) -> u32 {
        return (val << rot) | (val >> bits-rot);
    }

    pub fn rotate_right(&self, val:u32, rot:u32, bits:u32) -> u32 {
        //TODO: care with overflow
        return (val >> rot) | (val << bits-rot);
    }

    pub fn spawn_console(&mut self) {
        let con = Console::new();
        loop {
            let cmd = con.cmd();
            match cmd.as_str() {
                "q" => std::process::exit(1),
                "h" => con.help(),
                "r" => self.regs.print(),
                "r eax" => println!("eax: 0x{:x}", self.regs.eax),
                "r ebx" => println!("ebx: 0x{:x}", self.regs.ebx),
                "r ecx" => println!("ecx: 0x{:x}", self.regs.ecx),
                "r edx" => println!("edx: 0x{:x}", self.regs.edx),
                "r esi" => println!("esi: 0x{:x}", self.regs.esi),
                "r edi" => println!("edi: 0x{:x}", self.regs.edi),
                "r esp" => println!("esp: 0x{:x}", self.regs.esp),
                "r ebp" => println!("ebp: 0x{:x}", self.regs.ebp),
                "r eip" => println!("eip: 0x{:x}", self.regs.eip),
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
                            println!("bad address");
                            continue;
                        },
                    };
                    println!("0x{:x}: 0x{:x}", addr, value);
                },
                "mw"|"wm" => {
                    con.print("memory argument");
                    let operand = con.cmd();
                    con.print("value");
                    let value = u32::from_str_radix(con.cmd().as_str().trim_start_matches("0x"), 16).expect("bad num conversion");
                    if self.memory_write(operand.as_str(), value) {
                        println!("done.");
                    } else {
                        println!("cannot write there");
                    }
                    
                },
                "ba" => {
                    con.print("address");
                    let addr = u32::from_str_radix(con.cmd().as_str().trim_start_matches("0x"), 16).expect("bad num conversion");
                    self.bp = addr;
                    return;
                },
                "bi" => {
                    con.print("instruction number");
                    let num = u32::from_str_radix(con.cmd().as_str().trim_start_matches("0x"), 16).expect("bad num conversion");
                    self.exp = num;
                    return;
                },
                "s" => self.maps.get_mem("stack").print_dwords_from_to(self.regs.esp, self.regs.esp+48),
                "v" => self.maps.get_mem("stack").print_dwords_from_to(self.regs.ebp, self.regs.ebp+0x100),
                "c" => return,
                "f" => self.flags.print(),
                "cf" => self.flags.clear(),
                "mc" => {
                    con.print("name ");
                    let name = con.cmd();
                    con.print("base address ");
                    let saddr = con.cmd();
                    let addr = u32::from_str_radix(saddr.as_str().trim_start_matches("0x"), 16).expect("bad num conversion");
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
                    let addr = u32::from_str_radix(con.cmd().as_str().trim_start_matches("0x"), 16).expect("bad num conversion");
                    match self.maps.get_addr_name(addr) {
                        Some(name)  => println!("address at '{}' map", name),
                        None => println!("address not found on any map"),
                    }
                },
                "md" => {
                    con.print("address");
                    let addr = u32::from_str_radix(con.cmd().as_str().trim_start_matches("0x"), 16).expect("bad num conversion");
                    self.maps.dump(addr);
                },
                "mds" => {
                    con.print("address");
                    let addr = u32::from_str_radix(con.cmd().as_str().trim_start_matches("0x"), 16).expect("bad num conversion");
                    println!("{}", self.maps.read_string(addr));

                },
                "mdw" => {
                    con.print("address");
                    let addr = u32::from_str_radix(con.cmd().as_str().trim_start_matches("0x"), 16).expect("bad num conversion");
                    println!("{}", self.maps.read_wide_string(addr));
                },
                "eip" => {
                    con.print("=");
                    let saddr = con.cmd();
                    let addr = u32::from_str_radix(saddr.as_str().trim_start_matches("0x"), 16).expect("bad num conversion");
                    self.regs.eip = addr;
                },
                "push" => {
                    con.print("value");
                    let value = u32::from_str_radix(con.cmd().as_str().trim_start_matches("0x"), 16).expect("bad num conversion");
                    self.stack_push(value);
                    println!("pushed.");
                },
                "pop" => {
                    let value = self.stack_pop(false);
                    println!("poped value 0x{:x}", value);
                },
                "ss" => {
                    con.print("map name");
                    let map_name = con.cmd();
                    con.print("string");
                    let kw = con.cmd();
                    self.maps.search_string(kw, map_name);
                },
                "sb" => {
                    con.print("map name");
                    let map_name = con.cmd();
                    con.print("spaced bytes");
                    let sbs = con.cmd();
                    let bs:Vec<&str> = sbs.split(" ").collect();
                    let mut bytes:Vec<u8> = Vec::new();
                    for i in 0..bs.len() {
                        let b = u8::from_str_radix(bs[i],16).expect("bad num conversion");
                        bytes.push(b);
                    }
                    self.maps.search_bytes(bytes, map_name);
                },
                "n" => {
                    self.exp += 1;
                    return;
                },
                "m" => self.maps.print_maps(),
                "d" => {
                    con.print("address");
                    let addr = u32::from_str_radix(con.cmd().as_str().trim_start_matches("0x"), 16).expect("bad address");
                    self.disasemble(addr);
                },
                "" => {
                    self.exp += 1;
                    return;
                },
                _ => println!("command not found, type h"),
            }
        }
    }

    fn exception(&mut self) {
        let addr:u32;
        let next:u32;

        if self.veh > 0 {
            addr = self.veh;
            next = self.seh;

            self.stack_push(0x10f00);
            self.maps.write_dword(0x10f04, 0x10f00); // guloader trick
            self.maps.write_dword(0x10fb8, self.regs.eip); // guloader trick
            self.stack_push(self.regs.eip);

        } else {

            if self.seh == 0 {
                panic!("exception without any SEH handler nor vector configured.");
            }

            next = match self.maps.read_dword(self.seh) {
                Some(value) => value,
                None => panic!("exception wihout correct SEH"),
            };

            addr = match self.maps.read_dword(self.seh+4) {
                Some(value) => value,
                None => panic!("exception without correct SEH."),
            };

        }


        let con = Console::new();
        con.print("jump the exception pointer (y/n)?");
        let cmd = con.cmd();
        if cmd == "y" { 
            self.seh = next;
            self.set_eip(addr, false);    
        }
    }

    fn user32_api(&mut self, addr:u32) {
        match addr {
            0x7740ea11 => self.user32_MessageBoxA(),
            _ => panic!("calling unknown user32 API 0x{:x}", addr)
        }
    }

    fn ntdll_api(&mut self, addr:u32) {
        match addr {
            0x775b52d8 => self.ntdll_NtAllocateVirtualMemory(),
            0x775b5a18 => self.ntdll_NtGetContextThread(),
            0x7757f774 => self.ntdll_RtlVectoredExceptionHandler(),
            0x775d22b8 => self.ntdll_LdrLoadDll(),
            0x775b6258 => self.ntdll_NtQueryVirtualMemory(),
            0x775d531f => self.ntdll_stricmp(),
            _ => panic!("calling unknown ntdll API 0x{:x}", addr),
        }
    }

    fn kernel32_api(&mut self, addr:u32) {
        match addr {
            0x75e9395c => self.kernel32_LoadLibraryA(),
            0x75e847fa => self.kernel32_LoadLibraryExA(),
            0x75e93951 => self.kernel32_LoadLibraryExA(), // from jump table
            0x75e84775 => self.kernel32_LoadLibraryExW(),
            0x75e93c01 => self.kernel32_LoadLibraryW(),
            _ => panic!("calling unknown kernel32 API 0x{:x}", addr),
        }
    }

    fn ntdll_stricmp(&mut self) {
        let str1ptr = self.maps.read_dword(self.regs.esp).expect("ntdll_stricmp: error reading string1");
        let str2ptr = self.maps.read_dword(self.regs.esp+4).expect("ntdll_stricmp: error reading string2");
        let str1 = self.maps.read_string(str1ptr);
        let str2 = self.maps.read_string(str2ptr);
        let colors = Colors::new();
        println!("{}** ntdll_stricmp  '{}'=='{}'? {}", colors.light_red, str1, str2, colors.nc);

        if str1 == str2 {
            self.regs.eax = 0;
        } else {
            self.regs.eax = 1;
        }

        for _ in 0..2 {
            self.stack_pop(false);
        }
    }

    fn ntdll_NtQueryVirtualMemory(&mut self) {
        let handle = match self.maps.read_dword(self.regs.esp) {
            Some(v) => v,
            None => panic!("ntdll_NtQueryVirtualMemory: error reading handle"),
        };

        let addr = match self.maps.read_dword(self.regs.esp+4) {
            Some(v) => v,
            None => panic!("ntdll_NtQueryVirtualMemory: error reading address"),
        };

        if handle != 0xffffffff {
            panic!("ntdll_NtQueryVirtualMemory: using handle of remote process {:x}", handle);
        }

        let out_meminfo_ptr = match self.maps.read_dword(self.regs.esp+12) {
            Some(v) => v,
            None => panic!("ntdll_NtQueryVirtualMemory: error reading out pointer to meminfo"),
        };

        if !self.maps.is_mapped(addr) {
            println!("/!\\ ntdll_NtQueryVirtualMemory: querying non maped addr: 0x{:x}", addr);
            for _ in 0..6 {
                self.stack_pop(false);
            }
            self.regs.eax = constants::STATUS_INVALID_PARAMETER;
        }
    
        /*
        __kernel_entry NTSYSCALLAPI NTSTATUS NtQueryVirtualMemory(
            [in]            HANDLE                   ProcessHandle,
            [in, optional]  PVOID                    BaseAddress,
            [in]            MEMORY_INFORMATION_CLASS MemoryInformationClass,
            [out]           PVOID                    MemoryInformation,
            [in]            SIZE_T                   MemoryInformationLength,
            [out, optional] PSIZE_T                  ReturnLength
        );
        */

        let colors = Colors::new();
        println!("{}** ntdll_NtQueryVirtualMemory {}", colors.light_red, colors.nc);

        if !self.maps.write_spaced_bytes(out_meminfo_ptr, "00 00 01 00 00 00 01 00 04 00 00 00 00 00 01 00 00 10 00 00 04 00 00 00 00 00 04 00 00 00 00 00 00 00 00 00".to_string()) {
            panic!("ntdll_NtQueryVirtualMemory: cannot write in out ptr 0x{:x} the meminfo struct", out_meminfo_ptr);
        }

        for _ in 0..6 {
            self.stack_pop(false);
        }

        self.regs.eax = constants::STATUS_SUCCESS;
    }

    fn user32_MessageBoxA(&mut self) {
        let titleptr = match self.maps.read_dword(self.regs.esp+8) {
            Some(v) => v,
            None => panic!("user32_MessageBoxA: error reading title")
        };
        let msgptr = match self.maps.read_dword(self.regs.esp+4) {
            Some(v) => v,
            None => panic!("user32_MessageBoxA: error reading message")
        };

        let msg = self.maps.read_string(msgptr);
        let title = self.maps.read_string(titleptr);

        let colors = Colors::new();
        println!("{}** user32_MessageBoxA {} {} {}", colors.light_red, title, msg, colors.nc);
        self.regs.eax = 0;
        for _ in 0..4 {
            self.stack_pop(false);
        }
    }

    fn ntdll_LdrLoadDll(&mut self) {
        let libaddr_ptr = match self.maps.read_dword(self.regs.esp+12) {
            Some(v) => v,
            None => panic!("LdrLoadDll: error reading lib ptr")
        };

        let libname_ptr = match self.maps.read_dword(self.regs.esp+20) {
            Some(v) => v,
            None => panic!("LdrLoadDll: error reading lib param")
        };

        
        let colors = Colors::new();
        let libname = self.maps.read_wide_string(libname_ptr);
        println!("{}** ntdll_LdrLoadDll   lib:{} {}",colors.light_red, libname, colors.nc);

        
        if libname == "user32.dll" {
            let user32 = self.maps.create_map("user32");
            user32.set_base(0x773b0000);
            user32.load("maps/user32.bin");
            let user32_text = self.maps.create_map("user32_text");
            user32_text.set_base(0x773b1000);
            user32_text.load("maps/user32_text.bin");

            if !self.maps.write_dword(libaddr_ptr, 0x773b0000) {
                panic!("ntdll_LdrLoadDll: cannot write in addr param");
            }
        }


        for _ in 0..4 {
            self.stack_pop(false);
        }
        self.regs.eax = constants::STATUS_SUCCESS;
    }
    
    fn ntdll_RtlVectoredExceptionHandler(&mut self) {
        let p1 = match self.maps.read_dword(self.regs.esp) {
            Some(v) => v,
            None => panic!("ntdll_RtlVectoredExceptionHandler: error reading p1"),
        };

        let fptr = match self.maps.read_dword(self.regs.esp+4) {
            Some(v) => v,
            None => panic!("ntdll_RtlVectoredExceptionHandler: error reading fptr"),
        };

        let colors = Colors::new();
        println!("{}** ntdll_RtlVectoredExceptionHandler  {} callback:0x{:x} {}",colors.light_red, p1, fptr, colors.nc);

        self.veh = fptr;

        self.regs.eax = 0x2c2878;
        self.stack_pop(false);
        self.stack_pop(false);
    }

    fn ntdll_NtGetContextThread(&mut self) {
        let handle = match self.maps.read_dword(self.regs.esp) {
            Some(v) => v,
            None => panic!("ntdll_NtGetContextThread: error reading stack"),
        };

        let ctx_ptr = match self.maps.read_dword(self.regs.esp+4) {
            Some(v) => v,
            None => panic!("ntdll_NtGetContextThread: error reading context pointer"),
        };

        let ctx = match self.maps.read_dword(ctx_ptr) {
            Some(v) => v,
            None => panic!("ntdll_NtGetContextThread: error reading context ptr"),
        };

        let context_flags = match self.maps.read_dword(ctx) {
            Some(v) => v,
            None => panic!("ntdll_NtGetContextThread: error reading context flags"),
        };

        let colors = Colors::new();
        println!("{}** ntdll_NtGetContextThread   ctx flags:0x{:x} {}",colors.light_red, context_flags, colors.nc);

        if !self.maps.write_dword(ctx+4, 0) {
            panic!("ntdll_NtGetContextThread: error writting Dr0 in context");
        }
        if !self.maps.write_dword(ctx+8, 0) {
            panic!("ntdll_NtGetContextThread: error writting Dr1 in context");
        }
        if !self.maps.write_dword(ctx+12, 0) {
            panic!("ntdll_NtGetContextThread: error writting Dr2 in context");
        }
        if !self.maps.write_dword(ctx+16, 0) {
            panic!("ntdll_NtGetContextThread: error writting Dr3 in context");
        }
        if !self.maps.write_dword(ctx+16, 0) {
            panic!("ntdll_NtGetContextThread: error writting Dr6 in context");
        }
        if !self.maps.write_dword(ctx+16, 0) {
            panic!("ntdll_NtGetContextThread: error writting Dr7 in context");
        }

        self.regs.eax = 0;
        self.stack_pop(false);
        self.stack_pop(false);
        
        /*

        DR0-DR3 – breakpoint registers
        DR4 & DR5 – reserved
        DR6 – debug status
        DR7 – debug control


        typedef struct _CONTEXT
        {
            ULONG ContextFlags;
            ULONG Dr0;
            ULONG Dr1;
            ULONG Dr2;
            ULONG Dr3;
            ULONG Dr6;
            ULONG Dr7;
            FLOATING_SAVE_AREA FloatSave;
            ULONG SegGs;
            ULONG SegFs;
            ULONG SegEs;
            ULONG SegDs;
            ULONG Edi;
            ULONG Esi;
            ULONG Ebx;
            ULONG Edx;
            ULONG Ecx;
            ULONG Eax;
            ULONG Ebp;
            ULONG Eip;
            ULONG SegCs;
            ULONG EFlags;
            ULONG Esp;
            ULONG SegSs;
            UCHAR ExtendedRegisters[512];
        } CONTEXT, *PCONTEXT;
        */






    }

    fn ntdll_NtAllocateVirtualMemory(&mut self) {
        let colors = Colors::new();
        /*
            __kernel_entry NTSYSCALLAPI NTSTATUS NtAllocateVirtualMemory(
                [in]      HANDLE    ProcessHandle,
                [in, out] PVOID     *BaseAddress,
                [in]      ULONG_PTR ZeroBits,
                [in, out] PSIZE_T   RegionSize,
                [in]      ULONG     AllocationType,
                [in]      ULONG     Protect
                );
        */
        let addr_ptr = match self.maps.read_dword(self.regs.esp+4) {
            Some(v) => v,
            None => panic!("bad NtAllocateVirtualMemory address pointer parameter"),
        };

        let size_ptr = match self.maps.read_dword(self.regs.esp+12) {
            Some(v) => v,
            None => panic!("bad NtAllocateVirtualMemory size pointer parameter"),
        };

        let addr = match self.maps.read_dword(addr_ptr) {
            Some(v) => v,
            None => panic!("bad NtAllocateVirtualMemory address parameter"),
        };

        let size = match self.maps.read_dword(size_ptr) {
            Some(v) => v,
            None => panic!("bad NtAllocateVirtualMemory size parameter"),
        };

        match self.maps.get_addr_name(addr) {
            Some(name) => panic!("address already mapped: {}", name),
            None => println!("creating map on 0x{:x}", addr),
        }

        if size <= 0 {
            panic!("NtAllocateVirtualMemory mapping zero bytes.")
        }

        println!("{}** NtAllocateVirtualMemory  0x003e0000 {}",colors.light_red, colors.nc);

        //TODO: modify this, its allowing just one allocation
        let alloc = self.maps.create_map("alloc");
        let alloc_addr = 0x003e0000;
        alloc.set_base(alloc_addr);
        alloc.set_bottom(alloc_addr + size);

        if !self.maps.write_dword(addr_ptr, alloc_addr) {
            panic!("NtAllocateVirtualMemory: cannot write on address pointer");
        }

        self.regs.eax = constants::STATUS_SUCCESS;

        for _ in 0..6 {
            self.stack_pop(false);
        }
    }

    fn kernel32_LoadLibraryA(&mut self) {
        let colors = Colors::new();
        let dllptr = match self.maps.read_dword(self.regs.esp) {
            Some(v) => v,
            None => panic!("bad LoadLibraryA parameter"),
        };
        let dll = self.maps.read_string(dllptr);
        println!("{}** LoadLibraryA  '{}'  {}",colors.light_red, dll, colors.nc);


        if dll == "ntdll" || dll == "ntdll.dll" {
            self.regs.eax = self.maps.get_mem("ntdll").get_base();
        } else if dll == "ws2_32" || dll == "ws2_32.dll" {
            let ws2_32 = self.maps.create_map("ws2_32");
            ws2_32.set_base(0x77480000);
            ws2_32.load("maps/ws2_32.bin");
            let ws2_32_text = self.maps.create_map("ws2_32_text");
            ws2_32_text.set_base(0x77481000);
            ws2_32_text.load("maps/ws2_32_text.bin");
        }

        self.stack_pop(false);
    }

    fn kernel32_LoadLibraryExA(&mut self) {
        /*
        HMODULE LoadLibraryExA(
            [in] LPCSTR lpLibFileName,
                 HANDLE hFile,
            [in] DWORD  dwFlags
          );
        */
        let libname_ptr = self.maps.read_dword(self.regs.esp).expect("kernel32_LoadLibraryExA: error reading libname ptr param");
        let libname = self.maps.read_string(libname_ptr);

        let colors = Colors::new();
        println!("{}** LoadLibraryExA '{}' {}",colors.light_red, libname, colors.nc);
        panic!();
    }

    fn kernel32_LoadLibraryExW(&mut self) {
        let colors = Colors::new();
        println!("{}** LoadLibraryExW {}",colors.light_red, colors.nc);
    }

    fn kernel32_LoadLibraryW(&mut self) {
        let colors = Colors::new();
        let dllptr = match self.maps.read_dword(self.regs.esp) {
            Some(v) => v,
            None => panic!("bad LoadLibraryW parameter"),
        };
        let dll = self.maps.read_wide_string(dllptr);
        println!("{}** LoadLibraryW  '{}'  {}",colors.red, dll, colors.nc);

        if dll == "ntdll.dll" {
            self.regs.eax = self.maps.get_mem("ntdll").get_base();
        }

        self.stack_pop(false);
    }

    pub fn disasemble(&mut self, addr:u32) {
        let map_name = self.maps.get_addr_name(addr).expect("address not mapped");
        let code = self.maps.get_mem(map_name.as_str());
        let block = code.read_from(addr);
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode32)
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build()
            .expect("Failed to create Capstone object");
        
            let insns = cs.disasm_all(block, addr as u64).expect("Failed to disassemble");
            for ins in insns.as_ref() {
                println!("{}", ins);
            }
    }


    ///  RUN ENGINE ///

    pub fn run(&mut self) {        
        println!(" ----- emulation -----");
        let mut looped:Vec<u64> = Vec::new();
        let colors = Colors::new();
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode32)
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build()
            .expect("Failed to create Capstone object");

        let mut pos = 0;
        

        loop {

            let eip = self.regs.eip.clone();
            let map_name = self.maps.get_addr_name(eip).expect("jumped to an address non mapped");
            let code = self.maps.get_mem(map_name.as_str());
            let block = code.read_from(eip);
            let insns = cs.disasm_all(block, eip as u64).expect("Failed to disassemble");
            
            for ins in insns.as_ref() {
                //TODO: use InsnDetail https://docs.rs/capstone/0.4.0/capstone/struct.InsnDetail.html
                //let detail: InsnDetail = cs.insn_detail(&ins).expect("Failed to get insn detail");
                //let arch_detail: ArchDetail = detail.arch_detail();
                //let ops = arch_detail.operands();

                let sz = ins.bytes().len();
                let addr = ins.address();
                let mut step = false;

                pos += 1;

                /*
                if self.regs.eip == 0x3c8e18 {
                    println!("trace -> {}", self.maps.read_string(self.regs.edx));
                }

                if self.regs.eip == 0x3c8e29 {
                    println!("trace -> eax:{:x} == edx:{:x} ??  645AAB39", self.regs.eax, self.regs.edx)
                }*/

                if self.exp == pos || self.bp == addr as u32 {
                    step = true;
                    println!("-------");
                    println!("{} {}", pos, ins);
                    self.spawn_console();
                }
                    
                if self.iter {
                    // loop detector
                    looped.push(addr);
                    let mut count:u32 = 0;
                    for a in looped.iter() {
                        if addr == *a {
                            count += 1;
                        }
                    }
                    if count > self.loop_print {
                        println!("    loop: {} interations", count);
                    }
                    if count > self.loop_limit {
                        panic!("/!\\ iteration limit reached");
                    }
                    //TODO: if more than x addresses remove the bottom ones
                }

                // trace register
                if self.showregs {
                    println!("\teax: 0x{:x} ebx: 0x{:x} ecx: 0x{:x} edx: 0x{:x} esi: 0x{:x} edi: 0x{:x}", self.regs.eax, self.regs.ebx, self.regs.ecx, self.regs.edx, self.regs.esi, self.regs.edi);
                }
                
                if self.quick {
                    step = true;
                }

                // instructions implementation
                match ins.mnemonic() {
                    Some("jmp") => {
                        if !step {
                            println!("{}{} {}{}", colors.yellow, pos, ins, colors.nc);
                        }
                        let op = ins.op_str().unwrap();
                        let addr:u32;
                        if self.is_reg(op) {
                            addr = self.regs.get_by_name(op);

                        } else if op.contains("[") {
                            addr = match self.memory_read(op) {
                                Some(v) => v,
                                None => {
                                    self.exception();
                                    break;
                                }
                            };
                        } else  {
                            addr = self.get_inmediate(op);
                        }

                        self.set_eip(addr, false);
                        break;
                    },

                    Some("call") => {
                        if !step {
                            println!("{}{} {}{}", colors.yellow, pos, ins, colors.nc);
                        }

                        let op = ins.op_str().unwrap();
                        let addr:u32;
                        let bytes = ins.bytes();

                        if sz == 3 || sz == 6 {
                            addr = match self.memory_read(op) {
                                Some(v) => v,
                                None => {
                                    self.exception();
                                    break;
                                }
                            };
                        } else  if sz == 5 {
                            addr = self.get_inmediate(op);

                        } else if sz == 2 {
                            if bytes[0] == 0xff {
                            
                                addr = match bytes[1] {
                                    0xd0 => self.regs.eax,
                                    0xd3 => self.regs.ebx,
                                    0xd1 => self.regs.ecx,
                                    0xd2 => self.regs.edx,
                                    0xd6 => self.regs.esi,
                                    0xd7 => self.regs.edi,
                                    0xd4 => self.regs.esp,
                                    0xd5 => self.regs.ebp,

                                    _ => match self.memory_read(op) {
                                            Some(v) => v,
                                            None => {
                                                self.exception();
                                                break;
                                            }
                                    },
                                };
                                
                                

                            } else {
                                addr = self.regs.get_by_name(op);
                            }
                            
                        } else {
                            panic!("weird call");
                        }

                        let name = match self.maps.get_addr_name(addr) {
                            Some(n) => n,
                            None => panic!("calling non  mapped addr 0x{:x}", addr)
                        };

                        if name == "kernel32_text" {
                            self.kernel32_api(addr);
                        } else if name == "ntdll_text" {
                            self.ntdll_api(addr);
                        } else if name == "user32_text" {
                            self.user32_api(addr);
                        } else if name == "code" {
                            self.stack_push(self.regs.eip + sz as u32); // push return address
                            //println!("\tcall return addres: 0x{:x}", self.regs.eip + sz as u32);
                            self.set_eip(addr, false);
                            break;
                        } else {
                            panic!("calling to {} at 0x{:x}", name, addr);
                        }
                    },

                    Some("push") => {
                        if !step {
                            println!("{}{} {}{}", colors.blue, pos, ins, colors.nc);
                        }
                        let opcode:u8 = ins.bytes()[0];

                        match opcode {
                            // push + regs
                            0x50 => self.stack_push(self.regs.eax),
                            0x51 => self.stack_push(self.regs.ecx),
                            0x52 => self.stack_push(self.regs.edx),
                            0x53 => self.stack_push(self.regs.ebx),
                            0x54 => self.stack_push(self.regs.esp),
                            0x55 => self.stack_push(self.regs.ebp),
                            0x56 => self.stack_push(self.regs.esi),
                            0x57 => self.stack_push(self.regs.edi),
                            0x16 => self.stack_push(self.regs.esp),

                            0x66 => {
                                match ins.bytes()[1] {
                                    0x56 => self.stack_push(self.regs.esi), // push si
                                    _ => panic!("unimplemented push")
                                }
                            },

                            // push + inmediate
                            0x68|0x6a => {
                                let addr = self.get_inmediate(ins.op_str().unwrap());
                                self.stack_push(addr as u32);
                            },

                            0x64 => {
                                let bs = ins.bytes();
                                if bs[1] == 0xff && bs[2] == 0x35 && bs[3] == 0x00 && bs[4] == 0x00 && bs[5] == 0x00 && bs[6] == 0x00 {
                                    // pushing SEH
                                    self.stack_push(self.seh);

                                } else {
                                    panic!("weird push instruction {:?}", bs);
                                }
                            },

                            // push + mem operation
                            _ => {
                                let value = match self.memory_read(ins.op_str().unwrap()) {
                                    Some(v) => v,
                                    None => {
                                        self.exception();
                                        break;
                                    }
                                };
                                self.stack_push(value);
                            }
                        }
                    },

                    Some("pop") => {
                        if !step {
                            println!("{}{} {}{}", colors.blue, pos, ins, colors.nc);
                        }
                        let opcode:u8 = ins.bytes()[0];
                        

                        match opcode {
                            // pop + regs
                            0x58 => self.regs.eax = self.stack_pop(true),
                            0x59 => self.regs.ecx = self.stack_pop(true),
                            0x5a => self.regs.edx = self.stack_pop(true),
                            0x5b => self.regs.ebx = self.stack_pop(true),
                            0x5c => self.regs.esp = self.stack_pop(true),
                            0x5d => self.regs.ebp = self.stack_pop(true),
                            0x5e => self.regs.esi = self.stack_pop(true),
                            0x5f => self.regs.edi = self.stack_pop(true),
                            0x17 => self.regs.esp = self.stack_pop(true),

                            0x66 => {
                                match ins.bytes()[1] {
                                    0x5e => self.regs.esi = self.stack_pop(true), // pop si
                                    _ => panic!("unimplemented pop")
                                }
                            },

                            // pop + mem operation
                            _ => {
                                let value = self.stack_pop(true);
                                if !self.memory_write(ins.op_str().unwrap(), value) {
                                    self.exception();
                                    break;
                                }
                            },
                        }

                    },

                    Some("pushal") => {
                        if !step {
                            println!("{}{} {}{}", colors.blue, pos, ins, colors.nc);
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
                    },

                    Some("popal") => {
                        if !step {
                            println!("{}{} {}{}", colors.blue, pos, ins, colors.nc);
                        }
                        self.regs.edi = self.stack_pop(false);
                        self.regs.esi = self.stack_pop(false);
                        self.regs.ebp = self.stack_pop(false);
                        self.regs.esp += 4; // skip esp
                        self.regs.ebx = self.stack_pop(false);
                        self.regs.edx = self.stack_pop(false);
                        self.regs.ecx = self.stack_pop(false);
                        self.regs.eax = self.stack_pop(false);
                    },

                    Some("cdq") => {
                        let num:i64 = self.regs.eax as i64;
                        let unum:u64 = num as u64;
                        self.regs.edx = ((unum & 0xffffffff00000000) >> 32) as u32;
                        self.regs.eax = (unum & 0xffffffff) as u32;
                    },

                    Some("ret") => {
                        if !step {
                            println!("{}{} {}{}", colors.yellow, pos, ins, colors.nc);
                        }
                        let ret_addr = self.stack_pop(false); // return address
                        let op = ins.op_str().unwrap();
                        //println!("\tret return addres: 0x{:x}  return value: 0x{:x}", ret_addr, self.regs.eax);

                        
                        if op.len() > 0 {
                            let mut arg = self.get_inmediate(op);

                            // apply stack compensation of ret operand

                            if arg % 4 != 0 {
                                panic!("weird ret argument!");
                            }

                            arg = arg / 4;

                            for _ in 0..arg {
                                self.stack_pop(false);
                            }
                        }
                        
                        self.set_eip(ret_addr, false);
                        break;
                    },

                    Some("xchg") => {
                        if !step {
                            println!("{}{} {}{}", colors.light_cyan, pos, ins, colors.nc);
                        }

                        let parts:Vec<&str> = ins.op_str().unwrap().split(", ").collect();

                        if parts[0].contains("[") {
                            if self.is_reg(parts[1]) {
                                // xchg mem, reg
                                let value0 = match self.memory_read(parts[0]) {
                                    Some(v) => v,
                                    None => {
                                        self.exception();
                                        break;
                                    }
                                };
                                let value1 = self.regs.get_by_name(parts[1]);
                                if !self.memory_write(parts[0], value1) {
                                    self.exception();
                                    break;
                                }
                                self.regs.set_by_name(parts[1], value0);
                            } 

                        } else {

                            if parts[1].contains("[") {
                                // xchg reg, mem 
                                let value0 = self.regs.get_by_name(parts[0]);
                                let value1 = match self.memory_read(parts[1]) {
                                    Some(v) => v,
                                    None => {
                                        self.exception();
                                        break;
                                    }
                                };
                                if !self.memory_write(parts[1], value0) {
                                    self.exception();
                                    break;
                                }
                                self.regs.set_by_name(parts[0], value1);

                            } else {
                                // xchg reg, reg
                                println!("reg reg");
                                let value0 = self.regs.get_by_name(parts[0]);
                                let value1 = self.regs.get_by_name(parts[1]);
                                self.regs.set_by_name(parts[0], value1);
                                self.regs.set_by_name(parts[1], value0);
                                println!("end.");
                            }
                        }
                    }


                    Some("mov") => {
                        if !step {
                            println!("{}{} {}{}", colors.light_cyan, pos, ins, colors.nc);
                        }

                        let bs = ins.bytes();

                        if bs[0] == 0x69 && bs[1] == 0x89 && bs[2] == 0x25 && bs[3] == 0x00 && bs[4] == 0x00 && bs[5] == 0x00 && bs[6] == 0x00 {
                            self.seh = self.regs.esp;
                            println!("\n/!\\ programming exception handler SEH");
                        }

                        let parts:Vec<&str> = ins.op_str().unwrap().split(", ").collect();
                        
                        if parts[0].contains("[") {
                            if self.is_reg(parts[1]) {
                                // mov mem, reg
                                let value = self.regs.get_by_name(parts[1]);
                                if !self.memory_write(parts[0], value) {
                                    self.exception();
                                    break;
                                }
                                
                            } else {
                                // mov mem, inm
                                let inm = self.get_inmediate(parts[1]);
                                if !self.memory_write(parts[0], inm) {
                                    self.exception();
                                    break;
                                }
                            }

                        } else { 

                            if parts[1].contains("[") {
                                // mov reg, mem 
                                let value = match self.memory_read(parts[1]) {
                                    Some(v) => v,
                                    None => {
                                        self.exception();
                                        break;
                                    }
                                };
                                self.regs.set_by_name(parts[0], value);
                                //println!("reg '{}' '{}' new value: 0x{:x}", parts[0], parts[1], value);

                            } else if self.is_reg(parts[1]) {
                                // mov reg, reg
                                self.regs.set_by_name(parts[0], self.regs.get_by_name(parts[1]));
                                
                            } else {
                                // mov reg, inm
                                let inm = self.get_inmediate(parts[1]);
                                self.regs.set_by_name(parts[0], inm);
                            }
                        }
                    
                    },

                    Some("xor") => {
                        if !step {
                            println!("{}{} {}{}", colors.green, pos, ins, colors.nc);
                        }
                        let parts:Vec<&str> = ins.op_str().unwrap().split(", ").collect();

                        if parts[0].contains("[") {
                            if self.is_reg(parts[1]) {
                                // mov mem, reg
                                let value1 = self.regs.get_by_name(parts[1]);
                                let value0 = match self.memory_read(parts[0]) {
                                    Some(v) => v,
                                    None => {
                                        self.exception();
                                        break;
                                    }
                                };

                                if !self.memory_write(parts[0], value0 ^ value1) {
                                    self.exception();
                                    break;
                                }
                                
                            } else {
                                // mov mem, inm
                                let inm = self.get_inmediate(parts[1]);
                                let value0 = match self.memory_read(parts[0]) {
                                    Some(v) => v,
                                    None => {
                                        self.exception();
                                        break;
                                    }
                                };
                                if !self.memory_write(parts[0], value0 ^ inm) {
                                    self.exception();
                                    break;
                                }
                            }

                        } else {

                            if parts[1].contains("[") {
                                // mov reg, mem 
                                let value1 = match self.memory_read(parts[1]) {
                                    Some(v) => v,
                                    None => {
                                        self.exception();
                                        break;
                                    }
                                };
                                let value0 = self.regs.get_by_name(parts[0]);
                                self.regs.set_by_name(parts[0], value0 ^ value1);

                            } else if self.is_reg(parts[1]) {
                                // mov reg, reg
                                let value1 = self.regs.get_by_name(parts[1]);
                                let value0 = self.regs.get_by_name(parts[0]);
                                self.regs.set_by_name(parts[0], value0 ^ value1);
                                
                            } else {
                                // mov reg, inm
                                let inm = self.get_inmediate(parts[1]);
                                let value0 = self.regs.get_by_name(parts[0]);
                                self.regs.set_by_name(parts[0], value0 ^ inm);
                            }
                        }
                    },

                    Some("add") => { // https://c9x.me/x86/html/file_module_x86_id_5.html
                        if !step {
                            println!("{}{} {}{}", colors.cyan, pos, ins, colors.nc);
                        }
                        let ops = ins.op_str().unwrap();
                        let parts:Vec<&str> = ops.split(", ").collect();

                        if parts[0].contains("[") {
                            if self.is_reg(parts[1]) {
                                // mov mem, reg
                                let value1:u32 = self.regs.get_by_name(parts[1]);
                                let value0:u32 = match self.memory_read(parts[0]) {
                                    Some(v) => v,
                                    None => {
                                        self.exception();
                                        break;
                                    }
                                };
                                let res:u32;
                                match self.get_size(parts[1]) {
                                    32 => res = self.flags_add32(value0, value1),
                                    16 => res = self.flags_add16(value0, value1),
                                    8  => res = self.flags_add8(value0, value1),
                                    _  => panic!("weird precision")
                                }
                                if !self.memory_write(parts[0], res) {
                                    self.exception();
                                    break;
                                }
                                
                            } else {
                                // mov mem, inm
                                let inm = self.get_inmediate(parts[1]);
                                let value0 = match self.memory_read(parts[0]) {
                                    Some(v) => v,
                                    None => {
                                        self.exception();
                                        break;
                                    }
                                };
                                let res:u32;
                                match self.get_size(parts[0]) {
                                    32 => res = self.flags_add32(value0, inm),
                                    16 => res = self.flags_add16(value0, inm),
                                    8  => res = self.flags_add8(value0, inm),
                                    _  => panic!("weird precision")
                                }
                                if !self.memory_write(parts[0], res) {
                                    self.exception();
                                    break;
                                }
                            }

                        } else {

                            if parts[1].contains("[") {
                                // mov reg, mem 
                                let value1 = match self.memory_read(parts[1]) {
                                    Some(v) => v,
                                    None => {
                                        self.exception();
                                        break;
                                    }
                                };
                                let value0 = self.regs.get_by_name(parts[0]);
                                let res:u32;
                                match self.get_size(parts[1]) {
                                    32 => res = self.flags_add32(value0, value1),
                                    16 => res = self.flags_add16(value0, value1),
                                    8  => res = self.flags_add8(value0, value1),
                                    _  => panic!("weird precision")
                                }
                                self.regs.set_by_name(parts[0], res);


                            } else if self.is_reg(parts[1]) {
                                // mov reg, reg
                                let value1 = self.regs.get_by_name(parts[1]);
                                let value0 = self.regs.get_by_name(parts[0]);
                                let res:u32;
                                match self.get_size(parts[1]) {
                                    32 => res = self.flags_add32(value0, value1),
                                    16 => res = self.flags_add16(value0, value1),
                                    8  => res = self.flags_add8(value0, value1),
                                    _  => panic!("weird precision")
                                }
                                self.regs.set_by_name(parts[0], res);
                                
                            } else {
                                // mov reg, inm
                                let inm = self.get_inmediate(parts[1]);
                                let value0 = self.regs.get_by_name(parts[0]);
                                let res:u32;
                                match self.get_size(parts[0]) {
                                    32 => res = self.flags_add32(value0, inm),
                                    16 => res = self.flags_add16(value0, inm),
                                    8  => res = self.flags_add8(value0, inm),
                                    _  => panic!("weird precision")
                                }
                                self.regs.set_by_name(parts[0], res);
                            }
                        } 
                    },
                    
                    Some("sbb") => {
                        if !step {
                            println!("{}{} {}{}", colors.cyan, pos, ins, colors.nc);
                        }
                        let op = ins.op_str().unwrap();
                        let parts:Vec<&str> = op.split(", ").collect();

                        if parts[0].contains("[") {
                            if self.is_reg(parts[1]) {
                                // mov mem, reg
                                let value1 = self.regs.get_by_name(parts[1]);
                                let value0 = match self.memory_read(parts[0]) {
                                    Some(v) => v,
                                    None => {
                                        self.exception();
                                        break;
                                    }
                                };
                                let res:u32;
                                match self.get_size(op) {
                                    32 => res = self.flags_sub32(value0, value1),
                                    16 => res = self.flags_sub16(value0, value1),
                                    8  => res = self.flags_sub8(value0, value1),
                                    _  => panic!("weird precision")
                                }
                                if !self.memory_write(parts[0], res) {
                                    self.exception();
                                    break;
                                }
                                
                            } else {
                                // mov mem, inm
                                let inm = self.get_inmediate(parts[1]);
                                let value0 = match self.memory_read(parts[0]) {
                                    Some(v) => v,
                                    None => {
                                        self.exception();
                                        break;
                                    }
                                };
                                let res:u32;
                                match self.get_size(op) {
                                    32 => res = self.flags_sub32(value0, inm),
                                    16 => res = self.flags_sub16(value0, inm),
                                    8  => res = self.flags_sub8(value0, inm),
                                    _  => panic!("weird precision")
                                }
                                if !self.memory_write(parts[0], res) {
                                    self.exception();
                                    break;
                                }
                            }

                        } else {

                            if parts[1].contains("[") {
                                // mov reg, mem 
                                let value1 = match self.memory_read(parts[1]) {
                                    Some(v) => v,
                                    None => {
                                        self.exception();
                                        break;
                                    }
                                };
                                let value0 = self.regs.get_by_name(parts[0]);
                                let res:u32;
                                match self.get_size(parts[1]) {
                                    32 => res = self.flags_sub32(value0, value1),
                                    16 => res = self.flags_sub16(value0, value1),
                                    8  => res = self.flags_sub8(value0, value1),
                                    _  => panic!("weird precision")
                                }
                                self.regs.set_by_name(parts[0], res);

                            } else if self.is_reg(parts[1]) {
                                // mov reg, reg
                                let value1 = self.regs.get_by_name(parts[1]);
                                let value0 = self.regs.get_by_name(parts[0]);
                                let res:u32;
                                match self.get_size(parts[1]) {
                                    32 => res = self.flags_sub32(value0, value1),
                                    16 => res = self.flags_sub16(value0, value1),
                                    8  => res = self.flags_sub8(value0, value1),
                                    _  => panic!("weird precision")
                                }
                                self.regs.set_by_name(parts[0], res);
                                
                            } else {
                                // mov reg, inm
                                let inm = self.get_inmediate(parts[1]);
                                let value0 = self.regs.get_by_name(parts[0]);
                                let res:u32;
                                match self.get_size(parts[0]) {
                                    32 => res = self.flags_sub32(value0, inm),
                                    16 => res = self.flags_sub16(value0, inm),
                                    8  => res = self.flags_sub8(value0, inm),
                                    _  => panic!("weird precision")
                                }
                                self.regs.set_by_name(parts[0], res);
                            }
                        }
                    },
                    
                    Some("sub") => {
                        if !step {
                            println!("{}{} {}{}", colors.cyan, pos, ins, colors.nc);
                        }
                        let op = ins.op_str().unwrap();
                        let parts:Vec<&str> = op.split(", ").collect();

                        if parts[0].contains("[") {
                            if self.is_reg(parts[1]) {
                                // mov mem, reg
                                let value1 = self.regs.get_by_name(parts[1]);
                                let value0 = match self.memory_read(parts[0]) {
                                    Some(v) => v,
                                    None => {
                                        self.exception();
                                        break;
                                    }
                                };
                                let res:u32;
                                match self.get_size(op) {
                                    32 => res = self.flags_sub32(value0, value1),
                                    16 => res = self.flags_sub16(value0, value1),
                                    8  => res = self.flags_sub8(value0, value1),
                                    _  => panic!("weird precision")
                                }
                                if !self.memory_write(parts[0], res) {
                                    self.exception();
                                    break;
                                }
                                
                            } else {
                                // mov mem, inm
                                let inm = self.get_inmediate(parts[1]);
                                let value0 = match self.memory_read(parts[0]) {
                                    Some(v) => v,
                                    None => {
                                        self.exception();
                                        break;
                                    }
                                };
                                let res:u32;
                                match self.get_size(op) {
                                    32 => res = self.flags_sub32(value0, inm),
                                    16 => res = self.flags_sub16(value0, inm),
                                    8  => res = self.flags_sub8(value0, inm),
                                    _  => panic!("weird precision")
                                }
                                if !self.memory_write(parts[0], res) {
                                    self.exception();
                                    break;
                                }
                            }

                        } else {

                            if parts[1].contains("[") {
                                // mov reg, mem 
                                let value1 = match self.memory_read(parts[1]) {
                                    Some(v) => v,
                                    None => {
                                        self.exception();
                                        break;
                                    }
                                };
                                let value0 = self.regs.get_by_name(parts[0]);
                                let res:u32;
                                match self.get_size(parts[1]) {
                                    32 => res = self.flags_sub32(value0, value1),
                                    16 => res = self.flags_sub16(value0, value1),
                                    8  => res = self.flags_sub8(value0, value1),
                                    _  => panic!("weird precision")
                                }
                                self.regs.set_by_name(parts[0], res);

                            } else if self.is_reg(parts[1]) {
                                // mov reg, reg
                                let value1 = self.regs.get_by_name(parts[1]);
                                let value0 = self.regs.get_by_name(parts[0]);
                                let res:u32;
                                match self.get_size(parts[1]) {
                                    32 => res = self.flags_sub32(value0, value1),
                                    16 => res = self.flags_sub16(value0, value1),
                                    8  => res = self.flags_sub8(value0, value1),
                                    _  => panic!("weird precision")
                                }
                                self.regs.set_by_name(parts[0], res);
                                
                            } else {
                                // mov reg, inm
                                let inm = self.get_inmediate(parts[1]);
                                let value0 = self.regs.get_by_name(parts[0]);
                                let res:u32;
                                match self.get_size(parts[0]) {
                                    32 => res = self.flags_sub32(value0, inm),
                                    16 => res = self.flags_sub16(value0, inm),
                                    8  => res = self.flags_sub8(value0, inm),
                                    _  => panic!("weird precision")
                                }
                                self.regs.set_by_name(parts[0], res);
                            }
                        }
                    },

                    Some("inc") => {
                        if !step {
                            println!("{}{} {}{}", colors.cyan, pos, ins, colors.nc);
                        }
                        let op = ins.op_str().unwrap();
                        if self.is_reg(op) {
                            let value = self.regs.get_by_name(op);
                            let res:u32;

                            match self.get_size(op) {
                                32 => res = self.flags_inc32(value),
                                16 => res = self.flags_inc16(value),
                                8 =>  res = self.flags_inc8(value),
                                _ => res = 0,
                            }

                            self.regs.set_by_name(op, res);
                            
                        } else {
                            let value = match self.memory_read(op) {
                                Some(v) => v,
                                None => {
                                    self.exception();
                                    break;
                                }
                            };
                            let res:u32;

                            match self.get_size(op) {
                                32 => res = self.flags_inc32(value),
                                16 => res = self.flags_inc16(value),
                                8 =>  res = self.flags_inc8(value),
                                _ => res = 0,
                            }

                            if !self.memory_write(op, res) {
                                self.exception();
                                break;
                            }
                        }
                    },

                    Some("dec") => {
                        if !step {
                            println!("{}{} {}{}", colors.cyan, pos, ins, colors.nc);
                        }
                        let op = ins.op_str().unwrap();
                        if self.is_reg(op) {
                            // dec reg
                            let value = self.regs.get_by_name(op);
                            let res:u32;

                            match self.get_size(op) {
                                32 => res = self.flags_dec32(value),
                                16 => res = self.flags_dec16(value),
                                8 =>  res = self.flags_dec8(value),
                                _ => res = 0,
                            }

                            self.regs.set_by_name(op, res);
                        } else {
                            // dec  mem
                            let value = match self.memory_read(op) {
                                Some(v) => v,
                                None => {
                                    self.exception();
                                    break;
                                }
                            };
                            let res:u32;

                            match self.get_size(op) {
                                32 => res = self.flags_dec32(value),
                                16 => res = self.flags_dec16(value),
                                8 =>  res = self.flags_dec8(value),
                                _ => res = 0,
                            }

                            if !self.memory_write(op, res) {
                                self.exception();
                                break;
                            }
                        }
                    },

               
                    // neg not and or ror rol  sar sal shr shl 
                    Some("neg") => {
                        if !step {
                            println!("{}{} {}{}", colors.green, pos, ins, colors.nc);
                        }
                        let op = ins.op_str().unwrap();
                        if self.is_reg(op) {
                            let mut value = self.regs.get_by_name(op);
                            let mut signed:i32 = value as i32;
                            let bits = self.get_size(op);
                            match bits {
                                32 => self.flags.f_of = value == 0x80000000,
                                16 => self.flags.f_of = value == 0x8000,
                                8 =>  self.flags.f_of = value == 0x80,
                                _ => panic!("weird precision")
                            }
                            signed = signed * -1;
                            value = signed as u32;
                            self.calc_flags(value, bits);
                            self.flags.f_cf = true;
                            self.regs.set_by_name(op, value);
                            
                        } else {
                            let mut value = match self.memory_read(op) {
                                Some(v) => v,
                                None => {
                                    self.exception();
                                    break;
                                }
                            };
                            let mut signed:i32 = value as i32;
                            let bits = self.get_size(op);
                            match  bits {
                                32 => self.flags.f_of = value == 0x80000000,
                                16 => self.flags.f_of = value == 0x8000,
                                8 =>  self.flags.f_of = value == 0x80,
                                _ => panic!("weird precision")
                            }
                            signed = signed * -1;
                            value = signed as u32;
                            self.calc_flags(value, bits);
                            self.flags.f_cf = true;
                            
                            if !self.memory_write(op, value) {
                                self.exception();
                                break;
                            }
                        }
                    },

                    Some("not") => { // dont alter flags
                        if !step {
                            println!("{}{} {}{}", colors.green, pos, ins, colors.nc);
                        }
                        let op = ins.op_str().unwrap();
                        if self.is_reg(op) {
                            let mut value = self.regs.get_by_name(op);
                            let mut signed:i32 = value as i32;
                            signed = !signed;
                            value = signed as u32;
                            self.regs.set_by_name(op, value);
                        } else {
                            let mut value = match self.memory_read(op) {
                                Some(v) => v,
                                None => {
                                    self.exception();
                                    break;
                                }
                            };
                            let mut signed:i32 = value as i32;
                            signed = !signed;
                            value = signed as u32;
                            if !self.memory_write(op, value) {
                                self.exception();
                                break;
                            }
                        }
                    },

                    Some("and") => { // TODO: how to trigger overflow and carry with and
                        if !step {
                            println!("{}{} {}{}", colors.green, pos, ins, colors.nc);
                        }
                        let parts:Vec<&str> = ins.op_str().unwrap().split(", ").collect();

                        if parts[0].contains("[") {
                            if self.is_reg(parts[1]) {
                                // and mem, reg
                                let value1 = self.regs.get_by_name(parts[1]);
                                let value0 = match self.memory_read(parts[0]) {
                                    Some(v) => v,
                                    None => {
                                        self.exception();
                                        break;
                                    }
                                };
                                let res = value0 & value1;
                                self.calc_flags(res, self.get_size(parts[1]));
                                if !self.memory_write(parts[0], res) {
                                    self.exception();
                                    break;
                                }
                                
                            } else {
                                // and mem, inm
                                let inm = self.get_inmediate(parts[1]);
                                let value0 = match self.memory_read(parts[0]) {
                                    Some(v) => v,
                                    None => {
                                        self.exception();
                                        break;
                                    }
                                };
                                let res = value0 & inm;
                                self.calc_flags(res, self.get_size(parts[0]));
                                if !self.memory_write(parts[0], res) {
                                    self.exception();
                                    break;
                                }
                            }

                        } else {

                            if parts[1].contains("[") {
                                // and reg, mem 
                                let value1 = match self.memory_read(parts[1]) {
                                    Some(v) => v,
                                    None => {
                                        self.exception();
                                        break;
                                    }
                                };
                                let value0 = self.regs.get_by_name(parts[0]);
                                let res = value0 & value1;
                                self.calc_flags(res, self.get_size(parts[1]));
                                self.regs.set_by_name(parts[0], res);

                            } else if self.is_reg(parts[1]) {
                                // and reg, reg
                                let value1 = self.regs.get_by_name(parts[1]);
                                let value0 = self.regs.get_by_name(parts[0]);
                                let res = value0 & value1;
                                self.calc_flags(res, self.get_size(parts[1]));
                                self.regs.set_by_name(parts[0], res);
                                
                            } else {
                                // and reg, inm
                                let inm = self.get_inmediate(parts[1]);
                                let value0 = self.regs.get_by_name(parts[0]);
                                let res = value0 & inm;
                                self.calc_flags(res, self.get_size(parts[0]));
                                self.regs.set_by_name(parts[0], res);
                            }
                        }

                    },

                    Some("or") => {
                        if !step {
                            println!("{}{} {}{}", colors.green, pos, ins, colors.nc);
                        }
                        let parts:Vec<&str> = ins.op_str().unwrap().split(", ").collect();

                        if parts[0].contains("[") {
                            if self.is_reg(parts[1]) {
                                // or mem, reg
                                let value1 = self.regs.get_by_name(parts[1]);
                                let value0 = match self.memory_read(parts[0]) {
                                    Some(v) => v,
                                    None => {
                                        self.exception();
                                        break;
                                    }
                                };
                                let res = value0 | value1;
                                self.calc_flags(res, self.get_size(parts[1]));
                                if !self.memory_write(parts[0], res) {
                                    self.exception();
                                    break;
                                }
                                
                            } else {
                                // or mem, inm
                                let inm = self.get_inmediate(parts[1]);
                                let value0 = match self.memory_read(parts[0]) {
                                    Some(v) => v,
                                    None => {
                                        self.exception();
                                        break;
                                    }
                                };
                                let res = value0 | inm;
                                self.calc_flags(res, self.get_size(parts[0]));
                                if !self.memory_write(parts[0], res) {
                                    self.exception();
                                    break;
                                }
                            }

                        } else {

                            if parts[1].contains("[") {
                                // or reg, mem 
                                let value1 = match self.memory_read(parts[1]) {
                                    Some(v) => v,
                                    None => {
                                        self.exception();
                                        break;
                                    }
                                };
                                let value0 = self.regs.get_by_name(parts[0]);
                                let res = value0 | value1;
                                self.calc_flags(res, self.get_size(parts[0]));
                                self.regs.set_by_name(parts[0], res);

                            } else if self.is_reg(parts[1]) {
                                // or reg, reg
                                let value1 = self.regs.get_by_name(parts[1]);
                                let value0 = self.regs.get_by_name(parts[0]);
                                let res = value0 | value1;
                                self.calc_flags(res, self.get_size(parts[0]));
                                self.regs.set_by_name(parts[0], res);
                                
                            } else {
                                // or reg, inm
                                let inm = self.get_inmediate(parts[1]);
                                let value0 = self.regs.get_by_name(parts[0]);
                                let res = value0 | inm;
                                self.calc_flags(res, self.get_size(parts[0]));
                                self.regs.set_by_name(parts[0], res);
                            }
                        }
                    },

                    Some("sal") => {
                        if !step {
                            println!("{}{} {}{}", colors.green, pos, ins, colors.nc);
                        }
                        let op = ins.op_str().unwrap();
                        let parts:Vec<&str> = op.split(", ").collect();
                        let twoparams = parts.len() == 1;

                        if twoparams {
                            if self.is_reg(parts[0]) {
                                // reg
                                if self.is_reg(parts[1]) {
                                    // sal reg, reg
                                    let value0:u32 = self.regs.get_by_name(parts[0]);
                                    let value1:u32 = self.regs.get_by_name(parts[1]);
                                    let mut unsigned64:u64 = value0 as u64;
                                    let res:u32;
                                    let bits = self.get_size(parts[0]);
                                
                                    for _ in 0..value1 {
                                        unsigned64 *= 2;
                                    }

                                    match bits {
                                        32 => {
                                            self.flags.f_cf = unsigned64 > 0xffffffff;
                                            res = (unsigned64 & 0xffffffff) as u32
                                        },
                                        16 => {
                                            self.flags.f_cf = unsigned64 > 0xffff;
                                            res = (unsigned64 & 0xffff) as u32
                                        },
                                        8  => {
                                            self.flags.f_cf = unsigned64 > 0xff;
                                            res = (unsigned64 & 0xff) as u32;
                                        },
                                        _  => panic!("weird precision")
                                    }

                                    self.calc_flags(res, bits);
                                    self.regs.set_by_name(parts[0], res);


                                } else  {
                                    // sal reg, imm
                                    let value0:u32 = self.regs.get_by_name(parts[0]);
                                    let value1:u32 = self.get_inmediate(parts[1]);
                                    let mut unsigned64:u64 = value0 as u64;
                                    let res:u32;
                                    let bits = self.get_size(parts[0]);
                                
                                    for _ in 0..value1 {
                                        unsigned64 *= 2;
                                    }

                                    match bits {
                                        32 => {
                                            self.flags.f_cf = unsigned64 > 0xffffffff;
                                            res = (unsigned64 & 0xffffffff) as u32
                                        },
                                        16 => {
                                            self.flags.f_cf = unsigned64 > 0xffff;
                                            res = (unsigned64 & 0xffff) as u32
                                        },
                                        8  => {
                                            self.flags.f_cf = unsigned64 > 0xff;
                                            res = (unsigned64 & 0xff) as u32;
                                        },
                                        _  => panic!("weird precision")
                                    }

                                    self.calc_flags(res, bits);
                                    self.regs.set_by_name(parts[0], res);
                                }


                            } else {
                                // mem
                                if self.is_reg(parts[1]) {
                                    // sal mem, reg
                                    let value0:u32 = match self.memory_read(parts[0]) {
                                        Some(v) => v,
                                        None => {
                                            self.exception();
                                            break;
                                        }
                                    };
                                    let value1:u32 = self.regs.get_by_name(parts[1]);

                                    let mut unsigned64:u64 = value0 as u64;
                                    let res:u32;
                                    let bits = self.get_size(parts[0]);
                                
                                    for _ in 0..value1 {
                                        unsigned64 *= 2;
                                    }

                                    match bits {
                                        32 => {
                                            self.flags.f_cf = unsigned64 > 0xffffffff;
                                            res = (unsigned64 & 0xffffffff) as u32
                                        },
                                        16 => {
                                            self.flags.f_cf = unsigned64 > 0xffff;
                                            res = (unsigned64 & 0xffff) as u32
                                        },
                                        8  => {
                                            self.flags.f_cf = unsigned64 > 0xff;
                                            res = (unsigned64 & 0xff) as u32;
                                        },
                                        _  => panic!("weird precision")
                                    }

                                    self.calc_flags(res, bits);
                                    if !self.memory_write(parts[0], res) {
                                        self.exception();
                                        break;
                                    }

                                } else {
                                    // sal mem, imm
                                    let value0:u32 = match self.memory_read(parts[0]) {
                                        Some(v) => v,
                                        None => {
                                            self.exception();
                                            break;
                                        }
                                    };
                                    let value1:u32 = self.get_inmediate(parts[1]);
                                    let mut unsigned64:u64 = value0 as u64;
                                    let res:u32;
                                    let bits = self.get_size(parts[0]);
                                
                                    for _ in 0..value1 {
                                        unsigned64 *= 2;
                                    }

                                    match bits {
                                        32 => {
                                            self.flags.f_cf = unsigned64 > 0xffffffff;
                                            res = (unsigned64 & 0xffffffff) as u32
                                        },
                                        16 => {
                                            self.flags.f_cf = unsigned64 > 0xffff;
                                            res = (unsigned64 & 0xffff) as u32
                                        },
                                        8  => {
                                            self.flags.f_cf = unsigned64 > 0xff;
                                            res = (unsigned64 & 0xff) as u32;
                                        },
                                        _  => panic!("weird precision")
                                    }

                                    self.calc_flags(res, bits);
                                    if !self.memory_write(parts[0], res) {
                                        self.exception();
                                        break;
                                    }
                                }

                            }


                        } else { // one param
                            if self.is_reg(op) { // reg
                                let value:i32 = self.regs.get_by_name(op) as i32;
                                let unsigned64:u64;
                                let res:u32;
                                let bits = self.get_size(op);

                                unsigned64 = (value as u64) * 2;

                                match bits {
                                    32 => {
                                        self.flags.f_cf = unsigned64 > 0xffffffff;
                                        res = (unsigned64 & 0xffffffff) as u32
                                    },
                                    16 => {
                                        self.flags.f_cf = unsigned64 > 0xffff;
                                        res = (unsigned64 & 0xffff) as u32
                                    },
                                    8  => {
                                        self.flags.f_cf = unsigned64 > 0xff;
                                        res = (unsigned64 & 0xff) as u32;
                                    },
                                    _  => panic!("weird precision")
                                }

                                self.calc_flags(res, bits);
                                self.regs.set_by_name(op, res);


                            } else { // mem 
                                let value:i32 = match self.memory_read(op) {
                                    Some(v) => v as i32,
                                    None => {
                                        self.exception();
                                        break;
                                    }
                                };
                                let unsigned64:u64;
                                let res:u32;
                                let bits = self.get_size(op);

                                unsigned64 = (value as u64) * 2;

                                match bits {
                                    32 => {
                                        self.flags.f_cf = unsigned64 > 0xffffffff;
                                        res = (unsigned64 & 0xffffffff) as u32
                                    },
                                    16 => {
                                        self.flags.f_cf = unsigned64 > 0xffff;
                                        res = (unsigned64 & 0xffff) as u32
                                    },
                                    8  => {
                                        self.flags.f_cf = unsigned64 > 0xff;
                                        res = (unsigned64 & 0xff) as u32;
                                    },
                                    _  => panic!("weird precision")
                                }

                                self.calc_flags(res, bits);
                                if !self.memory_write(op, res) {
                                    self.exception();
                                    break;
                                }
                            }
                        }
                    },

                    Some("sar") => {
                        if !step {
                            println!("{}{} {}{}", colors.green, pos, ins, colors.nc);
                        }
                        let op = ins.op_str().unwrap();
                        let parts:Vec<&str> = op.split(", ").collect();
                        let twoparams = parts.len() == 1;

                        if twoparams {
                            if self.is_reg(parts[0]) {
                                // reg
                                if self.is_reg(parts[1]) {
                                    // shl reg, reg
                                    let value0:u32 = self.regs.get_by_name(parts[0]);
                                    let value1:u32 = self.regs.get_by_name(parts[1]);
                                    let mut unsigned64:u64 = value0 as u64;
                                    let res:u32;
                                    let bits = self.get_size(parts[0]);
                                
                                    for _ in 0..value1 {
                                        unsigned64 /= 2;
                                    }

                                    match bits {
                                        32 => {
                                            self.flags.f_cf = unsigned64 > 0xffffffff;
                                            res = (unsigned64 & 0xffffffff) as u32
                                        },
                                        16 => {
                                            self.flags.f_cf = unsigned64 > 0xffff;
                                            res = (unsigned64 & 0xffff) as u32
                                        },
                                        8  => {
                                            self.flags.f_cf = unsigned64 > 0xff;
                                            res = (unsigned64 & 0xff) as u32;
                                        },
                                        _  => panic!("weird precision")
                                    }

                                    self.calc_flags(res, bits);
                                    self.regs.set_by_name(parts[0], res);

                                } else  {
                                    // shl reg, imm
                                    let value0:u32 = self.regs.get_by_name(parts[0]);
                                    let value1:u32 = self.get_inmediate(parts[1]);
                                    let mut unsigned64:u64 = value0 as u64;
                                    let res:u32;
                                    let bits = self.get_size(parts[0]);
                                
                                    for _ in 0..value1 {
                                        unsigned64 /= 2;
                                    }

                                    match bits {
                                        32 => {
                                            self.flags.f_cf = unsigned64 > 0xffffffff;
                                            res = (unsigned64 & 0xffffffff) as u32
                                        },
                                        16 => {
                                            self.flags.f_cf = unsigned64 > 0xffff;
                                            res = (unsigned64 & 0xffff) as u32
                                        },
                                        8  => {
                                            self.flags.f_cf = unsigned64 > 0xff;
                                            res = (unsigned64 & 0xff) as u32;
                                        },
                                        _  => panic!("weird precision")
                                    }

                                    self.calc_flags(res, bits);
                                    self.regs.set_by_name(parts[0], res);
                                }


                            } else {
                                // mem
                                if self.is_reg(parts[1]) {
                                    // shl mem, reg
                                    let value0:u32 = match self.memory_read(parts[0]) {
                                        Some(v) => v,
                                        None => {
                                            self.exception();
                                            break;
                                        }
                                    };
                                    let value1:u32 = self.regs.get_by_name(parts[1]);

                                    let mut unsigned64:u64 = value0 as u64;
                                    let res:u32;
                                    let bits = self.get_size(parts[0]);
                                
                                    for _ in 0..value1 {
                                        unsigned64 /= 2;
                                    }

                                    match bits {
                                        32 => {
                                            self.flags.f_cf = unsigned64 > 0xffffffff;
                                            res = (unsigned64 & 0xffffffff) as u32
                                        },
                                        16 => {
                                            self.flags.f_cf = unsigned64 > 0xffff;
                                            res = (unsigned64 & 0xffff) as u32
                                        },
                                        8  => {
                                            self.flags.f_cf = unsigned64 > 0xff;
                                            res = (unsigned64 & 0xff) as u32;
                                        },
                                        _  => panic!("weird precision")
                                    }

                                    self.calc_flags(res, bits);
                                    if !self.memory_write(parts[0], res) {
                                        self.exception();
                                        break;  
                                    }


                                } else {
                                    // shl mem, imm
                                    let value0:u32 = match self.memory_read(parts[0]) {
                                        Some(v) => v,
                                        None => {
                                            self.exception();
                                            break;
                                        }
                                    };
                                    let value1:u32 = self.get_inmediate(parts[1]);
                                    let mut unsigned64:u64 = value0 as u64;
                                    let res:u32;
                                    let bits = self.get_size(parts[0]);
                                
                                    for _ in 0..value1 {
                                        unsigned64 /= 2;
                                    }

                                    match bits {
                                        32 => {
                                            self.flags.f_cf = unsigned64 > 0xffffffff;
                                            res = (unsigned64 & 0xffffffff) as u32
                                        },
                                        16 => {
                                            self.flags.f_cf = unsigned64 > 0xffff;
                                            res = (unsigned64 & 0xffff) as u32
                                        },
                                        8  => {
                                            self.flags.f_cf = unsigned64 > 0xff;
                                            res = (unsigned64 & 0xff) as u32;
                                        },
                                        _  => panic!("weird precision")
                                    }

                                    self.calc_flags(res, bits);
                                    if !self.memory_write(parts[0], res) {
                                        self.exception();
                                        break;
                                    }
                                }

                            }

                        } else { // one param
                            if self.is_reg(op) { // reg
                                let value:i32 = self.regs.get_by_name(op) as i32;
                                let unsigned64:u64;
                                let res:u32;
                                let bits = self.get_size(op);

                                unsigned64 = (value as u64) / 2;

                                match bits {
                                    32 => {
                                        self.flags.f_cf = unsigned64 > 0xffffffff;
                                        res = (unsigned64 & 0xffffffff) as u32
                                    },
                                    16 => {
                                        self.flags.f_cf = unsigned64 > 0xffff;
                                        res = (unsigned64 & 0xffff) as u32
                                    },
                                    8  => {
                                        self.flags.f_cf = unsigned64 > 0xff;
                                        res = (unsigned64 & 0xff) as u32;
                                    },
                                    _  => panic!("weird precision")
                                }

                                self.calc_flags(res, bits);
                                self.regs.set_by_name(op, res);


                            } else { // mem 
                                let value:i32 = match self.memory_read(op) {
                                    Some(v) => v as i32,
                                    None => {
                                        self.exception();
                                        break;
                                    }
                                };
                                let unsigned64:u64;
                                let res:u32;
                                let bits = self.get_size(op);

                                unsigned64 = (value as u64) / 2;

                                match bits {
                                    32 => {
                                        self.flags.f_cf = unsigned64 > 0xffffffff;
                                        res = (unsigned64 & 0xffffffff) as u32
                                    },
                                    16 => {
                                        self.flags.f_cf = unsigned64 > 0xffff;
                                        res = (unsigned64 & 0xffff) as u32
                                    },
                                    8  => {
                                        self.flags.f_cf = unsigned64 > 0xff;
                                        res = (unsigned64 & 0xff) as u32;
                                    },
                                    _  => panic!("weird precision")
                                }

                                self.calc_flags(res, bits);
                                if !self.memory_write(op, res) {
                                    self.exception();
                                    break;
                                }
                            }
                        }
                    },

                    Some("shr") => {
                        if !step {
                            println!("{}{} {}{}", colors.green, pos, ins, colors.nc);
                        }
                        let op = ins.op_str().unwrap();
                        let parts:Vec<&str> = op.split(", ").collect();
                        let twoparams = parts.len() == 2;

                        if twoparams {
                            if self.is_reg(parts[0]) {
                                // reg
                                if self.is_reg(parts[1]) {
                                    // shr reg, reg
                                    let value0:u32 = self.regs.get_by_name(parts[0]);
                                    let value1:u32 = self.regs.get_by_name(parts[1]);
                                    let mut unsigned64:u64 = value0 as u64;
                                    let res:u32;
                                    let bits = self.get_size(parts[0]);
                                
                                    for _ in 0..value1 {
                                        unsigned64 /= 2;
                                    }

                                    match bits {
                                        32 => {
                                            self.flags.f_cf = unsigned64 > 0xffffffff;
                                            res = (unsigned64 & 0xffffffff) as u32
                                        },
                                        16 => {
                                            self.flags.f_cf = unsigned64 > 0xffff;
                                            res = (unsigned64 & 0xffff) as u32
                                        },
                                        8  => {
                                            self.flags.f_cf = unsigned64 > 0xff;
                                            res = (unsigned64 & 0xff) as u32;
                                        },
                                        _  => panic!("weird precision")
                                    }

                                    self.calc_flags(res, bits);
                                    self.regs.set_by_name(parts[0], res);


                                } else  {
                                    // shr reg, imm
                                    let value0:u32 = self.regs.get_by_name(parts[0]);
                                    let value1:u32 = self.get_inmediate(parts[1]);
                                    let mut unsigned64:u64 = value0 as u64;
                                    let res:u32;
                                    let bits = self.get_size(parts[0]);
                                
                                    for _ in 0..value1 {
                                        unsigned64 /= 2;
                                    }

                                    match bits {
                                        32 => {
                                            self.flags.f_cf = unsigned64 > 0xffffffff;
                                            res = (unsigned64 & 0xffffffff) as u32
                                        },
                                        16 => {
                                            self.flags.f_cf = unsigned64 > 0xffff;
                                            res = (unsigned64 & 0xffff) as u32
                                        },
                                        8  => {
                                            self.flags.f_cf = unsigned64 > 0xff;
                                            res = (unsigned64 & 0xff) as u32;
                                        },
                                        _  => panic!("weird precision")
                                    }

                                    self.calc_flags(res, bits);
                                    self.regs.set_by_name(parts[0], res);
                                }


                            } else {
                                // mem
                                if self.is_reg(parts[1]) {
                                    // shr mem, reg
                                    let value0:u32 = match self.memory_read(parts[0]) {
                                        Some(v) => v,
                                        None => {
                                            self.exception();
                                            break;
                                        }
                                    };
                                    let value1:u32 = self.regs.get_by_name(parts[1]);
                                    let mut unsigned64:u64 = value0 as u64;
                                    let res:u32;
                                    let bits = self.get_size(parts[0]);
                                    

                                    for _ in 0..value1 {
                                        unsigned64 /= 2;
                                    }

                                    match bits {
                                        32 => {
                                            self.flags.f_cf = unsigned64 > 0xffffffff;
                                            res = (unsigned64 & 0xffffffff) as u32
                                        },
                                        16 => {
                                            self.flags.f_cf = unsigned64 > 0xffff;
                                            res = (unsigned64 & 0xffff) as u32
                                        },
                                        8  => {
                                            self.flags.f_cf = unsigned64 > 0xff;
                                            res = (unsigned64 & 0xff) as u32;
                                        },
                                        _  => panic!("weird precision")
                                    }

                                    self.calc_flags(res, bits);
                                    if !self.memory_write(parts[0], res) {
                                        self.exception();
                                        break;
                                    }

                                } else {
                                    // shr mem, imm
                                    let value0:u32 = match self.memory_read(parts[0]) {
                                        Some(v) => v,
                                        None => {
                                            self.exception();
                                            break;
                                        }
                                    };
                                    let value1:u32 = self.get_inmediate(parts[1]);
                                    let mut unsigned64:u64 = value0 as u64;
                                    let res:u32;
                                    let bits = self.get_size(parts[0]);
                                
                                    for _ in 0..value1 {
                                        unsigned64 /= 2;
                                    }

                                    match bits {
                                        32 => {
                                            self.flags.f_cf = unsigned64 > 0xffffffff;
                                            res = (unsigned64 & 0xffffffff) as u32
                                        },
                                        16 => {
                                            self.flags.f_cf = unsigned64 > 0xffff;
                                            res = (unsigned64 & 0xffff) as u32
                                        },
                                        8  => {
                                            self.flags.f_cf = unsigned64 > 0xff;
                                            res = (unsigned64 & 0xff) as u32;
                                        },
                                        _  => panic!("weird precision")
                                    }

                                    self.calc_flags(res, bits);
                                    if !self.memory_write(parts[0], res) {
                                        self.exception();
                                        break;
                                    }
                                }

                            }


                        } else { // one param
                            if self.is_reg(op) { // reg
                                let value:i32 = self.regs.get_by_name(op) as i32;
                                let unsigned64:u64;
                                let res:u32;
                                let bits = self.get_size(op);

                                unsigned64 = (value as u64) / 2;

                                match bits {
                                    32 => {
                                        self.flags.f_cf = unsigned64 > 0xffffffff;
                                        res = (unsigned64 & 0xffffffff) as u32
                                    },
                                    16 => {
                                        self.flags.f_cf = unsigned64 > 0xffff;
                                        res = (unsigned64 & 0xffff) as u32
                                    },
                                    8  => {
                                        self.flags.f_cf = unsigned64 > 0xff;
                                        res = (unsigned64 & 0xff) as u32;
                                    },
                                    _  => panic!("weird precision")
                                }

                                self.calc_flags(res, bits);
                                self.regs.set_by_name(op, res);


                            } else { // mem 
                                let value:i32 = match self.memory_read(op) {
                                    Some(v) => v as i32,
                                    None => {
                                        self.exception();
                                        break;
                                    }
                                };
                                let unsigned64:u64;
                                let res:u32;
                                let bits = self.get_size(op);

                                unsigned64 = (value as u64) / 2;

                                match bits {
                                    32 => {
                                        self.flags.f_cf = unsigned64 > 0xffffffff;
                                        res = (unsigned64 & 0xffffffff) as u32
                                    },
                                    16 => {
                                        self.flags.f_cf = unsigned64 > 0xffff;
                                        res = (unsigned64 & 0xffff) as u32
                                    },
                                    8  => {
                                        self.flags.f_cf = unsigned64 > 0xff;
                                        res = (unsigned64 & 0xff) as u32;
                                    },
                                    _  => panic!("weird precision")
                                }

                                self.calc_flags(res, bits);
                                if !self.memory_write(op, res) {
                                    self.exception();
                                    break;
                                }
                            }
                        }

                    },

                    Some("shl") => {
                        if !step {
                            println!("{}{} {}{}", colors.green, pos, ins, colors.nc);
                        }
                        let op = ins.op_str().unwrap();
                        let parts:Vec<&str> = op.split(", ").collect();
                        let twoparams = parts.len() == 2;

                        if twoparams {
                            if self.is_reg(parts[0]) {
                                // reg
                                if self.is_reg(parts[1]) {
                                    // shl reg, reg
                                    let value0:u32 = self.regs.get_by_name(parts[0]);
                                    let value1:u32 = self.regs.get_by_name(parts[1]);
                                    let mut unsigned64:u64 = value0 as u64;
                                    let res:u32;
                                    let bits = self.get_size(parts[0]);
                                
                                    for _ in 0..value1 {
                                        unsigned64 *= 2;
                                    }

                                    match bits {
                                        32 => {
                                            self.flags.f_cf = unsigned64 > 0xffffffff;
                                            res = (unsigned64 & 0xffffffff) as u32
                                        },
                                        16 => {
                                            self.flags.f_cf = unsigned64 > 0xffff;
                                            res = (unsigned64 & 0xffff) as u32
                                        },
                                        8  => {
                                            self.flags.f_cf = unsigned64 > 0xff;
                                            res = (unsigned64 & 0xff) as u32;
                                        },
                                        _  => panic!("weird precision")
                                    }

                                    self.calc_flags(res, bits);
                                    self.regs.set_by_name(parts[0], res);


                                } else  {
                                    // shl reg, imm
                                    let value0:u32 = self.regs.get_by_name(parts[0]);
                                    let value1:u32 = self.get_inmediate(parts[1]);
                                    let mut unsigned64:u64 = value0 as u64;
                                    let res:u32;
                                    let bits = self.get_size(parts[0]);
                                
                                    for _ in 0..value1 {
                                        unsigned64 *= 2;
                                    }

                                    match bits {
                                        32 => {
                                            self.flags.f_cf = unsigned64 > 0xffffffff;
                                            res = (unsigned64 & 0xffffffff) as u32
                                        },
                                        16 => {
                                            self.flags.f_cf = unsigned64 > 0xffff;
                                            res = (unsigned64 & 0xffff) as u32
                                        },
                                        8  => {
                                            self.flags.f_cf = unsigned64 > 0xff;
                                            res = (unsigned64 & 0xff) as u32;
                                        },
                                        _  => panic!("weird precision")
                                    }

                                    self.calc_flags(res, bits);
                                    self.regs.set_by_name(parts[0], res);
                                }

                            } else {
                                // mem
                                if self.is_reg(parts[1]) {
                                    // shl mem, reg
                                    let value0:u32 = match self.memory_read(parts[0]) {
                                        Some(v) => v,
                                        None => {
                                            self.exception();
                                            break;
                                        }
                                    };
                                    let value1:u32 = self.regs.get_by_name(parts[1]);
                                    let mut unsigned64:u64 = value0 as u64;
                                    let res:u32;
                                    let bits = self.get_size(parts[0]);
                                
                                    for _ in 0..value1 {
                                        unsigned64 *= 2;
                                    }

                                    match bits {
                                        32 => {
                                            self.flags.f_cf = unsigned64 > 0xffffffff;
                                            res = (unsigned64 & 0xffffffff) as u32
                                        },
                                        16 => {
                                            self.flags.f_cf = unsigned64 > 0xffff;
                                            res = (unsigned64 & 0xffff) as u32
                                        },
                                        8  => {
                                            self.flags.f_cf = unsigned64 > 0xff;
                                            res = (unsigned64 & 0xff) as u32;
                                        },
                                        _  => panic!("weird precision")
                                    }

                                    self.calc_flags(res, bits);
                                    if !self.memory_write(parts[0], res) {
                                        self.exception();
                                        break;
                                    }

                                } else {
                                    // shl mem, imm
                                    let value0:u32 = match self.memory_read(parts[0]) {
                                        Some(v) => v,
                                        None => {
                                            self.exception();
                                            break;
                                        }
                                    };
                                    let value1:u32 = self.get_inmediate(parts[1]);
                                    let mut unsigned64:u64 = value0 as u64;
                                    let res:u32;
                                    let bits = self.get_size(parts[0]);
                                
                                    for _ in 0..value1 {
                                        unsigned64 *= 2;
                                    }

                                    match bits {
                                        32 => {
                                            self.flags.f_cf = unsigned64 > 0xffffffff;
                                            res = (unsigned64 & 0xffffffff) as u32
                                        },
                                        16 => {
                                            self.flags.f_cf = unsigned64 > 0xffff;
                                            res = (unsigned64 & 0xffff) as u32
                                        },
                                        8  => {
                                            self.flags.f_cf = unsigned64 > 0xff;
                                            res = (unsigned64 & 0xff) as u32;
                                        },
                                        _  => panic!("weird precision")
                                    }

                                    self.calc_flags(res, bits);
                                    if !self.memory_write(parts[0], res) {
                                        self.exception();
                                        break;
                                    }
                                }

                            }


                        } else { // one param
                            if self.is_reg(op) { // reg
                                let value:i32 = self.regs.get_by_name(op) as i32;
                                let unsigned64:u64;
                                let res:u32;
                                let bits = self.get_size(op);

                                unsigned64 = (value as u64) * 2;

                                match bits {
                                    32 => {
                                        self.flags.f_cf = unsigned64 > 0xffffffff;
                                        res = (unsigned64 & 0xffffffff) as u32
                                    },
                                    16 => {
                                        self.flags.f_cf = unsigned64 > 0xffff;
                                        res = (unsigned64 & 0xffff) as u32
                                    },
                                    8  => {
                                        self.flags.f_cf = unsigned64 > 0xff;
                                        res = (unsigned64 & 0xff) as u32;
                                    },
                                    _  => panic!("weird precision")
                                }

                                self.calc_flags(res, bits);
                                self.regs.set_by_name(op, res);


                            } else { // mem 
                                let value:i32 = match self.memory_read(op) {
                                    Some(v) => v as i32,
                                    None => {
                                        self.exception();
                                        break;
                                    }
                                };
                                let unsigned64:u64;
                                let res:u32;
                                let bits = self.get_size(op);

                                unsigned64 = (value as u64) * 2;

                                match bits {
                                    32 => {
                                        self.flags.f_cf = unsigned64 > 0xffffffff;
                                        res = (unsigned64 & 0xffffffff) as u32
                                    },
                                    16 => {
                                        self.flags.f_cf = unsigned64 > 0xffff;
                                        res = (unsigned64 & 0xffff) as u32
                                    },
                                    8  => {
                                        self.flags.f_cf = unsigned64 > 0xff;
                                        res = (unsigned64 & 0xff) as u32;
                                    },
                                    _  => panic!("weird precision")
                                }

                                self.calc_flags(res, bits);
                                if !self.memory_write(op, res) {
                                    self.exception();
                                    break;
                                }
                            }
                        }
                    },



                    Some("ror") => {
                        if !step {
                            println!("{}{} {}{}", colors.green, pos, ins, colors.nc);
                        }
                        let op = ins.op_str().unwrap();
                        let parts:Vec<&str> = op.split(", ").collect();
                        let twoparams = parts.len() == 2;

                        if twoparams {
                            
                            if self.is_reg(parts[0]) {
                                // reg
                                if self.is_reg(parts[1]) {
                                    // ror reg, reg
                                    let value0:u32 = self.regs.get_by_name(parts[0]);
                                    let value1:u32 = self.regs.get_by_name(parts[1]);
                                    let res:u32;
                                    let bits:u8 = self.get_size(parts[0]);
                                
                                    res = self.rotate_right(value0, value1, bits as u32);
                            
                                    self.calc_flags(res, bits);
                                    self.regs.set_by_name(parts[0], res);


                                } else  {
                                    // ror reg, imm
                                    let value0:u32 = self.regs.get_by_name(parts[0]);
                                    let value1:u32 = self.get_inmediate(parts[1]);
                                    let res:u32;
                                    let bits:u8 = self.get_size(parts[0]);
                                    
                                    res = self.rotate_right(value0, value1, bits as u32);

                                    self.calc_flags(res, bits);
                                    self.regs.set_by_name(parts[0], res);
                                }


                            } else {
                                // mem
                                if self.is_reg(parts[1]) {
                                    // ror mem, reg
                                    let value0:u32 = match self.memory_read(parts[0]) {
                                        Some(v) => v,
                                        None => {
                                            self.exception();
                                            break;
                                        }
                                    };
                                    let value1:u32 = self.regs.get_by_name(parts[1]);

                                    let res:u32;
                                    let bits:u8 = self.get_size(op);

                                    res = self.rotate_right(value0, value1, bits as u32);
                              
                                    self.calc_flags(res, bits);
                                    if !self.memory_write(parts[0], res) {
                                        self.exception();
                                        break;
                                    }

                                } else {
                                    // ror mem, imm
                                    let value0:u32 = match self.memory_read(parts[0]) {
                                        Some(v) => v,
                                        None => {
                                            self.exception();
                                            break;
                                        }
                                    };
                                    let value1:u32 = self.get_inmediate(parts[1]);
                                    let res:u32;
                                    let bits:u8 = self.get_size(op);

                                    res = self.rotate_right(value0, value1, bits as u32);

                                    self.calc_flags(res, bits);
                                    if !self.memory_write(parts[0], res) {
                                        self.exception();
                                        break;
                                    }
                                }
                            }


                        } else { // one param
                            if self.is_reg(op) { 
                                // ror reg
                                let value:u32 = self.regs.get_by_name(op);
                                let res:u32;
                                let bits:u8 = self.get_size(op);

                                res = self.rotate_right(value, 1, bits as u32);

                                self.calc_flags(res, bits);
                                self.regs.set_by_name(op, res);


                            } else { 
                                // ror mem 
                                let value:u32 = match self.memory_read(op) {
                                    Some(v) => v,
                                    None => {
                                        self.exception();
                                        break;
                                    }
                                };
                                let res:u32;
                                let bits:u8 = self.get_size(op);

                                res = self.rotate_right(value, 1, bits as u32);

                                self.calc_flags(res, bits);
                                if !self.memory_write(op, res) {
                                    self.exception();
                                    break;
                                }
                            }
                        }
                    },

                    Some("rol") => {
                        if !step {
                            println!("{}{} {}{}", colors.green, pos, ins, colors.nc);
                        }
                        let op = ins.op_str().unwrap();
                        let parts:Vec<&str> = op.split(", ").collect();
                        let twoparams = parts.len() == 1;

                        if twoparams {
                            if self.is_reg(parts[0]) {
                                // reg
                                if self.is_reg(parts[1]) {
                                    // rol reg, reg
                                    let value0:u32 = self.regs.get_by_name(parts[0]);
                                    let value1:u32 = self.regs.get_by_name(parts[1]);
                                    let res:u32;
                                    let bits:u8 = self.get_size(op);
                                
                                    res = self.rotate_left(value0, value1, bits as u32);
                            
                                    self.calc_flags(res, bits);
                                    self.regs.set_by_name(parts[0], res);


                                } else  {
                                    // rol reg, imm
                                    let value0:u32 = self.regs.get_by_name(parts[0]);
                                    let value1:u32 = self.get_inmediate(parts[1]);
                                    let res:u32;
                                    let bits:u8 = self.get_size(op);
                                    
                                    res = self.rotate_left(value0, value1, bits as u32);

                                    self.calc_flags(res, bits);
                                    self.regs.set_by_name(parts[0], res);
                                }


                            } else {
                                // mem
                                if self.is_reg(parts[1]) {
                                    // rol mem, reg
                                    let value0:u32 = match self.memory_read(parts[0]) {
                                        Some(v) => v,
                                        None => {
                                            self.exception();
                                            break;
                                        }
                                    };
                                    let value1:u32 = self.regs.get_by_name(parts[1]);

                                    let res:u32;
                                    let bits:u8 = self.get_size(op);

                                    res = self.rotate_left(value0, value1, bits as u32);
                              
                                    self.calc_flags(res, bits);
                                    if !self.memory_write(parts[0], res) {
                                        self.exception();
                                        break;  
                                    }

                                } else {
                                    // rol mem, imm
                                    let value0:u32 = match self.memory_read(parts[0]) {
                                        Some(v) => v,
                                        None => {
                                            self.exception();
                                            break;
                                        }
                                    };
                                    let value1:u32 = self.get_inmediate(parts[1]);
                                    let res:u32;
                                    let bits:u8 = self.get_size(op);

                                    res = self.rotate_left(value0, value1, bits as u32);

                                    self.calc_flags(res, bits);
                                    if !self.memory_write(parts[0], res) {
                                        self.exception();
                                        break;
                                    }
                                }
                            }


                        } else { // one param
                            if self.is_reg(op) { 
                                // rol reg
                                let value:u32 = self.regs.get_by_name(op);
                                let res:u32;
                                let bits:u8 = self.get_size(op);

                                res = self.rotate_left(value, 1, bits as u32);

                                self.calc_flags(res, bits);
                                self.regs.set_by_name(op, res);


                            } else { 
                                // rol mem 
                                let value:u32 = match self.memory_read(op) {
                                    Some(v) => v,
                                    None => {
                                        self.exception();
                                        break;
                                    }
                                };
                                let res:u32;
                                let bits:u8 = self.get_size(op);

                                res = self.rotate_left(value, 1, bits as u32);

                                self.calc_flags(res, bits);
                                if !self.memory_write(op, res) {
                                    self.exception();
                                    break;
                                }
                            }
                        }
                    },

                    Some("mul") => {
                        if !step {
                            println!("{}{} {}{}", colors.cyan, pos, ins, colors.nc);
                        }
                        let op = ins.op_str().unwrap();
                        let bits = self.get_size(op);
                        if self.is_reg(op) {
                            // mul reg

                            match bits {
                                32 => {
                                    let value1:u32 = self.regs.eax;
                                    let value2:u32 = self.regs.get_by_name(op);
                                    let res:u64 = value1 as u64 * value2 as u64;
                                    self.regs.edx = ((res & 0xffffffff00000000) >> 32) as u32;
                                    self.regs.eax = (res & 0x00000000ffffffff) as u32;
                                    self.flags.f_pf = (res & 0xff) % 2 == 0;
                                    self.flags.f_of = self.regs.edx != 0;
                                    self.flags.f_cf = self.regs.edx != 0;
                                },
                                16 => {
                                    let value1:u32 = self.regs.get_ax();
                                    let value2:u32 = self.regs.get_by_name(op);
                                    let res:u32 = value1 * value2;
                                    self.regs.set_dx((res & 0xffff0000) >> 16);
                                    self.regs.set_ax(res & 0xffff);
                                    self.flags.f_pf = (res & 0xff) % 2 == 0;
                                    self.flags.f_of = self.regs.get_dx() != 0;
                                    self.flags.f_cf = self.regs.get_dx() != 0;
                                },
                                8 => {
                                    let value1:u32 = self.regs.get_al();
                                    let value2:u32 = self.regs.get_by_name(op);
                                    let res:u32 = value1 * value2;
                                    self.regs.set_ax(res & 0xffff);
                                    self.flags.f_pf = (res & 0xff) % 2 == 0;
                                    self.flags.f_of = self.regs.get_ah() != 0;
                                    self.flags.f_cf = self.regs.get_ah() != 0;
                                },
                                _ => panic!("weird precision")
                            }

                        } else {
                            // mul mem
                            match bits {
                                32 => {
                                    let value1:u32 = self.regs.eax;
                                    let value2:u32 = match self.memory_read(op) {
                                        Some(v) => v,
                                        None => {
                                            self.exception();
                                            break;
                                        }
                                    };
                                    let res:u64 = value1 as u64 * value2 as u64;
                                    self.regs.edx = ((res & 0xffffffff00000000) >> 32) as u32;
                                    self.regs.eax = (res & 0x00000000ffffffff) as u32;
                                    self.flags.f_pf = (res & 0xff) % 2 == 0;
                                    self.flags.f_of = self.regs.edx != 0;
                                    self.flags.f_cf = self.regs.edx != 0;
                                },
                                16 => {
                                    let value1:u32 = self.regs.get_ax();
                                    let value2:u32 = match self.memory_read(op) {
                                        Some(v) => v & 0xffff,
                                        None => {
                                            self.exception();
                                            break;
                                        }
                                    };
                                    let res:u32 = value1 * value2;
                                    self.regs.set_dx((res & 0xffff0000) >> 16);
                                    self.regs.set_ax(res & 0xffff);
                                    self.flags.f_pf = (res & 0xff) % 2 == 0;
                                    self.flags.f_of = self.regs.get_dx() != 0;
                                    self.flags.f_cf = self.regs.get_dx() != 0;
                                },
                                8 => {
                                    let value1:u32 = self.regs.get_al();
                                    let value2:u32 = match self.memory_read(op) {
                                        Some(v) => v & 0xff,
                                        None => {
                                            self.exception();
                                            break;
                                        }
                                    };
                                    let res:u32 = value1 * value2;
                                    self.regs.set_ax(res & 0xffff);
                                    self.flags.f_pf = (res & 0xff) % 2 == 0;
                                    self.flags.f_of = self.regs.get_ah() != 0;
                                    self.flags.f_cf = self.regs.get_ah() != 0;
                                },
                                _ => panic!("weird precision")
                            }
                        }
                    },

                    Some("div") => {
                        if !step {
                            println!("{}{} {}{}", colors.cyan, pos, ins, colors.nc);
                        }
                        let op = ins.op_str().unwrap();
                        let bits = self.get_size(op);
                        if self.is_reg(op) {
                            // div reg

                            match bits {
                                32 => {
                                    let mut value1:u64 = self.regs.edx as u64;
                                        value1 = value1 << 32;
                                        value1 += self.regs.eax as u64;
                                    let value2:u64 = self.regs.get_by_name(op) as u64;
                                    if value2 == 0 {
                                        self.flags.f_tf = true;
                                        println!("/!\\ division by 0 exception");
                                        self.exception();
                                        break;
                                        
                                        
                                    } else {
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

                                },
                                16 => {
                                    let value1:u32 = (self.regs.get_dx() << 16) + self.regs.get_ax();
                                    let value2:u32 = self.regs.get_by_name(op);
                                    if value2 == 0 {
                                        self.flags.f_tf = true;
                                        println!("/!\\ division by 0 exception");
                                        self.exception();
                                        break;
                                    } else {
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
             
                                },
                                8 => {
                                    let value1:u32 = self.regs.get_ax();
                                    let value2:u32 = self.regs.get_by_name(op);
                                    if value2 == 0 {
                                        self.flags.f_tf = true;
                                        println!("/!\\ division by 0 exception");
                                        self.exception();
                                        break;
                                    } else {
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
                                    
                                },
                                _ => panic!("weird precision")
                            }

                        } else {
                            // div mem
                            match bits {
                                32 => {
                                    let mut value1:u64 = self.regs.edx as u64;
                                        value1 = value1 << 32;
                                        value1 += self.regs.eax as u64;
                                    let value2:u64 = match self.memory_read(op) {
                                        Some(v) => v as u64,
                                        None => {
                                            self.exception();
                                            break;
                                        }
                                    };
                                    if value2 == 0 {
                                        self.flags.f_tf = true;
                                        println!("/!\\ division by 0 exception");
                                        self.exception();
                                        break;
                                    } else {
                                        let resq:u64 = value1 / value2;
                                        let resr:u64 = value1 % value2;
                                        self.regs.eax = resq as u32;
                                        self.regs.edx = resr as u32;
                                        self.flags.f_pf = (resq & 0xff) % 2 == 0;
                                        self.flags.f_of = resq > 0xffffffff;
                                        if self.flags.f_of {
                                            println!("/!\\ int overflow in division");
                                        }
                                    }

                                },
                                16 => {
                                    let value1:u32 = (self.regs.get_dx() << 16) + self.regs.get_ax();
                                    let value2:u32 = match self.memory_read(op) {
                                        Some(v) => v,
                                        None => {
                                            self.exception();
                                            break;
                                        }
                                    };
                                    if value2 == 0 {
                                        self.flags.f_tf = true;
                                        println!("/!\\ division by 0 exception");
                                        self.exception();
                                        break;
                                    } else {
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
             
                                },
                                8 => {
                                    let value1:u32 = self.regs.get_ax();
                                    let value2:u32 = match self.memory_read(op) {
                                        Some(v) => v,
                                        None => {
                                            self.exception();
                                            break;
                                        }
                                    };
                                    if value2 == 0 {
                                        self.flags.f_tf = true;
                                        println!("/!\\ division by 0 exception");
                                        self.exception();
                                        break;
                                    } else {
                                        let resq:u32 = value1 / value2;
                                        let resr:u32 = value1 % value2;
                                        self.regs.set_al(resq);
                                        self.regs.set_ah(resr);
                                        self.flags.f_pf = (resq & 0xff) % 2 == 0;
                                        self.flags.f_of = resq > 0xff;
                                        self.flags.f_tf = false;
                                        if self.flags.f_of {
                                            println!("/!\\ int overflow on division");
                                        }
                                    }
                                    
                                },
                                _ => panic!("weird precision")
                            }
                        }
                    },

                    Some("idiv") => {
                        if !step {
                            println!("{}{} {}{}", colors.cyan, pos, ins, colors.nc);
                        }
                        let op = ins.op_str().unwrap();
                        let bits = self.get_size(op);
                        if self.is_reg(op) {
                            // idiv reg

                            match bits {
                                32 => {
                                    let mut value1:u64 = self.regs.edx as u64;
                                        value1 = value1 << 32;
                                        value1 += self.regs.eax as u64;
                                    let value2:u64 = self.regs.get_by_name(op) as u64;
                                    if value2 == 0 {
                                        self.flags.f_tf = true;
                                        println!("/!\\ division by 0 exception");
                                        self.exception();
                                        break;
                                    } else {
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
                                            if (value1 as i64) > 0 && (resq as i32) < 0 {
                                                println!("/!\\ sign change exception on division");
                                                if self.break_on_alert {
                                                    panic!();
                                                }
                                            } else if (value1 as i64) < 0 && (resq as i32) > 0 { 
                                                println!("/!\\ sign change exception on division");
                                                if self.break_on_alert {
                                                    panic!();
                                                }
                                            }
                                        }
                                    }

                                },
                                16 => {
                                    let value1:u32 = (self.regs.get_dx() << 16) + self.regs.get_ax();
                                    let value2:u32 = self.regs.get_by_name(op);
                                    if value2 == 0 {
                                        self.flags.f_tf = true;
                                        println!("/!\\ division by 0 exception");
                                        self.exception();
                                        break;
                                    } else {
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
                                            if (value1 as i32) > 0 && (resq as i16) < 0 {
                                                println!("/!\\ sign change exception on division");
                                                if self.break_on_alert {
                                                    panic!();
                                                }
                                            } else if (value1 as i32) < 0 && (resq as i16) > 0 { 
                                                println!("/!\\ sign change exception on division");
                                                if self.break_on_alert {
                                                    panic!();
                                                }
                                            }
                                        }
                                    }
             
                                },
                                8 => {
                                    let value1:u32 = self.regs.get_ax();
                                    let value2:u32 = self.regs.get_by_name(op);
                                    if value2 == 0 {
                                        self.flags.f_tf = true;
                                        println!("/!\\ division by 0 exception");
                                        self.exception();
                                        break;
                                    } else {
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
                                            if (value1 as i16) > 0 && (resq as i8) < 0 {
                                                println!("/!\\ sign change exception on division");
                                                if self.break_on_alert {
                                                    panic!();
                                                }
                                            } else if (value1 as i16) < 0 && (resq as i8) > 0 { 
                                                println!("/!\\ sign change exception on division");
                                                if self.break_on_alert {
                                                    panic!();
                                                }
                                            }
                                        }
                                    }
                                    
                                },
                                _ => panic!("weird precision")
                            }

                        } else {
                            // idiv mem
                            match bits {
                                32 => {
                                    let mut value1:u64 = self.regs.edx as u64;
                                        value1 = value1 << 32;
                                        value1 += self.regs.eax as u64;
                                    let value2:u64 = match self.memory_read(op) {
                                        Some(v) => v as u64,
                                        None => {
                                            self.exception();
                                            break;
                                        }
                                    };
                                    if value2 == 0 {
                                        self.flags.f_tf = true;
                                        println!("/!\\ division by 0 exception");
                                        self.exception();
                                        break;
                                    } else {
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
                                            if (value1 as i64) > 0 && (resq as i32) < 0 {
                                                println!("/!\\ sign change exception on division");
                                                if self.break_on_alert {
                                                    panic!();
                                                }
                                            } else if (value1 as i64) < 0 && (resq as i32) > 0 { 
                                                println!("/!\\ sign change exception on division");
                                                if self.break_on_alert {
                                                    panic!();
                                                }
                                            }
                                        }
                                    }

                                },
                                16 => {
                                    let value1:u32 = (self.regs.get_dx() << 16) + self.regs.get_ax();
                                    let value2:u32 = match self.memory_read(op) {
                                        Some(v) => v,
                                        None => {
                                            self.exception();
                                            break;
                                        }
                                    };
                                    if value2 == 0 {
                                        self.flags.f_tf = true;
                                        println!("/!\\ division by 0 exception");
                                        self.exception();
                                        break;
                                    } else {
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
                                            if (value1 as i32) > 0 && (resq as i16) < 0 {
                                                println!("/!\\ sign change exception on division");
                                                if self.break_on_alert {
                                                    panic!();
                                                }
                                            } else if (value1 as i32) < 0 && (resq as i16) > 0 { 
                                                println!("/!\\ sign change exception on division");
                                                if self.break_on_alert {
                                                    panic!();
                                                }
                                            }
                                        }
                                    }
             
                                },
                                8 => {
                                    let value1:u32 = self.regs.get_ax();
                                    let value2:u32 = match self.memory_read(op) {
                                        Some(v) => v,
                                        None => {
                                            self.exception();
                                            break;
                                        }
                                    };
                                    if value2 == 0 {
                                        self.flags.f_tf = true;
                                        println!("/!\\ division by 0 exception");
                                        self.exception();
                                        break;
                                    } else {
                                        let resq:u32 = value1 / value2;
                                        let resr:u32 = value1 % value2;
                                        self.regs.set_al(resq);
                                        self.regs.set_ah(resr);
                                        self.flags.f_pf = (resq & 0xff) % 2 == 0;
                                        self.flags.f_tf = false;
                                        if resq > 0xff {
                                            println!("/!\\ int overflow exception on division");
                                            if self.break_on_alert {
                                                panic!();
                                            }
                                        } else {
                                            if (value1 as i16) > 0 && (resq as i8) < 0 {
                                                println!("/!\\ sign change exception on division");
                                                if self.break_on_alert {
                                                    panic!();
                                                }
                                            } else if (value1 as i16) < 0 && (resq as i8) > 0 { 
                                                println!("/!\\ sign change exception on division");
                                                if self.break_on_alert {
                                                    panic!();
                                                }
                                            }
                                        }
                                    }
                                    
                                },
                                _ => panic!("weird precision")
                            }
                        }
                    },

                    Some("imul") => {
                        if !step {
                            println!("{} {}", pos, ins);
                        }
                        //https://c9x.me/x86/html/file_module_x86_id_138.html
                        panic!("not implemented");
                    },

                    Some("movsx") => {
                        if !step {
                            println!("{}{} {}{}", colors.light_cyan, pos, ins, colors.nc);
                        }
                        let op = ins.op_str().unwrap();
                        let parts:Vec<&str> = op.split(", ").collect();
                        let value2:u32;                    

                        if self.is_reg(parts[1]) {
                            // movzx reg, reg
                            value2 = self.regs.get_by_name(parts[1]);
                        } else {
                            // movzx reg, mem
                            value2 = match self.memory_read(parts[1]) {
                                Some(v) => v,
                                None => {
                                    self.exception();
                                    break;
                                }
                            };
                        }

                        let rbits = self.get_size(parts[1]);

                        match rbits {
                            32 => panic!("cant be movsx of 32 bits"),
                            16 => {
                                if value2 > 0x7fff {
                                    self.regs.set_by_name(parts[0], 0xffff0000 + value2)
                                } else {
                                    self.regs.set_by_name(parts[0], value2);
                                }
                            },
                            8 => {
                                if value2 > 0x7f {
                                    self.regs.set_by_name(parts[0], 0xffffff00 + value2)
                                } else {
                                    self.regs.set_by_name(parts[0], value2);
                                }
                            },
                            _ => panic!("wrong precision"),
                        }
                    },

                    Some("movzx") => {
                        if !step {
                            println!("{}{} {}{}", colors.light_cyan, pos, ins, colors.nc);
                        }
                        let op = ins.op_str().unwrap();
                        let parts:Vec<&str> = op.split(", ").collect();
                        let value2:u32;                    

                        if self.is_reg(parts[1]) {
                            // movzx reg, reg
                            value2 = self.regs.get_by_name(parts[1]);
                        } else {
                            // movzx reg, mem
                            value2 = match self.memory_read(parts[1]) {
                                Some(v) => v,
                                None => {
                                    self.exception();
                                    break;
                                }
                            };
                        }

                        self.regs.set_by_name(parts[0], value2);
                    },

                    Some("test") => {
                        if !step {
                            println!("{}{} {}{}", colors.orange, pos, ins, colors.nc);
                        }
                        let op = ins.op_str().unwrap();
                        let parts:Vec<&str> = op.split(", ").collect();
                        let bits = self.get_size(parts[0]);
                        let value1:u32;
                        let value2:u32;
                        let result:u32;

                        if self.is_reg(parts[0]) {
                            if self.is_reg(parts[1]) {
                                // cmp reg, reg
                                value1 = self.regs.get_by_name(parts[0]);
                                value2 = self.regs.get_by_name(parts[1]);

                            } else if parts[1].contains("[") {
                                // cmp reg, mem
                                value1 = self.regs.get_by_name(parts[0]);
                                value2 = match self.memory_read(parts[1]) {
                                    Some(v) => v,
                                    None => {
                                        self.exception();
                                        break;
                                    }
                                };


                            } else {
                                // cmp reg, inm
                                value1 = self.regs.get_by_name(parts[0]);
                                value2 = self.get_inmediate(parts[1]);

                            }

                        } else {
                            if self.is_reg(parts[1]) {
                                // cmp mem, reg
                                value1 = match self.memory_read(parts[0]) {
                                    Some(v) => v,
                                    None => {
                                        self.exception();
                                        break;
                                    }
                                };
                                value2 = self.regs.get_by_name(parts[1]);

                            } else {
                                // cmp mem, inm
                                value1 = match self.memory_read(parts[0]) {
                                    Some(v) => v,
                                    None => {
                                        self.exception();
                                        break;
                                    }
                                };
                                value2 = self.get_inmediate(parts[1]);

                            }
                        }

                        result = value1 & value2;

                        self.flags.f_zf = result == 0;
                        self.flags.f_cf = false;
                        self.flags.f_of = false;
                        self.flags.f_pf = (result & 0xff) % 2 == 0;

                        match bits {
                            32 => self.flags.f_sf = (result as i32) < 0,
                            16 => self.flags.f_sf = (result as i16) < 0,
                            8  => self.flags.f_sf = (result as i8) < 0,
                            _  => panic!("weird precision")
                        }

                    },

                    Some("cmp") => {
                        if !step {
                            println!("{}{} {}{}", colors.orange, pos, ins, colors.nc);                            
                            println!("\tcmp-> eax: 0x{:x} ebx: 0x{:x} ecx: 0x{:x} edx: 0x{:x} esi: 0x{:x} edi: 0x{:x}", self.regs.eax, self.regs.ebx, self.regs.ecx, self.regs.edx, self.regs.esi, self.regs.edi);
                        }
                        let op = ins.op_str().unwrap();
                        let parts:Vec<&str> = op.split(", ").collect();
                        let bits = self.get_size(parts[0]);
                        let value1:u32;
                        let value2:u32;

                        if self.is_reg(parts[0]) {
                            if self.is_reg(parts[1]) {
                                // cmp reg, reg
                                value1 = self.regs.get_by_name(parts[0]);
                                value2 = self.regs.get_by_name(parts[1]);

                            } else if parts[1].contains("[") {
                                // cmp reg, mem
                                value1 = self.regs.get_by_name(parts[0]);
                                value2 = match self.memory_read(parts[1]) {
                                    Some(v) => v,
                                    None => {
                                        self.exception();
                                        break;
                                    }
                                };


                            } else {
                                // cmp reg, inm
                                value1 = self.regs.get_by_name(parts[0]);
                                value2 = self.get_inmediate(parts[1]);

                            }

                        } else {
                            if self.is_reg(parts[1]) {
                                // cmp mem, reg
                                value1 = match self.memory_read(parts[0]) {
                                    Some(v) => v,
                                    None => {
                                        self.exception();
                                        break;
                                    }
                                };
                                value2 = self.regs.get_by_name(parts[1]);

                            } else {
                                // cmp mem, inm
                                value1 = match self.memory_read(parts[0]) {
                                    Some(v) => v,
                                    None => {
                                        self.exception();
                                        break;
                                    }
                                };
                                value2 = self.get_inmediate(parts[1]);

                            }
                        }

                        match bits {
                            32 => { self.flags_sub32(value1, value2); },
                            16 => { self.flags_sub16(value1, value2); },
                             8 => { self.flags_sub8(value1, value2); },
                             _ => panic!("incorrect bits size"),
                        }

                        /*
                        let res:i32 = (value1 as i64 - value2 as i64) as i32;

                        self.flags.f_zf = res == 0;
                        self.flags.f_sf = res < 0;

    

                        if value1 < value2 {
                            self.flags.f_zf = false;
                            self.flags.f_cf = true;

                        } else if value1 > value2 {
                            self.flags.f_zf = false;
                            self.flags.f_cf = false;

                        } else if value1 == value2 {
                            self.flags.f_zf = true;
                            self.flags.f_cf = false;
                            self.flags.f_of = false;
                        }*/
                        


                    },  


                    //branches: https://web.itu.edu.tr/kesgin/mul06/intel/instr/jxx.html
                    //          https://c9x.me/x86/html/file_module_x86_id_146.html
                    //          http://unixwiz.net/techtips/x86-jumps.html <---aqui

                    Some("jo") => {
                        if !step {
                            println!("{}{} {}{}", colors.orange, pos, ins, colors.nc);
                        }
                        if self.flags.f_of {
                            if !step {
                                println!("{}{} {}{} taken", colors.orange, pos, ins, colors.nc);
                            }
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} {}{} not taken", colors.orange, pos, ins, colors.nc);
                            }
                        }
                    },

                    Some("jno") => {
                        
                        if !self.flags.f_of {
                            if !step {
                                println!("{}{} {}{} taken", colors.orange, pos, ins, colors.nc);
                            }
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} {}{} not taken", colors.orange, pos, ins, colors.nc);
                            }
                        }
                    },

                    Some("js") => {
                        if self.flags.f_sf {
                            if !step {
                                println!("{}{} {}{} taken", colors.orange, pos, ins, colors.nc);
                            }
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} {}{} not taken", colors.orange, pos, ins, colors.nc);
                            }
                        }
                        
                    },

                    Some("jns") => {
                        if !self.flags.f_sf {
                            if !step {
                                println!("{}{} {}{} taken", colors.orange, pos, ins, colors.nc);
                            }
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} {}{} not taken", colors.orange, pos, ins, colors.nc);
                            }
                        }
                    },

                    Some("je") => {
                        if self.flags.f_zf {
                            if !step {
                                println!("{}{} {}{} taken", colors.orange, pos, ins, colors.nc);
                            }
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} {}{} not taken", colors.orange, pos, ins, colors.nc);
                            }
                        }
                    },

                    Some("jz") => {
                        if self.flags.f_zf {
                            if !step {
                                println!("{}{} {}{} taken", colors.orange, pos, ins, colors.nc);
                            }
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} {}{} not taken", colors.orange, pos, ins, colors.nc);
                            }
                        }
                    },


                    Some("jne") => {
                        if !self.flags.f_zf {
                            if !step {
                                println!("{}{} {}{} taken", colors.orange, pos, ins, colors.nc);
                            }
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} {}{} not taken", colors.orange, pos, ins, colors.nc);
                            }
                        }
                    },

                    Some("jnz") => {
                        if !self.flags.f_zf {
                            if !step {
                                println!("{}{} {}{} taken", colors.orange, pos, ins, colors.nc);
                            }
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} {}{} not taken", colors.orange, pos, ins, colors.nc);
                            }
                        }
                    },

                    Some("jb") => {
                        if self.flags.f_cf {
                            if !step {
                                println!("{}{} {}{} taken", colors.orange, pos, ins, colors.nc);
                            }
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} {}{} not taken", colors.orange, pos, ins, colors.nc);
                            }
                        }
                    },

                    Some("jnae") => {
                        if self.flags.f_cf {
                            if !step {
                                println!("{}{} {}{} taken", colors.orange, pos, ins, colors.nc);
                            }
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} {}{} not taken", colors.orange, pos, ins, colors.nc);
                            }
                        }
                    },

                    Some("jc") => {
                        if self.flags.f_cf {
                            if !step {
                                println!("{}{} {}{} taken", colors.orange, pos, ins, colors.nc);
                            }
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} {}{} not taken", colors.orange, pos, ins, colors.nc);
                            }
                        }
                    },

                    Some("jnb") => {
                        if !self.flags.f_cf {
                            if !step {
                                println!("{}{} {}{} taken", colors.orange, pos, ins, colors.nc);
                            }
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} {}{} not taken", colors.orange, pos, ins, colors.nc);
                            }
                        }
                    },

                    Some("jae") => {
                        if !self.flags.f_cf {
                            if !step {
                                println!("{}{} {}{} taken", colors.orange, pos, ins, colors.nc);
                            }
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} {}{} not taken", colors.orange, pos, ins, colors.nc);
                            }
                        }
                    },

                    Some("jnc") => {
                        if !self.flags.f_cf {
                            if !step {
                                println!("{}{} {}{} taken", colors.orange, pos, ins, colors.nc);
                            }
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} {}{} not taken", colors.orange, pos, ins, colors.nc);
                            }
                        }
                    },

                    Some("jbe") => {
                        if self.flags.f_cf || self.flags.f_zf {
                            if !step {
                                println!("{}{} {}{} taken", colors.orange, pos, ins, colors.nc);
                            }
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} {}{} not taken", colors.orange, pos, ins, colors.nc);
                            }
                        }
                    },

                    Some("jna") => {
                        if self.flags.f_cf || self.flags.f_zf {
                            if !step {
                                println!("{}{} {}{} taken", colors.orange, pos, ins, colors.nc);
                            }
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} {}{} not taken", colors.orange, pos, ins, colors.nc);
                            }
                        }
                    },

                    Some("ja") => {
                        if !self.flags.f_cf && !self.flags.f_zf {
                            if !step {
                                println!("{}{} {}{} taken", colors.orange, pos, ins, colors.nc);
                            }
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} {}{} not taken", colors.orange, pos, ins, colors.nc);
                            }
                        }
                    },

                    Some("jnbe") => {
                        if !self.flags.f_cf && !self.flags.f_zf {
                            if !step {
                                println!("{}{} {}{} taken", colors.orange, pos, ins, colors.nc);
                            }
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} {}{} not taken", colors.orange, pos, ins, colors.nc);
                            }
                        }
                    },

                    Some("jl") => {
                        if self.flags.f_sf != self.flags.f_of {
                            if !step {
                                println!("{}{} {}{} taken", colors.orange, pos, ins, colors.nc);
                            }
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} {}{} not taken", colors.orange, pos, ins, colors.nc);
                            }
                        }
                    },

                    Some("jnge") => {
                        if self.flags.f_sf != self.flags.f_of {
                            if !step {
                                println!("{}{} {}{} taken", colors.orange, pos, ins, colors.nc);
                            }
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} {}{} not taken", colors.orange, pos, ins, colors.nc);
                            }
                        }
                    },

                    Some("jge") => {
                        if self.flags.f_sf == self.flags.f_of {
                            if !step {
                                println!("{}{} {}{} taken", colors.orange, pos, ins, colors.nc);
                            }
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} {}{} not taken", colors.orange, pos, ins, colors.nc);
                            }
                        }
                    },

                    Some("jnl") => {
                        if self.flags.f_sf == self.flags.f_of {
                            if !step {
                                println!("{}{} {}{} taken", colors.orange, pos, ins, colors.nc);
                            }
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} {}{} not taken", colors.orange, pos, ins, colors.nc);
                            }
                        }
                    },

                    Some("jle") => {
                        if self.flags.f_zf || self.flags.f_sf != self.flags.f_of {
                            if !step {
                                println!("{}{} {}{} taken", colors.orange, pos, ins, colors.nc);
                            }
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} {}{} not taken", colors.orange, pos, ins, colors.nc);
                            }
                        }
                    },

                    Some("jng") => {
                        if self.flags.f_zf || self.flags.f_sf != self.flags.f_of {
                            if !step {
                                println!("{}{} {}{} taken", colors.orange, pos, ins, colors.nc);
                            }
    
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} {}{} not taken", colors.orange, pos, ins, colors.nc);
                            }
                        }
                    },

                    Some("jg") => {
                        if !self.flags.f_zf && self.flags.f_sf != self.flags.f_of {
                            if !step {
                                println!("{}{} {}{} taken", colors.orange, pos, ins, colors.nc);
                            }
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} {}{} not taken", colors.orange, pos, ins, colors.nc);
                            }
                        }
                    },

                    Some("jnle") => {
                        if !self.flags.f_zf && self.flags.f_sf != self.flags.f_of {
                            if !step {
                                println!("{}{} {}{} taken", colors.orange, pos, ins, colors.nc);
                            }
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} {}{} not taken", colors.orange, pos, ins, colors.nc);
                            }
                        }
                    },

                    Some("jp") => {
                        if self.flags.f_pf {
                            if !step {
                                println!("{}{} {}{} taken", colors.orange, pos, ins, colors.nc);
                            }
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} {}{} not taken", colors.orange, pos, ins, colors.nc);
                            }
                        }
                    },

                    Some("jpe") => {
                        if self.flags.f_pf {
                            if !step {
                                println!("{}{} {}{} taken", colors.orange, pos, ins, colors.nc);
                            }
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} {}{} not taken", colors.orange, pos, ins, colors.nc);
                            }
                        }
                    },

                    Some("jnp") => {
                        if !self.flags.f_pf {
                            if !step {
                                println!("{}{} {}{} taken", colors.orange, pos, ins, colors.nc);
                            }
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} {}{} not taken", colors.orange, pos, ins, colors.nc);
                            }
                        }
                    },

                    Some("jpo") => {
                        if !self.flags.f_pf {
                            if !step {
                                println!("{}{} {}{} taken", colors.orange, pos, ins, colors.nc);
                            }
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} {}{} not taken", colors.orange, pos, ins, colors.nc);
                            }
                        }
                    },

                    Some("jcxz") => {
                        if self.regs.get_cx() == 0 {
                            if !step {
                                println!("{}{} {}{} taken", colors.orange, pos, ins, colors.nc);
                            }
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} {}{} not taken", colors.orange, pos, ins, colors.nc);
                            }
                        }
                    },

                    Some("jecxz") => {
                        if self.regs.ecx == 0 {
                            if !step {
                                println!("{}{} {}{} taken", colors.orange, pos, ins, colors.nc);
                            }
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        } else {
                            if !step {
                                println!("{}{} {}{} not taken", colors.orange, pos, ins, colors.nc);
                            }
                        }
                    },


                    //TODO: test syenter / int80
                    Some("int3") => {
                        if !step {
                            println!("{}{} {}{}", colors.red, pos, ins, colors.nc);
                        }
                        println!("/!\\ int 3 sigtrap!!!!");
                        self.exception();
                        break;
                    },

                    Some("nop") => {
                        if !step {
                            println!("{} {}", pos, ins);
                        }
                    },

                    Some("mfence")|Some("lfence")|Some("sfence") => {
                        if !step {
                            println!("{}{} {}{}", colors.red, pos, ins, colors.nc);
                        }
                    }

                    Some("cpuid") => {
                        if !step {
                            println!("{}{} {}{}", colors.red, pos, ins, colors.nc);
                        }
                        // guloader checks bit31 which is if its hipervisor with command
                        // https://c9x.me/x86/html/file_module_x86_id_45.html

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
                            _ => panic!("unimplemented cpuid call 0x{:x}", self.regs.eax),
                        }

                    },

                    Some("clc") => {
                        if !step {
                            println!("{}{} {}{}", colors.light_gray, pos, ins, colors.nc);
                        }
                        self.flags.f_cf = false;
                    },

                    Some("rdtsc") => {
                        if !step {
                            println!("{}{} {}{}", colors.red, pos, ins, colors.nc);
                        }
                        self.regs.edx = 0;
                        self.regs.eax = 0;

                    },

                    Some("loop") => {
                        if !step {
                            println!("{}{} {}{}", colors.yellow, pos, ins, colors.nc);
                        }
                        let addr = self.get_inmediate(ins.op_str().unwrap());
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
                    },

                    Some("loope") => {
                        if !step {
                            println!("{}{} {}{}", colors.yellow, pos, ins, colors.nc);
                        }
                        let addr = self.get_inmediate(ins.op_str().unwrap());
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
                    },

                    Some("loopz") => {
                        if !step {
                            println!("{}{} {}{}", colors.yellow, pos, ins, colors.nc);
                        }
                        let addr = self.get_inmediate(ins.op_str().unwrap());
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
                    },

                    Some("loopne") => {
                        if !step {
                            println!("{}{} {}{}", colors.yellow, pos, ins, colors.nc);
                        }
                        let addr = self.get_inmediate(ins.op_str().unwrap());
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
                    },

                    Some("loopnz") => {
                        if !step {
                            println!("{}{} {}{}", colors.yellow, pos, ins, colors.nc);
                        }
                        let addr = self.get_inmediate(ins.op_str().unwrap());
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
                    },

                    Some("lea") => {
                        if !step {
                            println!("{}{} {}{}", colors.light_cyan, pos, ins, colors.nc);
                        }
                        let ops = ins.op_str().unwrap();
                        let parts:Vec<&str> = ops.split(", ").collect();
                        let spl:Vec<&str> = parts[1].split("[").collect::<Vec<&str>>()[1].split("]").collect::<Vec<&str>>()[0].split(" ").collect();
                        let mut result:u32 = 0;
                        let mut sum = false;
                        let mut sub = false;

                        for i in 0..spl.len() {
                            if spl[i] == "+" {
                                sub = false;
                                sum = true;
                            } else if  spl[i] == "-" {
                                sum = false;
                                sub = true;
                            } else if self.is_reg(spl[i]) {
                                if sum {
                                    result = result + self.regs.get_by_name(spl[i]);
                                } else if sub {
                                    result = result - self.regs.get_by_name(spl[i]);
                                } else {
                                    result = self.regs.get_by_name(spl[i]);
                                }
                            } else {
                                if sum {
                                    result = result + self.get_inmediate(spl[i]);
                                } else if sub {
                                    result = result - self.get_inmediate(spl[i]);
                                } else {
                                    result = self.get_inmediate(spl[i]);
                                }
                            }
                        }

                        self.regs.set_by_name(parts[0], result);
                    },

                    Some("leave") => {
                        if !step {
                            println!("{}{} {}{}", colors.red, pos, ins, colors.nc);
                        }
                        self.regs.esp = self.regs.ebp;
                        self.regs.ebp = self.stack_pop(true);
                    },

                    Some("int") => {
                        if !step {
                            println!("{}{} {}{}", colors.red, pos, ins, colors.nc);
                        }
                        let op = ins.op_str().unwrap();
                        let interrupt = u32::from_str_radix(op.trim_start_matches("0x"),16).expect("conversion error");
                        match interrupt {
                            0x80 => {
                                println!("/!\\ interrupt 0x80 function:{}", self.regs.eax);
                                if self.break_on_alert {
                                    panic!();
                                }
                                match self.regs.eax {
                                    11 => {
                                        panic!("execve() detected");
                                    }
                                    _ => {}
                                }
                            },
                            _ => {
                                panic!("unknown interrupt {}", interrupt);
                            }
                        }
                    },

                    Some("lock btr") => {
                        // 747712 0x775b77b2: lock btr dword ptr [eax], 0
                        if !step {
                            println!("{}{} {}{}", colors.blue, pos, ins, colors.nc);
                        }
                        let op = ins.op_str().unwrap();
                        let parts:Vec<&str> = op.split(", ").collect();
                        let bit_off = self.get_inmediate(parts[1]);
                        let bit_base = match self.memory_read(parts[0]) {
                            Some(v) => v,
                            None => {
                                self.exception();
                                break;
                            }
                        };
                        let bit:u32 = bit_base & (1 << (bit_off-1)); // thanks Robert

                        self.flags.f_cf = bit == 1;
                        
                    },

                    Some("lock cmpxchg") => {
                        if !step {
                            println!("{}{} {}{}", colors.blue, pos, ins, colors.nc);
                        }
                        // 747743 0x775a229a: lock cmpxchg dword ptr [ebx], edx
                        // compare memory [ebx] with eax if they are same, move edx to [ebx]
                        let op = ins.op_str().unwrap();
                        let parts:Vec<&str> = op.split(", ").collect();
                        let bits = self.get_size(parts[0]);
                        let memval = match self.memory_read(parts[0]) {
                            Some(v) => v,
                            None=> {
                                self.exception();
                                break;
                            }
                        };

                        match bits {
                            32 => {
                                if memval == self.regs.eax {
                                    if !self.memory_write(parts[0], memval) {
                                        self.exception();
                                        break;
                                    }
                                }
                            },
                            16 => {
                                if memval == self.regs.get_ax() {
                                    if !self.memory_write(parts[0], memval) {
                                        self.exception();
                                        break;
                                    }
                                }
                            },
                             8 => {
                                if memval == self.regs.get_al() {
                                    if !self.memory_write(parts[0], memval) {
                                        self.exception();
                                        break;
                                    }
                                }
                            },
                             _ => panic!("weird precision"),
                        }

                    },

                    Some("std") => {
                        if !step {
                            println!("{}{} {}{}", colors.blue, pos, ins, colors.nc);
                        }
                        self.flags.f_df = true;
                    },

                    Some("cld") => {
                        if !step {
                            println!("{}{} {}{}", colors.blue, pos, ins, colors.nc);
                        }
                        self.flags.f_df = false;
                    },

                    Some("lodsd") => {
                        if !step {
                            println!("{}{} {}{}", colors.cyan, pos, ins, colors.nc);
                        }
                        let val = match self.memory_read("dword ptr [esi]") { 
                            Some(v) => v,
                            None => panic!("lodsw: memory read error")
                        };
                        self.regs.eax = val;
                        if self.flags.f_df {
                            self.regs.esi -= 4;
                        } else {
                            self.regs.esi += 4;
                        }
                    },

                    Some("lodsw") => {
                        if !step {
                            println!("{}{} {}{}", colors.cyan, pos, ins, colors.nc);
                        }
                        let val = match self.memory_read("word ptr [esi]") {
                            Some(v) => v,
                            None => panic!("lodsw: memory read error")
                        };
                        self.regs.set_ax(val);
                        if self.flags.f_df {
                            self.regs.esi -= 2;
                        } else {
                            self.regs.esi += 2;
                        }
                    },

                    Some("lodsb") => {
                        if !step {
                            println!("{}{} {}{}", colors.cyan, pos, ins, colors.nc);
                        }
                        let val = match self.memory_read("byte ptr [esi]") {
                            Some(v) => v,
                            None => panic!("lodsw: memory read error")
                        };
                        self.regs.set_al(val);
                        if self.flags.f_df {
                            self.regs.esi -= 1;
                        } else {
                            self.regs.esi += 1;
                        }
                    },

                    Some("lods") => {
                        if !step {
                            println!("{}{} {}{}", colors.cyan, pos, ins, colors.nc);
                        }

                        let op = ins.op_str().unwrap();
                        let bits = self.get_size(op);
                        let val = match self.memory_read(op) {
                            Some(v) => v,
                            None => panic!("lodsw: memory read error")
                        };

                        match bits {
                            32 => {
                                self.regs.eax = val;
                                if self.flags.f_df {
                                    self.regs.esi -= 4;
                                } else {
                                    self.regs.esi += 4;
                                }
                            },
                            16 => {
                                self.regs.set_ax(val);
                                if self.flags.f_df {
                                    self.regs.esi -= 2;
                                } else {
                                    self.regs.esi += 2;
                                }
                            },
                            8 => {
                                self.regs.set_al(val);
                                if self.flags.f_df {
                                    self.regs.esi -= 1;
                                } else {
                                    self.regs.esi += 1;
                                }
                            },
                            _ => panic!("bad precision"),
                        }
                    },


                    Some("sysenter") => {
                        println!("{}{} {}{} function: 0x{:x}", colors.red, pos, ins, colors.nc, self.regs.eax);
                        return;
                    }

                    Some(&_) =>  { 
                        println!("{}{} {}{}", colors.red, pos, ins, colors.nc);
                        panic!("unimplemented instruction");
                    },
                    None => panic!("none instruction"),
                }

                self.regs.eip += sz as u32;

            }
        }   

        

    }

}