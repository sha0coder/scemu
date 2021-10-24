/*
    TODO:
        - code no deberia estar en posicion 0 y si cae en 0 un set_eip finalizar.
        - ante un pop mirar si ha recogido un puntero a un string y printar el string.
        - pop popea una direccion de codigo?
        - modo de ver codigo o de no verlo
        - modo de ver solo los saltos/branches/calls/rets
        - en cada set_eip() dumpear pila a fichero
        - detectar si lleva mucho tiempo loopeado
*/


extern crate capstone;

mod flags; 
mod eflags;
mod mem32;
mod regs32;


use flags::Flags;
use eflags::Eflags;
use mem32::Mem32;
use regs32::Regs32;

//use std::mem;
//use std::fs;
use std::fs::File;
use std::io::Read;
use capstone::prelude::*;
//use capstone::arch::x86::X86Operand;

pub struct Emu32 {
    regs: Regs32,
    flags: Flags,
    eflags: Eflags,
    code: Mem32,
    stack: Mem32,
    peb: Mem32,
}

impl Emu32 {
    pub fn new() -> Emu32 {
        Emu32{
            regs: Regs32::new(),
            flags: Flags::new(),
            eflags: Eflags::new(),
            code: Mem32::new(),
            stack: Mem32::new(),
            peb: Mem32::new(),
        }
    }

    pub fn init(&mut self) {
        println!("initializing regs");
        self.regs.clear();
        self.regs.esp = 0x00100000;
        self.regs.ebp = 0x00100100;
        self.regs.eip = 0;

        println!("initializing code and stack");
        self.code.set_base(self.regs.eip);
        let q = (self.stack.size() as u32) / 4;
        self.stack.set_base(self.regs.esp - (q*3));

        /* fake PEB
                mov eax, dword ptr fs:[0x30]        
                mov eax, dword ptr [eax + 0xc]
                mov eax, dword ptr [eax + 0x14]
                mov ecx, dword ptr [eax]
        */
        
        //TODO: replicate full PEB structure
        println!("initializing PEB");
        self.peb.set_base(0x00200000);   

        // 0x02 must be 0   (is being debugged)

        self.peb.write_dword(0x00200000, 0x00200004);       // PEB addr
        self.peb.write_dword(0x00200004+0xc, 0x00200008);   // PEB->Ldr
        self.peb.write_dword(0x00200008+0x14, 0x0020000c);  // PEB->Ldr.InMemOrder
        self.peb.write_dword(0x0020000c, 0x00210000);
        self.peb.write_dword(0x00210000, 0x00004e00);
    }

    pub fn load_code(&mut self, filename: &String) {
        let mut f = File::open(&filename).expect("no file found");
        //let metadata = fs::metadata(&filename).expect("unable to read metadata");
        //let mut buffer = vec![0; metadata.len() as usize];
        f.read(&mut self.code.mem).expect("buffer overflow");
    }

    pub fn stack_push(&mut self, value:u32) {
        self.regs.esp -= 4;
        self.stack.write_dword(self.regs.esp, value);
    }

    pub fn stack_pop(&mut self) -> u32 {
        let value = self.stack.read_dword(self.regs.esp);
        if self.code.inside(value) {
            println!("/!\\ poping a code address 0x{:x}", value);
        }
        self.regs.esp += 4;
        return value;
    }

    pub fn memory_operand_to_address(&self, operand:&str) -> u32 {
        let spl:Vec<&str> = operand.split("[").collect::<Vec<&str>>()[1].split("]").collect::<Vec<&str>>()[0].split(" ").collect();

        if operand.contains("fs:[") {
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
                return self.peb.get_base();
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
                let num = usize::from_str_radix(spl2[1].trim_start_matches("0x"),16).expect("bad num conversion") as u32;

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
            let disp:u32 = usize::from_str_radix(spl[2].trim_start_matches("0x"),16).expect("bad disp") as u32;
            
            if sign != "+" && sign != "-" {
                panic!("weird sign {}", sign);
            }

            if sign == "+" {
                return self.regs.get_by_name(reg) + disp;
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
    
    pub fn memory_read(&mut self, operand:&str) -> u32 {
        //TODO: access to operand .disp instead parsing the string
        //ie [ebp + 0x44]
        let addr:u32 = self.memory_operand_to_address(operand);

        // check integrity of eip, esp and ebp registers


        // could be normal if executing code from stack
        if !self.code.inside(self.regs.eip) {
            panic!("eip outside code");
        }

        // could be normal using part of code as stack
        if !self.stack.inside(self.regs.esp) {
            //hack: redirect stack
            self.regs.esp = self.stack.get_base() + 0x1ff;

            //panic!("esp outside stack");
        }

        if !self.stack.inside(self.regs.ebp) {
            panic!("ebp outside stack");
        }

        // isnt normal, addr outside maps
        if !self.code.inside(addr) && !self.stack.inside(addr) && !self.peb.inside(addr) {
            panic!("addr 0x{:x} outside maps, operand: {}", addr, operand);
        }

        let value:u32;

        if self.code.inside(addr) {

            if operand.contains("byte ptr") {
                value = (self.code.read_byte(addr) as u32) & 0x000000ff;

            } else if operand.contains("word ptr") {
                value = (self.code.read_word(addr) as u32) & 0x0000ffff;
                
            } else if operand.contains("dword ptr") {
                value = self.code.read_dword(addr);
    
            } else {
                panic!("weird precision: {}", operand);
            }

            return value;
        }

        if self.stack.inside(addr) {

            if operand.contains("byte ptr") {
                value = (self.stack.read_byte(addr) as u32) & 0x000000ff;

            } else if operand.contains("word ptr") {
                value = (self.stack.read_word(addr) as u32) & 0x0000ffff;
                
            } else if operand.contains("dword ptr") {
                value = self.stack.read_dword(addr);
    
            } else {
                panic!("weird precision: {}", operand);
            }

            return value;
        }

        if self.peb.inside(addr) {
            
            if operand.contains("byte ptr") {
                value = (self.peb.read_byte(addr) as u32) & 0x000000ff;

            } else if operand.contains("word ptr") {
                value = (self.peb.read_word(addr) as u32) & 0x0000ffff;
                
            } else if operand.contains("dword ptr") {
                value = self.peb.read_dword(addr);
    
            } else {
                panic!("weird precision: {}", operand);
            }

            return value;
        }

        panic!("weird case");
    }

    pub fn memory_write(&mut self, operand:&str, value:u32) {
        let addr:u32 = self.memory_operand_to_address(operand);

        // could be normal if executing code from stack
        if !self.code.inside(self.regs.eip) {
            panic!("eip outside code");
        }

        // could be normal using part of code as stack
        if !self.stack.inside(self.regs.esp) {
            panic!("esp outside stack");
        }

        if self.peb.inside(addr) {
            panic!("modifying peb!!");
        }

        // isnt normal, addr outside maps
        if !self.code.inside(addr) && !self.stack.inside(addr) {
            panic!("addr {} outside maps, operand: {}", addr, operand);
        }

        let value:u32 = 0;

        if self.code.inside(addr) {
            println!("writting on code 0x{:x} ebp: 0x{:x}", addr, self.regs.ebp);

            if operand.contains("byte ptr") {
                self.code.write_byte(addr, (value&0x000000ff) as u8);

            } else if operand.contains("word ptr") {
                self.code.write_word(addr, (value&0x0000ffff) as u16);
                
            } else if operand.contains("dword ptr") {
                self.code.write_dword(addr, value);
    
            } else {
                panic!("weird precision: {}", operand);
            }

            return;
        }

        if self.stack.inside(addr) {
            println!("writting on stack");
            if operand.contains("byte ptr") {
                self.stack.write_byte(addr, (value&0x000000ff) as u8);

            } else if operand.contains("word ptr") {
                self.stack.write_word(addr, (value&0x0000ffff) as u16);
                
            } else if operand.contains("dword ptr") {
                println!("writing on stack addr 0x{:x} the value 0x{:x}", addr, value);
                self.stack.write_dword(addr, value);
    
            } else {
                panic!("weird precision: {}", operand);
            }

            return;
        }

        panic!("weird case");
    }

    pub fn set_eip(&mut self, addr:u32, is_branch:bool) {
        if self.code.inside(addr) {
           self.regs.eip = addr; 
        } else if self.stack.inside(addr) {
            println!("/!\\ weird, changing eip to stack.");
            self.regs.eip = addr;
        } else {
            panic!("cannot redirect  eip to 0x{:x} is outisde maps", addr);
        }

        //TODO: lanzar memory scan self.code.scan() y self.stack.scan()
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
        } else {
            return u32::from_str_radix(operand, 16).unwrap();
        }
    }

    pub fn get_size(&self, operand:&str) -> u8 {
        if operand.contains("byte ptr") {
            return 8;

        } else if operand.contains("word ptr") {
            return 16;
            
        } else if operand.contains("dword ptr") {
            return 32;

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
        }

        panic!("weird precision: {}", operand);
    }


    /// FLAGS ///
    /// 
    /// overflow 0xffffffff + 1     
    /// carry    0x7fffffff + 1     o  0x80000000 - 1       o    0 - 1
    

    pub fn flags_add32(&mut self, value1:u32, value2:u32) -> u32 {
        let signed:i32 = value1 as i32 + value2 as i32;
        let unsigned:u64 = value1 as u64 + value2 as u64;

        self.flags.f_sf = signed < 0;
        self.flags.f_zf = signed == 0;
        self.flags.f_pf = (signed & 0xff) % 2 == 0;
        self.flags.f_of = (value1 as i32) > 0 && signed < 0;
        self.flags.f_cf = unsigned > 0xffffffff;

        return signed as u32;
    }

    pub fn flags_add16(&mut self, value1:u32, value2:u32) -> u32 {
        if value1 > 0xffff || value2 > 0xffff {
            panic!("flags_add16 with a bigger precision");
        }

        let signed:i16 = value1 as i16 + value2 as i16;
        let unsigned:u32 = value1 as u32 + value2 as u32;

        self.flags.f_sf = signed < 0;
        self.flags.f_zf = signed == 0;
        self.flags.f_pf = (signed & 0xff) % 2 == 0;
        self.flags.f_of = (value1 as i32) > 0 && signed < 0;
        self.flags.f_cf = unsigned > 0xffff;

        return signed as u32;
    }

    pub fn flags_add8(&mut self, value1:u32, value2:u32) -> u32 {
        if value1 > 0xff || value2 > 0xff {
            panic!("flags_add8 with a bigger precision");
        }

        let signed:i8 = value1 as i8 + value2 as i8;
        let unsigned:u16 = value1 as u16 + value2 as u16;

        self.flags.f_sf = signed < 0;
        self.flags.f_zf = signed == 0;
        self.flags.f_pf = signed % 2 == 0;
        self.flags.f_of = (value1 as i32) > 0 && signed < 0;
        self.flags.f_cf = unsigned > 0xff;

        return signed as u32;
    }

    pub fn flags_sub32(&mut self, value1:u32, value2:u32) -> u32 {
        let sr:i32 = value1 as i32 - value2 as i32;

        self.flags.f_zf = sr == 0;
        self.flags.f_sf = sr < 0;
        self.flags.f_pf = (sr & 0xff) % 2 == 0;
        self.flags.f_of = (value1 as i32) < 0 && sr >= 0;
        self.flags.f_cf = (value1 as i32) >= 0 && sr < 0;

        return sr as u32;
    }

    pub fn flags_sub16(&mut self, value1:u32, value2:u32) -> u32 {
        let sr:i16 = value1 as i16 - value2 as i16;

        self.flags.f_zf = sr == 0;
        self.flags.f_sf = sr < 0;
        self.flags.f_pf = (sr & 0xff) % 2 == 0;
        self.flags.f_of = (value1 as i16) < 0 && sr >= 0;
        self.flags.f_cf = (value1 as i16) >= 0 && sr < 0;

        return sr as u32;
    }

    pub fn flags_sub8(&mut self, value1:u32, value2:u32) -> u32 {
        let sr:i8 = value1 as i8 - value2 as i8;

        self.flags.f_zf = sr == 0;
        self.flags.f_sf = sr < 0;
        self.flags.f_pf = sr % 2 == 0;
        self.flags.f_of = (value1 as i8) < 0 && sr >= 0;
        self.flags.f_cf = (value1 as i8) >= 0 && sr < 0;

        return sr as u32;
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

        self.flags.f_zf = value == 0;

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

        self.flags.f_zf = value == 0;

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

        self.flags.f_zf = value == 0;

        return value - 1;
    }

    pub fn calc_flags(&mut self, final_value:u32) {
        self.flags.f_zf = final_value == 0;
        self.flags.f_sf = (final_value as i32) < 0;
        self.flags.f_pf = (final_value & 0xff) % 2 == 0;        
    }


    ///  RUN ENGINE ///

    pub fn run(&mut self) {
        println!(" ----- emulation -----");
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode32)
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build()
            .expect("Failed to create Capstone object");


        loop {

            let eip = self.regs.eip.clone();
            let block = self.code.read_from(eip);
            let insns = cs.disasm_all(block, eip as u64).expect("Failed to disassemble");
            

            for ins in insns.as_ref() {
                //TODO: use InsnDetail https://docs.rs/capstone/0.4.0/capstone/struct.InsnDetail.html
                //let detail: InsnDetail = cs.insn_detail(&ins).expect("Failed to get insn detail");
                //let arch_detail: ArchDetail = detail.arch_detail();
                //let ops = arch_detail.operands();
                let sz = ins.bytes().len();

                println!("{}", ins);
                //println!("{}  esp:0x{:x} ebp:0x{:x} top:0x{:x} bottom:0x{:x}", ins, self.regs.esp, self.regs.ebp, self.stack.get_base(), self.stack.get_bottom()); //, ins.bytes());
                


                // TODO: popal, popad, pushal, pushad

                match ins.mnemonic() {
                    Some("jmp") => {
                        let addr = self.get_inmediate(ins.op_str().unwrap());       
                        self.set_eip(addr, false);

                        break;
                    },

                    Some("call") => {

                        if sz == 3 {
                            let addr = self.memory_read(ins.op_str().unwrap());
                            self.stack_push(self.regs.eip + sz as u32); // push return address
                            self.set_eip(addr, false);
                            break; 
                        }

                        if sz == 5 {
                            let addr = self.get_inmediate(ins.op_str().unwrap());
                            self.stack_push(self.regs.eip + sz as u32); // push return address
                            self.set_eip(addr, false);
                            break;
                        }

                        println!("weird call");
                        return;
                    },

                    Some("push") => {
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

                            // push + inmediate
                            0x68 => {
                                let addr = self.get_inmediate(ins.op_str().unwrap());
                                self.stack_push(addr as u32);
                            },

                            // push + mem operation
                            _ => {
                                let value = self.memory_read(ins.op_str().unwrap());
                                self.stack_push(value);
                            }
                        }
                        //self.stack.print_dwords_from_to(self.regs.esp, self.regs.ebp);
                    },

                    Some("pop") => {
                        let opcode:u8 = ins.bytes()[0];

                        match opcode {
                            // pop + regs
                            0x58 => self.regs.eax = self.stack_pop(),
                            0x59 => self.regs.ecx = self.stack_pop(),
                            0x5a => self.regs.edx = self.stack_pop(),
                            0x5b => self.regs.ebx = self.stack_pop(),
                            0x5c => self.regs.esp = self.stack_pop(),
                            0x5d => self.regs.ebp = self.stack_pop(),
                            0x5e => self.regs.esi = self.stack_pop(),
                            0x5f => self.regs.edi = self.stack_pop(),

                            // pop + mem operation
                            _ => {
                                //let value = self.memory_read(ins.op_str().unwrap());
                                let value = self.stack_pop();
                                self.memory_write(ins.op_str().unwrap(), value);
                            },
                        }

                        //self.stack.print_dwords_from_to(self.regs.esp, self.regs.ebp);
                    },

                    Some("pushal") => {
                        let tmp_esp = self.regs.esp;
                        self.stack_push(self.regs.eax);
                        self.stack_push(self.regs.ecx);
                        self.stack_push(self.regs.edx);
                        self.stack_push(self.regs.ebx);
                        self.stack_push(tmp_esp);
                        self.stack_push(self.regs.ebp);
                        self.stack_push(self.regs.esi);
                        self.stack_push(self.regs.edi);
                        self.stack.print_dwords_from_to(self.regs.esp, self.regs.ebp);
                    },

                    Some("popal") => {
                        self.regs.edi = self.stack_pop();
                        self.regs.esi = self.stack_pop();
                        self.regs.ebp = self.stack_pop();
                        self.regs.esp += 4; // skip esp
                        self.regs.ebx = self.stack_pop();
                        self.regs.edx = self.stack_pop();
                        self.regs.ecx = self.stack_pop();
                        self.regs.eax = self.stack_pop();
                        self.stack.print_dwords_from_to(self.regs.esp, self.regs.ebp);
                    },

                    Some("ret") => {
                        
                        // what if there isnt operand in ret?
                        let mut arg = self.get_inmediate(ins.op_str().unwrap());

                        // apply stack compensation of ret operand

                        if arg % 4 != 0 {
                            panic!("weird ret argument!");
                        }

                        arg = arg / 4;

                        for _ in 0..arg {
                            self.stack_pop();
                        }

                        let ret_addr = self.stack_pop(); // return address
                        self.set_eip(ret_addr, false);
                        break;
                    },

                    Some("mov") => {
                        let parts:Vec<&str> = ins.op_str().unwrap().split(", ").collect();
                        
                        if parts[0].contains("[") {
                            if self.is_reg(parts[1]) {
                                // mov mem, reg
                                let value = self.regs.get_by_name(parts[1]);
                                self.memory_write(parts[0], value);
                                
                            } else {
                                // mov mem, inm
                                let inm = self.get_inmediate(parts[1]);
                                self.memory_write(parts[0], inm);
                            }

                        } else {

                            if parts[1].contains("[") {
                                // mov reg, mem 
                                let value = self.memory_read(parts[1]);
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
                        let parts:Vec<&str> = ins.op_str().unwrap().split(", ").collect();

                        if parts[0].contains("[") {
                            if self.is_reg(parts[1]) {
                                // mov mem, reg
                                let value1 = self.regs.get_by_name(parts[1]);
                                let value0 = self.memory_read(parts[0]);

                                self.memory_write(parts[0], value0 ^ value1);
                                
                            } else {
                                // mov mem, inm
                                let inm = self.get_inmediate(parts[1]);
                                let value0 = self.memory_read(parts[0]);
                                self.memory_write(parts[0], value0 ^ inm);
                            }

                        } else {

                            if parts[1].contains("[") {
                                // mov reg, mem 
                                let value1 = self.memory_read(parts[1]);
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
                        let ops = ins.op_str().unwrap();
                        let parts:Vec<&str> = ops.split(", ").collect();

                        if parts[0].contains("[") {
                            if self.is_reg(parts[1]) {
                                // mov mem, reg
                                let value1:u32 = self.regs.get_by_name(parts[1]);
                                let value0:u32 = self.memory_read(parts[0]);
                                let res:u32;
                                match self.get_size(parts[1]) {
                                    32 => res = self.flags_add32(value0, value1),
                                    16 => res = self.flags_add16(value0, value1),
                                    8  => res = self.flags_add8(value0, value1),
                                    _  => panic!("weird precision")
                                }
                                self.memory_write(parts[0], res); 
                                
                            } else {
                                // mov mem, inm
                                let inm = self.get_inmediate(parts[1]);
                                let value0 = self.memory_read(parts[0]);
                                let res:u32;
                                match self.get_size(parts[0]) {
                                    32 => res = self.flags_add32(value0, inm),
                                    16 => res = self.flags_add16(value0, inm),
                                    8  => res = self.flags_add8(value0, inm),
                                    _  => panic!("weird precision")
                                }
                                self.memory_write(parts[0], res);
                            }

                        } else {

                            if parts[1].contains("[") {
                                // mov reg, mem 
                                let value1 = self.memory_read(parts[1]);
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
                    
                    
                    Some("sub") => {
                        let op = ins.op_str().unwrap();
                        let parts:Vec<&str> = op.split(", ").collect();

                        if parts[0].contains("[") {
                            if self.is_reg(parts[1]) {
                                // mov mem, reg
                                let value1 = self.regs.get_by_name(parts[1]);
                                let value0 = self.memory_read(parts[0]);
                                let res:u32;
                                match self.get_size(op) {
                                    32 => res = self.flags_sub32(value0, value1),
                                    16 => res = self.flags_sub16(value0, value1),
                                    8  => res = self.flags_sub8(value0, value1),
                                    _  => panic!("weird precision")
                                }
                                self.memory_write(parts[0], res);
                                
                            } else {
                                // mov mem, inm
                                let inm = self.get_inmediate(parts[1]);
                                let value0 = self.memory_read(parts[0]);
                                let res:u32;
                                match self.get_size(op) {
                                    32 => res = self.flags_sub32(value0, inm),
                                    16 => res = self.flags_sub16(value0, inm),
                                    8  => res = self.flags_sub8(value0, inm),
                                    _  => panic!("weird precision")
                                }
                                self.memory_write(parts[0], res);
                            }

                        } else {

                            if parts[1].contains("[") {
                                // mov reg, mem 
                                let value1 = self.memory_read(parts[1]);
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
                            let value = self.memory_read(op);
                            let res:u32;

                            match self.get_size(op) {
                                32 => res = self.flags_inc32(value),
                                16 => res = self.flags_inc16(value),
                                8 =>  res = self.flags_inc8(value),
                                _ => res = 0,
                            }

                            self.memory_write(op, res);
                        }
                    },

                    Some("dec") => {
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
                            let value = self.memory_read(op);
                            let res:u32;

                            match self.get_size(op) {
                                32 => res = self.flags_dec32(value),
                                16 => res = self.flags_dec16(value),
                                8 =>  res = self.flags_dec8(value),
                                _ => res = 0,
                            }

                            self.memory_write(op, res);
                        }
                    },

                    // neg not and or ror rol  sar sal shr shl 
                    Some("neg") => {
                        let op = ins.op_str().unwrap();
                        if self.is_reg(op) {
                            let mut value = self.regs.get_by_name(op);
                            let mut signed:i32 = value as i32;
                            match self.get_size(op) {
                                32 => self.flags.f_of = value == 0x80000000,
                                16 => self.flags.f_of = value == 0x8000,
                                8 =>  self.flags.f_of = value == 0x80,
                                _ => panic!("weird precision")
                            }
                            signed = signed * -1;
                            value = signed as u32;
                            self.calc_flags(value);
                            self.flags.f_cf = true;
                            self.regs.set_by_name(op, value);
                            
                        } else {
                            let mut value = self.memory_read(op);
                            let mut signed:i32 = value as i32;
                            match self.get_size(op) {
                                32 => self.flags.f_of = value == 0x80000000,
                                16 => self.flags.f_of = value == 0x8000,
                                8 =>  self.flags.f_of = value == 0x80,
                                _ => panic!("weird precision")
                            }
                            signed = signed * -1;
                            value = signed as u32;
                            self.calc_flags(value);
                            self.flags.f_cf = true;
                            
                            self.memory_write(op, value);
                        }
                    },

                    Some("not") => { // dont alter flags
                        let op = ins.op_str().unwrap();
                        if self.is_reg(op) {
                            let mut value = self.regs.get_by_name(op);
                            let mut signed:i32 = value as i32;
                            signed = !signed;
                            value = signed as u32;
                            self.regs.set_by_name(op, value);
                        } else {
                            let mut value = self.memory_read(op);
                            let mut signed:i32 = value as i32;
                            signed = !signed;
                            value = signed as u32;
                            self.memory_write(op, value);
                        }
                    },

                    Some("and") => { // TODO: how to trigger overflow and carry with and
                        let parts:Vec<&str> = ins.op_str().unwrap().split(", ").collect();

                        if parts[0].contains("[") {
                            if self.is_reg(parts[1]) {
                                // and mem, reg
                                let value1 = self.regs.get_by_name(parts[1]);
                                let value0 = self.memory_read(parts[0]);
                                let res = value0 & value1;
                                self.calc_flags(res);
                                self.memory_write(parts[0], res);
                                
                            } else {
                                // and mem, inm
                                let inm = self.get_inmediate(parts[1]);
                                let value0 = self.memory_read(parts[0]);
                                let res = value0 & inm;
                                self.calc_flags(res);
                                self.memory_write(parts[0], res);
                            }

                        } else {

                            if parts[1].contains("[") {
                                // and reg, mem 
                                let value1 = self.memory_read(parts[1]);
                                let value0 = self.regs.get_by_name(parts[0]);
                                let res = value0 & value1;
                                self.calc_flags(res);
                                self.regs.set_by_name(parts[0], res);

                            } else if self.is_reg(parts[1]) {
                                // and reg, reg
                                let value1 = self.regs.get_by_name(parts[1]);
                                let value0 = self.regs.get_by_name(parts[0]);
                                let res = value0 & value1;
                                self.calc_flags(res);
                                self.regs.set_by_name(parts[0], res);
                                
                            } else {
                                // and reg, inm
                                let inm = self.get_inmediate(parts[1]);
                                let value0 = self.regs.get_by_name(parts[0]);
                                let res = value0 & inm;
                                self.calc_flags(res);
                                self.regs.set_by_name(parts[0], res);
                            }
                        }

                    },

                    Some("or") => {
                        let parts:Vec<&str> = ins.op_str().unwrap().split(", ").collect();

                        if parts[0].contains("[") {
                            if self.is_reg(parts[1]) {
                                // or mem, reg
                                let value1 = self.regs.get_by_name(parts[1]);
                                let value0 = self.memory_read(parts[0]);
                                let res = value0 | value1;
                                self.calc_flags(res);
                                self.memory_write(parts[0], res);
                                
                            } else {
                                // or mem, inm
                                let inm = self.get_inmediate(parts[1]);
                                let value0 = self.memory_read(parts[0]);
                                let res = value0 | inm;
                                self.calc_flags(res);
                                self.memory_write(parts[0], res);
                            }

                        } else {

                            if parts[1].contains("[") {
                                // or reg, mem 
                                let value1 = self.memory_read(parts[1]);
                                let value0 = self.regs.get_by_name(parts[0]);
                                let res = value0 | value1;
                                self.calc_flags(res);
                                self.regs.set_by_name(parts[0], res);

                            } else if self.is_reg(parts[1]) {
                                // or reg, reg
                                let value1 = self.regs.get_by_name(parts[1]);
                                let value0 = self.regs.get_by_name(parts[0]);
                                let res = value0 | value1;
                                self.calc_flags(res);
                                self.regs.set_by_name(parts[0], res);
                                
                            } else {
                                // or reg, inm
                                let inm = self.get_inmediate(parts[1]);
                                let value0 = self.regs.get_by_name(parts[0]);
                                let res = value0 | inm;
                                self.calc_flags(res);
                                self.regs.set_by_name(parts[0], res);
                            }
                        }
                    },

                    Some("sal") => {
                        let op = ins.op_str().unwrap();
                        //let twoparams = op.contains(", ");
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
                                
                                    for _ in 0..value1 {
                                        unsigned64 *= 2;
                                    }

                                    match self.get_size(parts[0]) {
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

                                    self.calc_flags(res);
                                    self.regs.set_by_name(parts[0], res);


                                } else  {
                                    // sal reg, imm
                                    let value0:u32 = self.regs.get_by_name(parts[0]);
                                    let value1:u32 = self.get_inmediate(parts[1]);
                                    let mut unsigned64:u64 = value0 as u64;
                                    let res:u32;
                                
                                    for _ in 0..value1 {
                                        unsigned64 *= 2;
                                    }

                                    match self.get_size(parts[0]) {
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

                                    self.calc_flags(res);
                                    self.regs.set_by_name(parts[0], res);
                                }


                            } else {
                                // mem
                                if self.is_reg(parts[1]) {
                                    // sal mem, reg
                                    let value0:u32 = self.memory_read(parts[0]);
                                    let value1:u32 = self.regs.get_by_name(parts[1]);

                                    let mut unsigned64:u64 = value0 as u64;
                                    let res:u32;
                                
                                    for _ in 0..value1 {
                                        unsigned64 *= 2;
                                    }

                                    match self.get_size(parts[0]) {
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

                                    self.calc_flags(res);
                                    self.memory_write(parts[0], res);

                                } else {
                                    // sal mem, imm
                                    let value0:u32 = self.memory_read(parts[0]);
                                    let value1:u32 = self.get_inmediate(parts[1]);
                                    let mut unsigned64:u64 = value0 as u64;
                                    let res:u32;
                                
                                    for _ in 0..value1 {
                                        unsigned64 *= 2;
                                    }

                                    match self.get_size(parts[0]) {
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

                                    self.calc_flags(res);
                                    self.memory_write(parts[0], res);
                                }

                            }


                        } else { // one param
                            if self.is_reg(op) { // reg
                                let value:i32 = self.regs.get_by_name(op) as i32;
                                let unsigned64:u64;
                                let res:u32;

                                unsigned64 = (value as u64) * 2;

                                match self.get_size(op) {
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

                                self.calc_flags(res);
                                self.regs.set_by_name(op, res);


                            } else { // mem 
                                let value:i32 = self.memory_read(op) as i32;
                                let unsigned64:u64;
                                let res:u32;

                                unsigned64 = (value as u64) * 2;

                                match self.get_size(op) {
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

                                self.calc_flags(res);
                                self.memory_write(op, res);
                            }
                        }
                    },

                    Some("sar") => {

                    },

                    Some("shr") => {

                    },

                    Some("shl") => {

                    },

                    Some("ror") => {

                    },

                    Some("rol") => {

                    },

                    Some("cmp") => {

                    },

                    Some("test") => {

                    },


                    // mul div idiv

                    //branches: https://web.itu.edu.tr/kesgin/mul06/intel/instr/jxx.html
                    //          https://c9x.me/x86/html/file_module_x86_id_146.html
                    //          http://unixwiz.net/techtips/x86-jumps.html <---aqui


                    //TODO: test syenter / int80
                    Some("int3") => {
                        
                    },

                    Some("nop") => {

                    },

                    Some(&_) =>  { 
                        
                    },
                    None => println!("unknon instruction"),
                }

                self.regs.eip += sz as u32;

            }
        }   

        

    }

}