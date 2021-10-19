extern crate capstone;

mod flags; 
mod eflags;
mod mem32;
mod regs32;


use flags::Flags;
use eflags::Eflags;
use mem32::Mem32;
use regs32::Regs32;

use std::mem;
use std::fs;
use std::fs::File;
use std::io::Read;
use capstone::prelude::*;
use capstone::arch::x86::X86Operand;




pub struct Emu32 {
    regs: Regs32,
    flags: Flags,
    eflags: Eflags,
    code: Mem32,
    stack: Mem32,
    teb: Mem32,
}

impl Emu32 {
    pub fn new() -> Emu32 {
        Emu32{
            regs: Regs32::new(),
            flags: Flags::new(),
            eflags: Eflags::new(),
            code: Mem32::new(),
            stack: Mem32::new(),
            teb: Mem32::new(),
        }
    }

    pub fn init(&mut self) {
        self.regs.clear();
        self.regs.esp = 0x00100000;
        self.regs.ebp = 0x00100100;
        self.regs.eip = 0;

        self.code.set_base(self.regs.eip);
        self.stack.set_base(self.regs.esp - ((self.stack.size() as u32) / 2));
        self.teb.set_base(0x00200000);
    }

    pub fn load_code(&mut self, filename: &String) {
        let mut f = File::open(&filename).expect("no file found");
        let metadata = fs::metadata(&filename).expect("unable to read metadata");
        //let mut buffer = vec![0; metadata.len() as usize];
        f.read(&mut self.code.mem).expect("buffer overflow");
    }

    pub fn stack_push(&mut self, value:u32) {
        self.stack.write_dword(self.regs.esp, value);
        self.regs.esp -= 4;
    }

    pub fn stack_pop(&mut self) -> u32 {
        let value = self.stack.read_dword(self.regs.esp);
        self.regs.esp += 4;
        return value;
    }

    pub fn memory_operand_to_address(&self, operand:&str) -> u32 {
        let spl:Vec<&str> = operand.split("[").collect::<Vec<&str>>()[1].split("]").collect::<Vec<&str>>()[0].split(" ").collect();

        if operand.contains("fs:[") {
            let inm = self.get_inmediate(spl[0]);
            println!("FS ACCESS TO 0x{:x}", inm);

            if inm == 0x30 { // TEB
                return self.teb.get_base();
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

            let reg_val = self.regs.get_by_name(reg);
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
    
    pub fn memory_read(&self, operand:&str) -> u32 {
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
            panic!("esp outside stack");
        }

        // isnt normal, addr outside maps
        if !self.code.inside(addr) && !self.stack.inside(addr) && !self.teb.inside(addr) {
            panic!("addr 0x{:x} outside maps, operand: {}", addr, operand);
        }

        let mut value:u32 = 0;

        if self.code.inside(addr) {

            if operand.contains("byte ptr") {
                value = (self.code.read_byte(addr) as u32) & 0x000000ff;

            } else if operand.contains("word dptr") {
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

            } else if operand.contains("word dptr") {
                value = (self.stack.read_word(addr) as u32) & 0x0000ffff;
                
            } else if operand.contains("dword ptr") {
                value = self.stack.read_dword(addr);
    
            } else {
                panic!("weird precision: {}", operand);
            }

            return value;
        }

        if self.teb.inside(addr) {
            
            if operand.contains("byte ptr") {
                value = (self.teb.read_byte(addr) as u32) & 0x000000ff;

            } else if operand.contains("word dptr") {
                value = (self.teb.read_word(addr) as u32) & 0x0000ffff;
                
            } else if operand.contains("dword ptr") {
                value = self.teb.read_dword(addr);
    
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

        if self.teb.inside(addr) {
            panic!("modifying teb!!");
        }

        // isnt normal, addr outside maps
        if !self.code.inside(addr) && !self.stack.inside(addr) {
            panic!("addr {} outside maps, operand: {}", addr, operand);
        }

        let mut value:u32 = 0;

        if self.code.inside(addr) {

            if operand.contains("byte ptr") {
                self.code.write_byte(addr, (value&0x000000ff) as u8);

            } else if operand.contains("word dptr") {
                self.code.write_word(addr, (value&0x0000ffff) as u16);
                
            } else if operand.contains("dword ptr") {
                self.code.write_dword(addr, value);
    
            } else {
                panic!("weird precision: {}", operand);
            }

            return;
        }

        if self.stack.inside(addr) {

            if operand.contains("byte ptr") {
                self.stack.write_byte(addr, (value&0x000000ff) as u8);

            } else if operand.contains("word dptr") {
                self.stack.write_word(addr, (value&0x0000ffff) as u16);
                
            } else if operand.contains("dword ptr") {
                self.stack.write_dword(addr, value);
    
            } else {
                panic!("weird precision: {}", operand);
            }

            return;
        }

        panic!("weird case");
    }

    pub fn set_eip(&mut self, addr:u32) {
        if self.code.inside(addr) {
           self.regs.eip = addr; 
        } else if self.stack.inside(addr) {
            println!("/!\\ weird, changing eip to stack.");
            self.regs.eip = addr;
        } else {
            panic!("cannot redirect  eip to 0x{:x} is outisde maps", addr);
        }
    }

    pub fn is_reg(&self, operand:&str) -> bool {
        match operand {
            "eax"|"ebx"|"ecx"|"edx"|"esi"|"edi"|"esp"|"ebp"|"eip"|"ax"|"bx"|"cx"|"dx"|"si"|"di"|"al"|"ah"|"bl"|"bh"|"cl"|"ch"|"dl"|"dh" => return true,
            &_ => return false,
        }
        return false;
    }

    pub fn get_inmediate(&self, operand:&str) -> u32 {
        if operand.contains("0x") {
            return u32::from_str_radix(operand.get(2..).unwrap(), 16).unwrap();
        } else {
            return u32::from_str_radix(operand, 16).unwrap();
        }
    }


    pub fn run(&mut self) {
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode32)
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build()
            .expect("Failed to create Capstone object");


        loop {

            let mut eip = self.regs.eip.clone();
            let block = self.code.read_from(eip);
            let insns = cs.disasm_all(block, eip as u64).expect("Failed to disassemble");
            

            for ins in insns.as_ref() {
                
                //TODO: use InsnDetail https://docs.rs/capstone/0.4.0/capstone/struct.InsnDetail.html
                let detail: InsnDetail = cs.insn_detail(&ins).expect("Failed to get insn detail");
                let arch_detail: ArchDetail = detail.arch_detail();
                let ops = arch_detail.operands();
                let sz = ins.bytes().len();

                println!("{} bytes:{:?} operands:'{}'", ins, ins.bytes(), ins.op_str().unwrap());
                


                // TODO: popal, popad, pushal, pushad

                match ins.mnemonic() {
                    Some("jmp") => {
                        let addr = self.get_inmediate(ins.op_str().unwrap());       
                        self.set_eip(addr);

                        break;
                    },

                    Some("call") => {

                        if sz == 3 {
                            println!("call de 3 bytes: {:?}", detail.regs_read()[0]);
                            let ret_addr = self.memory_read(ins.op_str().unwrap());
                            self.stack_push(self.regs.eip.clone() + sz as u32); // push return address
                            self.set_eip(ret_addr);
                            println!("return address: {}", ret_addr);
                            return; //TODO: change this to break  to follow the flow
                        }

                        if sz == 5 {
                            println!("instruciton sz of call: {}", sz as u32);
                            let addr = self.get_inmediate(ins.op_str().unwrap());

                            self.stack_push(self.regs.eip + sz as u32); // push return address
                            self.set_eip(addr as u32);
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
                        self.stack.print_dwords_from_to(self.regs.esp, self.regs.ebp);
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

                        self.stack.print_dwords_from_to(self.regs.esp, self.regs.ebp);
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
                    },

                    Some("ret") => {
                        
                        // what if there isnt operand in ret?
                        let mut arg = self.get_inmediate(ins.op_str().unwrap());

                        // apply stack compensation of ret operand

                        if arg % 4 != 0 {
                            panic!("weird ret argument!");
                            return;
                        }

                        arg = arg / 4;

                        for i in 0..arg {
                            self.stack_pop();
                        }

                        let mut ret_addr = self.stack_pop(); // return address
                        self.set_eip(ret_addr);
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
                                println!("reg '{}' '{}' new value: 0x{:x}", parts[0], parts[1], value);

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



                    Some(&_) =>  { 
                        
                    },
                    None => println!("unknon instruction"),
                }

                self.regs.eip += sz as u32;

            }
        }   

        

    }

}