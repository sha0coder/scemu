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
    cs: Capstone
}

impl Emu32 {
    pub fn new() -> Emu32 {
        Emu32{
            regs: Regs32::new(),
            flags: Flags::new(),
            eflags: Eflags::new(),
            code: Mem32::new(),
            stack: Mem32::new(),
            cs: Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode32)
                .syntax(arch::x86::ArchSyntax::Intel)
                .detail(true)
                .build()
                .expect("Failed to create Capstone object")
        }
    }

    pub fn init(&mut self) {
        self.regs.clear();
        self.regs.esp = 0x00100000;
        self.regs.ebp = 0x00100100;
        self.regs.eip = 0;

        self.code.set_base(self.regs.eip);
        self.stack.set_base(self.regs.esp - ((self.stack.size() as u32) / 2));
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


    /*
    pub fn memory_read(&self, addr:u32, sz:usize) -> u32 {
        let addr2 = addr as usize;

        if addr2 < MAX_CODE {
            let data:u32 = as_u32_le(self.code.get(addr2..addr2+sz).unwrap());
            return data;
        }

        if addr >= self.regs.esp && addr <= (self.regs.esp+(self.stack.size()*4)) {
            let idx = (addr - self.regs.esp) as usize;
            return self.stack.fetch(idx);
        }

        self.mem.


        return 0;
    }*/

    pub fn run(&mut self) {
        while(true) {
            let mut insns = self.cs.disasm_all(&self.code.read_from(self.regs.eip), &self.regs.eip as u64).expect("Failed to disassemble");
            
            for ins in insns.as_ref() {
                println!("{}", ins);

                let detail: InsnDetail = self.cs.insn_detail(&ins).expect("Failed to get insn detail");
                let arch_detail: ArchDetail = detail.arch_detail();
                let ops = arch_detail.operands();
                let sz = ins.bytes().len();
                

                match ins.mnemonic() {
                    Some("jmp") => {
                        let addr:usize = usize::from_str_radix(ins.op_str().unwrap().trim_start_matches("0x"),16).unwrap();       
                        self.regs.eip = addr as u32;
                        break;
                    },

                    Some("call") => {
                        

                        if sz == 3 {
                            println!("call de 3 bytes: {:?}", detail.regs_read()[0]);
                            let sum = ins.op_str().unwrap().contains(" + ");
                            let sub = ins.op_str().unwrap().contains(" - ");

                            if detail.regs_read()[0] == RegId(30) { // ebp
                                let op_num = ins.bytes()[2] as u32;

                                let ret_addr:u32;

                                if sum {
                                    ret_addr = self.stack.read_dword(self.regs.ebp + op_num);
                                } else if sub {
                                    ret_addr = self.stack.read_dword(self.regs.ebp - op_num);
                                } else {
                                    println!("weird case !!");
                                    return;
                                }

                                self.stack_push(self.regs.eip + sz as u32); // push return address
                                self.regs.eip = ret_addr;
                            }

                            return;
                        }

                        if sz == 5 {
                            println!("instruciton sz of call: {}", sz as u32);
                            let addr:usize = usize::from_str_radix(ins.op_str().unwrap().trim_start_matches("0x"),16).unwrap();

                            self.stack_push(self.regs.eip + sz as u32); // push return address
                            self.regs.eip = addr as u32;
                            break;
                        }
                    },

                    Some("push") => {

                        self.regs.eip += sz as u32;
                    },

                    Some("ret") => {
                        
                        let mut arg = usize::from_str_radix(ins.op_str().unwrap(), 16).unwrap();

                        /*
                        self.regs.esp -= arg as u32;

                        if arg % 4 != 0 {
                            println!("weird ret argument!");
                            return;
                        }

                        arg = arg / 4;

                        for i in 0..arg {
                            self.stack_pop();
                        }*/

                        self.regs.eip = self.stack_pop(); // return address
                        break;
                    }



                    Some(&_) =>  { 
                        self.regs.eip += sz as u32;
                    },
                    None => println!("unknon instruction"),
                }



                /*
                if ins.mnemonic() == Some("jmp") {
                    println!("a jump");
                }*/
                

            }
        }   

    }

}