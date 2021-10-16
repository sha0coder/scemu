extern crate capstone;

mod flags; 
mod eflags;
mod mem32;
mod stack32;
mod regs32;


use flags::Flags;
use eflags::Eflags;
use mem32::Mem32;
use stack32::Stack32;
use regs32::Regs32;

use std::mem;
use std::fs;
use std::fs::File;
use std::io::Read;
use capstone::prelude::*;

const MAX_CODE:usize = 102400;


pub struct Emu32 {
    stack: Stack32,
    mem: Mem32,
    regs: Regs32,
    flags: Flags,
    eflags: Eflags,
    code: [u8;MAX_CODE],
    cs: Capstone
}

impl Emu32 {
    pub fn new() -> Emu32 {
        Emu32{
            stack: Stack32::new(),
            mem: Mem32::new(),
            regs: Regs32::new(),
            flags: Flags::new(),
            eflags: Eflags::new(),
            code: [0;MAX_CODE],
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
    }

    pub fn load_code(&mut self, filename: &String) {
        let mut f = File::open(&filename).expect("no file found");
        let metadata = fs::metadata(&filename).expect("unable to read metadata");
        //let mut buffer = vec![0; metadata.len() as usize];
        f.read(&mut self.code).expect("buffer overflow");
    }

    pub fn run(&mut self) {
        while(true) {
            let mut insns = self.cs.disasm_all(&self.code.get(self.regs.eip as usize..MAX_CODE).unwrap(), self.regs.eip as u64).expect("Failed to disassemble");
            
            for ins in insns.as_ref() {
                println!("{}", ins);

                let detail: InsnDetail = self.cs.insn_detail(&ins).expect("Failed to get insn detail");
                let arch_detail: ArchDetail = detail.arch_detail();
                let ops = arch_detail.operands();

                match ins.mnemonic() {
                    Some("jmp") => {
     
                        let addr:usize = usize::from_str_radix(ins.op_str().unwrap().trim_start_matches("0x"),16).unwrap();
                        self.regs.eip = addr as u32;
                        break;
                    },

                    Some("call") => {
                        
                        let sz = ins.bytes().len(); // sz must be 5 

                        if sz == 3 {
                            println!("call de 3 bytes: {:?}", detail.regs_read()[0]);

                            match detail.regs_read()[0] {
                                RegId(30) ==> { // ebp
                                    println!("")
                                }
                            }

                            return;
                        }

                        if sz == 5 {
                            println!("instruciton sz of call: {}", sz as u32);
                            self.stack.push(self.regs.eip + sz as u32); // push return address 
                            println!("ret addr: {:x}", self.regs.eip + sz as u32);
                            self.regs.esp -= 4;
                            let addr:usize = usize::from_str_radix(ins.op_str().unwrap().trim_start_matches("0x"),16).unwrap();
                            self.regs.eip = addr as u32;
                            break;
                        }
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
                            self.stack.pop();
                        }*/

                        self.regs.eip = self.stack.pop(); // return address
                        break;
                    }



                    Some(&_) =>  { 
                        let sz = ins.bytes().len();
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