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

const max_code:usize = 102400;


pub struct Emu32 {
    stack: Stack32,
    mem: Mem32,
    regs: Regs32,
    flags: Flags,
    eflags: Eflags,
    code: [u8;max_code],
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
            code: [0;max_code],
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
    }

    pub fn load_code(&mut self, filename: &String) {
        let mut f = File::open(&filename).expect("no file found");
        let metadata = fs::metadata(&filename).expect("unable to read metadata");
        //let mut buffer = vec![0; metadata.len() as usize];
        f.read(&mut self.code).expect("buffer overflow");
    }

    pub fn run(&self) {
        let mut insns = self.cs.disasm_all(&self.code, 0x0).expect("Failed to disassemble");
        
        for ins in insns.as_ref() {
            println!("{}", ins);

            let detail: InsnDetail = self.cs.insn_detail(&ins).expect("Failed to get insn detail");
            let arch_detail: ArchDetail = detail.arch_detail();
            let ops = arch_detail.operands();

            //println!("{:?}", ins.id());

            match ins.mnemonic() {
                Some("jmp") => {
                    
                    let addr:usize = usize::from_str_radix(ins.op_str().unwrap().trim_start_matches("0x"),16).unwrap();
                    println!("a jump to {}", addr);
            
                    insns = self.cs.disasm_all(self.code.get(addr..102400).unwrap(), 0x0).expect("Failed to disassemble");

                },
                Some(&_) => println!("non implemented"),
                None => println!("unknon instruction"),
            }



            /*
            if ins.mnemonic() == Some("jmp") {
                println!("a jump");
            }*/
            

        }

    }

}