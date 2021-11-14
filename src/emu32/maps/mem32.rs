/*
    Little endian generic memory
*/

use std::fs::File;
use std::io::Read;

const MAX_MEM:usize = 0x000f0000;

pub struct Mem32 {
    base_addr: u32,
    bottom_addr: u32,
    pub mem: Box<[u8]>, //:[u8;MAX_MEM],
}

impl Mem32 {
    pub fn new() -> Mem32 {
        Mem32 {
            base_addr: 0,
            bottom_addr: MAX_MEM as u32,
            mem: Box::new([0;MAX_MEM]),
        }
    }

    pub fn size(&self) -> usize {
        return MAX_MEM;
    }

    pub fn get_base(&self) -> u32 {
        return self.base_addr;
    }

    pub fn get_bottom(&self) -> u32 {
        return self.bottom_addr;
    }

    pub fn inside(&self, addr:u32) -> bool {
        if addr >= self.base_addr && addr <= self.bottom_addr {
            return true;
        }
        return false;
    }

    pub fn set_base(&mut self, base_addr:u32) {
        self.base_addr = base_addr;
        self.bottom_addr = base_addr + MAX_MEM as u32;
    }

    pub fn set_bottom(&mut self, bottom_addr:u32) {
        self.bottom_addr = bottom_addr;
    }

    pub fn set_size(&mut self, size:u32) {
        self.bottom_addr = self.base_addr + size;
    }

    pub fn read_from(&self, addr:u32) -> &[u8] {
        let idx = (addr - self.base_addr) as usize;
        let sz = (self.bottom_addr - self.base_addr) as usize;
        self.mem.get(idx..sz).unwrap()
    }

    pub fn read_byte(&self, addr:u32) -> u8 {
        let idx = (addr - self.base_addr) as usize;
        self.mem[idx]
    }

    pub fn read_word(&self, addr:u32) -> u16 {
        let idx = (addr - self.base_addr) as usize;
        ((self.mem[idx] as u16)  << 0) + 
        ((self.mem[idx+1] as u16) << 8)
    }

    pub fn read_dword(&self, addr:u32) -> u32 {
        let idx = (addr - self.base_addr) as usize;
        ((self.mem[idx] as u32)   <<  0) +
        ((self.mem[idx+1] as u32) <<  8) +
        ((self.mem[idx+2] as u32) << 16) +
        ((self.mem[idx+3] as u32) << 24)
    }

    pub fn write_byte(&mut self, addr:u32, value:u8) {
        let idx = (addr - self.base_addr) as usize;
        self.mem[idx] = value;
    }

    pub fn write_word(&mut self, addr:u32, value:u16) {
        let idx = (addr - self.base_addr) as usize;
        self.mem[idx]   = (value & 0x00ff) as u8;
        self.mem[idx+1] = ((value & 0xff00) >> 8) as u8;
    }

    pub fn write_dword(&mut self, addr:u32, value:u32) {
        let idx = (addr - self.base_addr) as usize;
        self.mem[idx]   = (value & 0x000000ff) as u8;
        self.mem[idx+1] = ((value & 0x0000ff00) >> 8) as u8;
        self.mem[idx+2] = ((value & 0x00ff0000) >> 16) as u8;
        self.mem[idx+3] = ((value & 0xff000000) >> 24) as u8;
    }

    pub fn print_bytes(&self) {
        println!("---mem---");
        for b in self.mem.iter() {
            print!("{}", b);
        }
        println!("---");
    }

    pub fn print_dwords(&self) {
        self.print_dwords_from_to(self.get_base(), self.get_bottom());
    }

    pub fn print_dwords_from_to(&self, from:u32, to:u32) {
        println!("---mem---");
        for addr in (from..to).step_by(4) {
            println!("0x{:x}", self.read_dword(addr))
        }

        println!("---");
    }

    pub fn load(&mut self, filename: &str) {
        let mut f = File::open(&filename).expect("no file found");
        self.bottom_addr = self.base_addr + f.metadata().unwrap().len() as u32;
        f.read(&mut self.mem).expect("buffer overflow");
    }


}

