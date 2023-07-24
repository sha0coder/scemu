/*
    Little endian generic any bits memory
*/

use std::io::BufReader;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use md5;

pub struct Mem32 {
    base_addr: u32,
    bottom_addr: u32,
    pub mem: Vec<u8>, 
}

impl Mem32 {
    pub fn new() -> Mem32 {
        Mem32 {
            base_addr: 0,
            bottom_addr: 0,
            mem: Vec::new(),
        }
    }

    pub fn alloc(&mut self, amount:usize) {
        self.mem = vec![0; amount];
    }

    pub fn size(&self) -> usize {
        self.mem.len()
    }

    pub fn get_base(&self) -> u32 {
        self.base_addr
    }

    pub fn get_bottom(&self) -> u32 {
        self.bottom_addr
    }

    pub fn inside(&self, addr:u32) -> bool {
        if addr >= self.base_addr && addr < self.bottom_addr {
            return true;
        }
        false
    }

    pub fn set_base(&mut self, base_addr:u32) {
        self.base_addr = base_addr;
        self.bottom_addr = base_addr;
    }

    pub fn set_bottom(&mut self, bottom_addr:u32) {
        self.bottom_addr = bottom_addr;
        let size = self.bottom_addr - self.base_addr;
        self.alloc(size as usize);
    }

    pub fn set_size(&mut self, size:u32) {
        self.bottom_addr = self.base_addr + size;
        self.alloc(size as usize);
    }

    pub fn read_from(&self, addr:u32) -> &[u8] {
        let idx = (addr - self.base_addr) as usize;
        let max_sz = (self.bottom_addr - self.base_addr) as usize;
        /*
        let mut sz = idx + 5;
        if sz > max_sz {
            sz = max_sz;
        }*/
        return self.mem.get(idx..max_sz).unwrap();
    }

    pub fn read_bytes(&self, addr:u32, sz:usize) -> &[u8] {
        let idx = (addr - self.base_addr) as usize;
        let sz2 = idx as usize + sz;
        if sz2 > self.mem.len() {
            return &[0;0];
        }
        return self.mem.get(idx..sz2).unwrap();
    }

    pub fn read_byte(&self, addr:u32) -> u8 {

        assert!(self.inside(addr));

        let idx = (addr - self.base_addr) as usize;
        if idx < self.mem.len() {
            self.mem[idx]
        } else {
            panic!("reading at 0x{:x}", addr);
        }
    }

    pub fn read_word(&self, addr:u32) -> u16 {
        let idx = (addr - self.base_addr) as usize;
        (self.mem[idx] as u16)   + 
        ((self.mem[idx+1] as u16) << 8)
    }

    pub fn read_dword(&self, addr:u32) -> u32 {
        let idx = (addr - self.base_addr) as usize;
        (self.mem[idx] as u32)   +
        ((self.mem[idx+1] as u32) <<  8) +
        ((self.mem[idx+2] as u32) << 16) +
        ((self.mem[idx+3] as u32) << 24)
    }


    pub fn read_qword(&self, addr:u32) -> u64 {
        let idx = (addr - self.base_addr) as usize;
        let mut r:u64 = 0;

        for i in 0..8 {
            r += (self.mem[idx+i] as u64) << (8*i);
        }

        r
    }

    pub fn write_qword(&mut self, addr:u32, value:u64) {
        let idx = (addr - self.base_addr) as usize;
        
        for i in 0..8 {
            self.mem[idx+i] = (value & (0xff<<i)) as u8;
        }
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
        //println!("write dword addr: 0x{:x}  base_addr: 0x{:x}  value: {} ", addr, self.base_addr, value);
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

    pub fn md5(&self) -> md5::Digest {
        md5::compute(&self.mem)
    }

    pub fn load(&mut self, filename: &str) -> bool {
        let f = match File::open(&filename) {
            Ok(f) => f,
            Err(_) => {  return false; }
        };
        let len = f.metadata().unwrap().len() as usize;
        self.bottom_addr = self.base_addr + (len as u32);
        //self.alloc(len);
        let mut reader = BufReader::new(&f);
        reader.read_to_end(&mut self.mem).expect("cannot load map file");

        f.sync_all(); // thanks Alberto Segura
        true
    }

    pub fn save(&self, addr:u32, size:usize, filename:String) {
        let idx = (addr - self.base_addr) as usize;
        let sz2 = idx as usize + size;
        if sz2 > self.mem.len() {
            println!("size too big");
            return;
        }

        let mut f = match File::create(filename) {
            Ok(f) => f,
            Err(e) => {
                println!("cannot create the file {}", e);
                return;
            }
        };

        let blob = self.mem.get(idx..sz2).unwrap();

        match f.write_all(blob) {
            Ok(_) => println!("saved."),
            Err(_) => println!("couldn't save the file"),
        }

        f.sync_all().unwrap();
    }


}

