/*
    Little endian 64 bits and inferior bits memory.
*/

use md5;
use bitcode::{Decode, Encode};
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::io::Read;
use std::io::SeekFrom;
use std::io::Write;

#[derive(Clone, Encode, Decode)]
pub struct Mem64 {
    mem_name: String,
    base_addr: u64,
    bottom_addr: u64,
    pub mem: Vec<u8>,
}

impl Default for Mem64 {
    fn default() -> Self {
        Self::new()
    }
}

impl Mem64 {
    pub fn new() -> Mem64 {
        Mem64 {
            mem_name: "".to_string(),
            base_addr: 0,
            bottom_addr: 0,
            mem: Vec::new(),
        }
    }

    pub fn get_name(&self) -> String {
        self.mem_name.clone()
    }

    pub fn set_name(&mut self, name: &str) {
        self.mem_name = name.to_string();
    }

    pub fn get_mem(&self) -> Vec<u8> {
        self.mem.clone()
    }

    pub fn alloc(&mut self, amount: usize) {
        self.mem = vec![0; amount];
    }

    pub fn extend(&mut self, amount: usize) {
        for i in 0..amount {
            self.mem.push(0);
        }
        self.bottom_addr += amount as u64;
    }

    pub fn size(&self) -> usize {
        self.mem.len()
    }

    pub fn get_base(&self) -> u64 {
        self.base_addr
    }

    pub fn get_bottom(&self) -> u64 {
        self.bottom_addr
    }

    pub fn memcpy(&mut self, ptr: &[u8], sz: usize) {
        if self.mem.len() < sz {
            panic!("memcpy: {} < {}", self.mem.len(), sz);
        }
        self.mem[..sz].copy_from_slice(&ptr[..sz]);
    }

    pub fn inside(&self, addr: u64) -> bool {
        if addr >= self.base_addr && addr < self.bottom_addr {
            return true;
        }
        false
    }

    pub fn set_base(&mut self, base_addr: u64) {
        self.base_addr = base_addr;
        self.bottom_addr = base_addr;
    }

    pub fn update_base(&mut self, base_addr: u64) {
        self.base_addr = base_addr;
    }

    pub fn set_bottom(&mut self, bottom_addr: u64) {
        self.bottom_addr = bottom_addr;
        let size = self.bottom_addr - self.base_addr;
        self.alloc(size as usize);
    }

    pub fn update_bottom(&mut self, bottom_addr: u64) {
        self.bottom_addr = bottom_addr;
    }

    pub fn set_size(&mut self, size: u64) {
        self.bottom_addr = self.base_addr + size;
        self.alloc(size as usize);
    }

    pub fn read_from(&self, addr: u64) -> &[u8] {
        let idx = (addr - self.base_addr) as usize;
        let max_sz = (self.bottom_addr - self.base_addr) as usize;
        /*
        let mut sz = idx + 5;
        if sz > max_sz {
            sz = max_sz;
        }*/
        self.mem.get(idx..max_sz).unwrap()
    }

    pub fn read_bytes(&self, addr: u64, sz: usize) -> &[u8] {
        let idx = (addr - self.base_addr) as usize;
        let sz2 = idx + sz;
        if sz2 > self.mem.len() {
            return &[0; 0];
        }
        self.mem.get(idx..sz2).unwrap()
    }

    pub fn read_byte(&self, addr: u64) -> u8 {
        assert!(self.inside(addr));

        let idx = (addr - self.base_addr) as usize;
        if idx < self.mem.len() {
            self.mem[idx]
        } else {
            panic!("reading at 0x{:x}", addr);
        }
    }

    pub fn read_word(&self, addr: u64) -> u16 {
        let idx = (addr - self.base_addr) as usize;
        (self.mem[idx] as u16) + ((self.mem[idx + 1] as u16) << 8)
    }

    pub fn read_dword(&self, addr: u64) -> u32 {
        let idx = (addr - self.base_addr) as usize;
        (self.mem[idx] as u32)
            + ((self.mem[idx + 1] as u32) << 8)
            + ((self.mem[idx + 2] as u32) << 16)
            + ((self.mem[idx + 3] as u32) << 24)
    }

    pub fn read_qword(&self, addr: u64) -> u64 {
        let idx = (addr - self.base_addr) as usize;
        let mut r: u64 = 0;

        for i in 0..8 {
            r |= (self.mem[idx + i] as u64) << (8 * i);
        }

        r
    }

    pub fn write_byte(&mut self, addr: u64, value: u8) {
        let idx = (addr - self.base_addr) as usize;
        self.mem[idx] = value;
    }

    pub fn write_bytes(&mut self, addr: u64, bs: &[u8]) {
        let idx = (addr - self.base_addr) as usize;
        self.mem[idx..(bs.len() + idx)].copy_from_slice(&bs[..]);
    }

    pub fn write_word(&mut self, addr: u64, value: u16) {
        let idx = (addr - self.base_addr) as usize;
        self.mem[idx] = (value & 0x00ff) as u8;
        self.mem[idx + 1] = ((value & 0xff00) >> 8) as u8;
    }

    pub fn write_dword(&mut self, addr: u64, value: u32) {
        let idx = (addr - self.base_addr) as usize;
        assert!(idx < self.mem.len());
        self.mem[idx] = (value & 0x000000ff) as u8;
        self.mem[idx + 1] = ((value & 0x0000ff00) >> 8) as u8;
        self.mem[idx + 2] = ((value & 0x00ff0000) >> 16) as u8;
        self.mem[idx + 3] = ((value & 0xff000000) >> 24) as u8;
    }

    pub fn write_qword(&mut self, addr: u64, value: u64) {
        let idx = (addr - self.base_addr) as usize;
        for i in 0..8 {
            self.mem[idx + i] = ((value >> (i * 8)) & 0xff) as u8;
        }
    }

    pub fn write_string(&mut self, addr: u64, s: &str) {
        let mut v = s.as_bytes().to_vec();
        v.push(0);
        self.write_bytes(addr, &v);
    }

    pub fn write_wide_string(&mut self, addr: u64, s: &str) {
        let mut wv: Vec<u8> = Vec::new();
        let v = s.as_bytes().to_vec();
        for b in v {
            wv.push(b);
            wv.push(0);
        }
        wv.push(0);
        wv.push(0);
        self.write_bytes(addr, &wv);
    }

    pub fn print_bytes(&self) {
        log::info!("---mem---");
        for b in self.mem.iter() {
            print!("{}", b);
        }
        log::info!("---");
    }

    pub fn print_dwords(&self) {
        self.print_dwords_from_to(self.get_base(), self.get_bottom());
    }

    pub fn print_dwords_from_to(&self, from: u64, to: u64) {
        log::info!("---mem---");
        for addr in (from..to).step_by(4) {
            log::info!("0x{:x}", self.read_dword(addr))
        }

        log::info!("---");
    }

    pub fn md5(&self) -> md5::Digest {
        md5::compute(&self.mem)
    }

    pub fn load_at(&mut self, base_addr: u64) {
        self.set_base(base_addr);
        let mut name: String = String::from(&self.mem_name);
        name.push_str(".bin");
        self.load(name.as_str());
    }

    pub fn load_chunk(&mut self, filename: &str, off: u64, sz: usize) -> bool {
        // log::info!("loading chunk: {} {} {}", filename, off, sz);
        let mut f = match File::open(filename) {
            Ok(f) => f,
            Err(_) => {
                return false;
            }
        };
        f.seek(SeekFrom::Start(off));
        let mut reader = BufReader::new(&f);
        self.mem.clear();
        for i in 0..sz {
            self.mem.push(0);
        }
        reader
            .read_exact(&mut self.mem)
            .expect("cannot load chunk of file");
        f.sync_all(); // thanks Alberto Segura
        true
    }

    pub fn load(&mut self, filename: &str) -> bool {
        // log::info!("loading map: {}", filename);
        let f = match File::open(filename) {
            Ok(f) => f,
            Err(_) => {
                return false;
            }
        };
        let len = f.metadata().unwrap().len();
        self.bottom_addr = self.base_addr + len;
        let mut reader = BufReader::new(&f);
        reader
            .read_to_end(&mut self.mem)
            .expect("cannot load map file");
        f.sync_all(); // thanks Alberto Segura
        true
    }

    pub fn save(&self, addr: u64, size: usize, filename: String) {
        let idx = (addr - self.base_addr) as usize;
        let sz2 = idx + size;
        if sz2 > self.mem.len() {
            log::info!("size too big, map size is {}  sz2:{}", self.mem.len(), sz2);
            return;
        }

        let mut f = match File::create(filename) {
            Ok(f) => f,
            Err(e) => {
                log::info!("cannot create the file {}", e);
                return;
            }
        };

        let blob = self.mem.get(idx..sz2).unwrap();

        match f.write_all(blob) {
            Ok(_) => log::info!("saved."),
            Err(_) => log::info!("couldn't save the file"),
        }

        f.sync_all().unwrap();
    }
}
