mod mem32;

use mem32::Mem32;
use std::collections::HashMap;

/*
pub struct Map {
    pub name: String,
    pub mem: Mem32,
}

impl Map {
    pub fn new(name:&str) -> Map {
        Map {
            name: name.to_string(),
            mem: Mem32::new(),
        }
    }
}*/


pub struct Maps {
    pub maps: HashMap<String,Mem32>
}

impl Maps {
    pub fn new() -> Maps {
        Maps {
            maps: HashMap::new(),
        }
    }

    pub fn create_map(&mut self, name:&str) {
        let mem = Mem32::new();
        self.maps.insert(name.to_string(), mem);
    }

    pub fn write_dword(&mut self, addr:u32, value:u32) {
        for (_,mem) in self.maps.iter_mut() {
            if mem.inside(addr) {
                mem.write_dword(addr, value);
                return;
            }
        }
        panic!("writing on non mapped zone 0x{:x}", addr);
    }

    pub fn write_word(&mut self, addr:u32, value:u16) {
        for (_,mem) in self.maps.iter_mut() {
            if mem.inside(addr) {
                mem.write_word(addr, value);
                return;
            }
        }
        panic!("writing on non mapped zone 0x{:x}", addr);
    }

    pub fn write_byte(&mut self, addr:u32, value:u8) {
        for (_,mem) in self.maps.iter_mut() {
            if mem.inside(addr) {
                mem.write_byte(addr, value);
                return;
            }
        }
        panic!("writing on non mapped zone 0x{:x}", addr);
    }

    pub fn read_dword(&self, addr:u32) -> u32 {
        for (_,mem) in self.maps.iter() {
            if mem.inside(addr) {
                return mem.read_dword(addr);
            }
        }
        panic!("reading on non mapped zone 0x{:x}", addr);
    }

    pub fn read_word(&self, addr:u32) -> u16 {
        for (_,mem) in self.maps.iter() {
            if mem.inside(addr) {
                return mem.read_word(addr);
            }
        }
        panic!("reading on non mapped zone 0x{:x}", addr);
    }

    pub fn read_byte(&self, addr:u32) -> u8 {
        for (_,mem) in self.maps.iter() {
            if mem.inside(addr) {
                return mem.read_byte(addr);
            }
        }
        panic!("reading on non mapped zone 0x{:x}", addr);
    }

    pub fn get_mem(&mut self, name:&str) -> &mut Mem32 {
        return self.maps.get_mut(&name.to_string()).expect("incorrect memory map name");
    }
}