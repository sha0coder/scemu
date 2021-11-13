mod mem32;


use mem32::Mem32;
use std::collections::HashMap;


pub struct Maps {
    pub maps: HashMap<String,Mem32>,
}

impl Maps {
    pub fn new() -> Maps {
        Maps {
            maps: HashMap::new(),
        }
    }

    pub fn create_map(&mut self, name:&str) -> &mut Mem32 {
        let mem = Mem32::new();
        self.maps.insert(name.to_string(), mem);
        return self.maps.get_mut(name).expect("incorrect memory map name");
    }

    pub fn write_dword(&mut self, addr:u32, value:u32) -> bool {
        for (_,mem) in self.maps.iter_mut() {
            if mem.inside(addr) {
                mem.write_dword(addr, value);
                return true;
            }
        }
        println!("writing on non mapped zone 0x{:x}", addr);
        return false;
    }

    pub fn write_word(&mut self, addr:u32, value:u16) -> bool {
        for (_,mem) in self.maps.iter_mut() {
            if mem.inside(addr) {
                mem.write_word(addr, value);
                return true;
            }
        }
        println!("writing on non mapped zone 0x{:x}", addr);
        return false;
    }

    pub fn write_byte(&mut self, addr:u32, value:u8) -> bool {
        for (_,mem) in self.maps.iter_mut() {
            if mem.inside(addr) {
                mem.write_byte(addr, value);
                return true;
            }
        }
        println!("writing on non mapped zone 0x{:x}", addr);
        return false;
    }

    pub fn read_dword(&self, addr:u32) -> Option<u32> {
        for (name,mem) in self.maps.iter() {
            if mem.inside(addr) {
                if name == "kernel32" {
                    println!("\treading kernel32 addr 0x{:x}", addr);
                }
                return Some(mem.read_dword(addr));
            }
        }
        println!("/!\\ exception: reading on non mapped zone 0x{:x}", addr);
        return None;
    }

    pub fn read_word(&self, addr:u32) -> Option<u16> {
        for (name,mem) in self.maps.iter() {
            if mem.inside(addr) {
                if name == "kernel32" {
                    println!("\treading kernel32 addr 0x{:x}", addr);
                }
                return Some(mem.read_word(addr));
            }
        }
        println!("/!\\ exception: reading on non mapped zone 0x{:x}", addr);
        return None;
    }

    pub fn read_byte(&self, addr:u32) -> Option<u8> {
        for (name,mem) in self.maps.iter() {
            if mem.inside(addr) {
                if name == "kernel32" {
                    println!("\treading kernel32 addr 0x{:x}", addr);
                }
                return Some(mem.read_byte(addr));
            }
        }
        println!("/!\\ exception: reading on non mapped zone 0x{:x}", addr);
        return None;
    }

    pub fn get_mem(&mut self, name:&str) -> &mut Mem32 {
        return self.maps.get_mut(&name.to_string()).expect("incorrect memory map name");
    }

    pub fn print_maps(&self) {
        println!("--- maps ---");
        for k in self.maps.keys() {
            let map = self.maps.get(k).unwrap();
            println!("{}\t0x{:x} - 0x{:x}", k, map.get_base(), map.get_bottom());
        }
        println!("---");
    }

    pub fn get_addr_name(&self, addr:u32) -> Option<String> {
        for (name,mem) in self.maps.iter() {
            if mem.inside(addr) {
                return Some(name.to_string());
            }
        }
        return None;
    }

    pub fn dump(&self, addr:u32) {
        let mut count = 0;
        for _ in 0..8 {
            let mut bytes:Vec<char> = Vec::new();
            for _ in 0..4 {
                let dw = match self.read_dword(addr + count*4) {
                    Some(v) => v,
                    None => {
                        println!("bad address");
                        return;
                    }
                };
                count += 1;
                bytes.push(((dw&0xff) as u8) as char);
                bytes.push((((dw&0xff00)>>8) as u8) as char);
                bytes.push((((dw&0xff0000)>>16) as u8) as char);
                bytes.push((((dw&0xff000000)>>24) as u8) as char);
                print!("{:02x} {:02x} {:02x} {:02x}  ", dw&0xff, (dw&0xff00)>>8, (dw&0xff0000)>>16, (dw&0xff000000)>>24);
            }
            //let s:String = String::from_iter(bytes);
            //let s = str::from_utf8(&bytes).unwrap();
            let s: String = bytes.into_iter().collect();
            println!("{}",s);
        }
    }

    pub fn read_string(&self, addr:u32) -> String {
        let mut bytes:Vec<char> = Vec::new();
        let mut b:u8;
        let mut i:u32 = 0;

        loop {
            b = match self.read_byte(addr+i) {
                Some(v) => v,
                None => break,
            };
            
            if b == 0x00 {
                break;
            }

            i += 1;
            bytes.push(b as char);
        }

        let s: String = bytes.into_iter().collect();
        return s;
    }

    pub fn read_wide_string(&self, addr:u32) -> String {
        let mut bytes:Vec<char> = Vec::new();
        let mut b:u8;
        let mut i:u32 = 0;

        loop {
            b = match self.read_byte(addr+i) {
                Some(v) => v,
                None => break,
            };
            
            if b == 0x00 {
                break;
            }

            i += 2;
            bytes.push(b as char);
        }

        let s: String = bytes.into_iter().collect();
        return s;
    }

    pub fn search_string(&self, kw:String, map_name:String) {
        for (name,mem) in self.maps.iter() {
            if *name == map_name {
                for addr in mem.get_base()..mem.get_bottom() {
                    let bkw = kw.as_bytes();
                    let mut c = 0;
                    
                    for i in 0..bkw.len() {
                        let b = mem.read_byte(addr+(i as u32));
                        if b == bkw[i] {
                            c+=1;
                        } else {
                            break;
                        }
                    }

                    if c == bkw.len() {
                        println!("found at 0x{:x}", addr);
                        return
                    }

                }
                println!("string not found.");
                return;
            }
        }
        println!("map not found");
    }
   
    pub fn search_bytes(&self, bkw:Vec<u8>, map_name:String) {
        for (name,mem) in self.maps.iter() {
            if *name == map_name {
                for addr in mem.get_base()..mem.get_bottom() {
                    let mut c = 0;
                    
                    for i in 0..bkw.len() {
                        let b = mem.read_byte(addr+(i as u32));
                        if b == bkw[i] {
                            c+=1;
                        } else {
                            break;
                        }
                    }

                    if c == bkw.len() {
                        println!("found at 0x{:x}", addr);
                        return
                    }

                }
                println!("string not found.");
                return;
            }
        }
        println!("map not found");

    }

    fn fake_alloc(&mut self, addr:u32, size:u32) {

    }

}



