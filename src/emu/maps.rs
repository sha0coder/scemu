pub mod mem64;

use mem64::Mem64;
use std::collections::HashMap;
use std::str;

#[derive(Clone)]
pub struct Maps {
    pub maps: HashMap<String,Mem64>,
    pub is_64bits: bool,
}

impl Maps {
    pub fn new() -> Maps {
        Maps {
            maps: HashMap::new(),
            is_64bits: false,
        }
    }

    pub fn get_map_by_name(&self, name:&str) -> Option<&Mem64> {
        let s = name.to_string();
        self.maps.get(&s)
    }

    pub fn create_map(&mut self, name:&str) -> &mut Mem64 {
        let mut mem = Mem64::new();
        mem.set_name(name);
        self.maps.insert(name.to_string(), mem);
        return self.maps.get_mut(name).expect("incorrect memory map name");
    }


    pub fn write_qword(&mut self, addr:u64, value:u64) -> bool {
        for (_,mem) in self.maps.iter_mut() {
            if mem.inside(addr) {
                mem.write_qword(addr, value);
                return true;
            }
        }
        println!("writing on non mapped zone 0x{:x}", addr);
        false
    }


    pub fn write_dword(&mut self, addr:u64, value:u32) -> bool {
        for (_,mem) in self.maps.iter_mut() {
            if mem.inside(addr) {
                mem.write_dword(addr, value);
                return true;
            }
        }
        println!("writing on non mapped zone 0x{:x}", addr);
        false
    }

    pub fn write_word(&mut self, addr:u64, value:u16) -> bool {
        for (_,mem) in self.maps.iter_mut() {
            if mem.inside(addr) {
                mem.write_word(addr, value);
                return true;
            }
        }
        println!("writing on non mapped zone 0x{:x}", addr);
        false
    }

    pub fn write_byte(&mut self, addr:u64, value:u8) -> bool {
        for (_,mem) in self.maps.iter_mut() {
            if mem.inside(addr) {
                mem.write_byte(addr, value);
                return true;
            }
        }
        println!("writing on non mapped zone 0x{:x}", addr);
        false
    }

    pub fn read_128bits_be(&self, addr:u64) -> Option<u128> {
        for (_,mem) in self.maps.iter() {
            if mem.inside(addr) {
                let mut n:u128 = 0;
                let bytes = mem.read_bytes(addr, 16);
                for i in 0..16 {
                   n |= (bytes[i] as u128) << (i*8);
                }
                return Some(n);
            }
        }
        None
    }

    pub fn read_128bits_le(&self, addr:u64) -> Option<u128> {
        for (_,mem) in self.maps.iter() {
            if mem.inside(addr) {
                let mut n:u128 = 0;
                let bytes = mem.read_bytes(addr, 16);
                for i in (0..16).rev() {
                    n |= (bytes[i] as u128) << (i*8);
                }
                return Some(n);
            }
        }
        None
    }

    pub fn read_qword(&self, addr:u64) -> Option<u64> {
        for (_,mem) in self.maps.iter() {
            if mem.inside(addr) {
                return Some(mem.read_qword(addr));
            }
        }
        None
    }

    pub fn read_dword(&self, addr:u64) -> Option<u32> {
        for (_,mem) in self.maps.iter() {
            if mem.inside(addr) {
                return Some(mem.read_dword(addr));
            }
        }
        None
    }

    pub fn read_word(&self, addr:u64) -> Option<u16> {
        for (_,mem) in self.maps.iter() {
            if mem.inside(addr) {
                return Some(mem.read_word(addr));
            }
        }
        None
    }

    pub fn read_byte(&self, addr:u64) -> Option<u8> {
        for (_,mem) in self.maps.iter() {
            if mem.inside(addr) {
                return Some(mem.read_byte(addr));
            }
        }
        None
    }

    pub fn get_mem_ref(&self, name:&str) -> &Mem64 {
        return self.maps.get(&name.to_string()).expect("incorrect memory map name");
    }

    pub fn get_mem(&mut self, name:&str) -> &mut Mem64 {
        let mem = self.maps.get_mut(&name.to_string()).or_else(|| {
            panic!("incorrect memory map name {}", name);
        }).unwrap();

        return mem;
    }

    pub fn get_mem_by_addr(&mut self, addr:u64) -> Option<&mut Mem64> {
        for (_,mem) in self.maps.iter_mut() {
            if mem.inside(addr) {
                return Some(mem);
            }
        }
        None
    }

    pub fn memset(&mut self, addr:u64, b:u8, amount:usize)  {
        for i in 0..amount {
            self.write_byte(addr+i as u64, b);
        }
    }

    pub fn memcpy(&mut self, to:u64, from:u64, size:usize) -> bool {
        let mut b:u8;
        for i in 0..size {
            b = match self.read_byte(from+i as u64) {
                Some(v) => v,
                None => return false,
            };
            if !self.write_byte(to+i as u64, b) {
                return false;
            }
        }
        true
    }

    pub fn write_string(&mut self, to:u64, from:&str) {
        let bs:Vec<u8> = from.bytes().collect();

        for (i, bsi) in bs.iter().enumerate() {
            self.write_byte(to + i as u64, *bsi);
        }
    }

    pub fn write_buffer(&mut self, to:u64, from:&[u8]) {
        for (i,fromi) in from.iter().enumerate() {
            self.write_byte(to + i as u64, *fromi);
        }
    }

    pub fn read_buffer(&mut self, from:u64, sz:usize) -> Vec<u8> {
        let mut buff:Vec<u8> = Vec::new();

        for i in 0..sz {
            let b = match self.read_byte(from + i as u64) {
                Some(v) => v,
                None => { break; }
            };
            buff.push(b);
        }

        buff
    }

    pub fn print_maps(&self) {
        println!("--- maps ---");
        for k in self.maps.keys() {
            let map = self.maps.get(k).unwrap();
            let n;
            if k.len() < 20 {
                n = 20 - k.len();
            } else {
                n = 1;
            }
            let mut spcs:String = String::new();
            for i in 0..n {
                spcs.push(' ');
            }
            println!("{}{}0x{:x} - 0x{:x} ({})", k, spcs, map.get_base(), map.get_bottom(), map.size());
        }
        println!("memory usage: {} bytes", self.size());
        println!("---");
    }

    pub fn get_addr_base(&self, addr:u64) -> Option<u64> {
        for (_, mem) in self.maps.iter() {
            if mem.inside(addr) {
                return Some(mem.get_base());
            }
        }
        None
    }

    pub fn is_mapped(&self, addr:u64) -> bool {
        for (_,mem) in self.maps.iter() {
            if mem.inside(addr) {
                return true;
            }
        }
        false
    }

    pub fn get_addr_name(&self, addr:u64) -> Option<String> {
        for (name,mem) in self.maps.iter() {
            if mem.inside(addr) {
                return Some(name.to_string());
            }
        }
        None
    }

    pub fn dump(&self, addr:u64) {
        let mut count = 0;
        for i in 0..8 {
            let mut bytes:Vec<u8> = Vec::new();
            print!("0x{:x}: ", addr + i * 16);
            for _ in 0..16 {
                let b = self.read_byte(addr + count).unwrap_or(0);
                bytes.push(b);
                count += 1;
                print!("{:02x} ", b);
            }

            let pritable_bytes = self.filter_replace_bytes(&bytes);
            let s:String = match str::from_utf8(&pritable_bytes) {
                Ok(v) => v.to_string(),
                Err(n) => " -utf8err- ".to_string(),
            };
            
            println!("    {}", s);
        }
    }

    #[deprecated]
    pub fn dump2(&self, addr:u64) {
        let mut count = 0;
        for _ in 0..8 {
            let mut bytes:Vec<u8> = Vec::new();
            print!("0x{:x}: ", addr + count * 4);
            for _ in 0..4 {
                let dw = match self.read_dword(addr + count*4) {
                    Some(v) => v,
                    None => {
                        println!("bad address");
                        return;
                    }
                };
                count += 1;
                bytes.push((dw&0xff) as u8);
                bytes.push(((dw&0xff00)>>8) as u8);
                bytes.push(((dw&0xff0000)>>16) as u8);
                bytes.push(((dw&0xff000000)>>24) as u8);
                print!("{:02x} {:02x} {:02x} {:02x}  ", dw&0xff, (dw&0xff00)>>8, (dw&0xff0000)>>16, (dw&0xff000000)>>24);
            }

            let pritable_bytes = self.filter_replace_bytes(&bytes);
            let s:String = match str::from_utf8(&pritable_bytes) {
                Ok(v) => v.to_string(),
                Err(n) => " -utf8err- ".to_string(),
            };
            
            println!("{}", s);
        }
    }

    pub fn dump_qwords(&self, addr:u64, n:u64) {
        let mut value:u64;

        for i in 0..n {
            let a = addr + i * 8;
            value = match self.read_qword(a) {
                Some(v) => v,
                None => break,
            };

            let name = match self.get_addr_name(value.into()) {
                Some(v) => v,
                None => "".to_string(),
            };

            println!("0x{:x}: 0x{:x} ({}) '{}'", a, value, name, self.filter_replace_string(&self.read_string(value.into())));

        }
    }

    pub fn dump_dwords(&self, addr:u64, n:u64) {
        let mut value:u32;

        for i in 0..n {
            let a = addr + i * 4;
            value = match self.read_dword(a) {
                Some(v) => v,
                None => break,
            };

            if !self.is_64bits {
                // only in 32bits make sense derreference dwords in memory
                let name = match self.get_addr_name(value.into()) {
                    Some(v) => v,
                    None => "".to_string(),
                };

                println!("0x{:x}: 0x{:x} ({}) '{}'", a, value, name, self.filter_replace_string(&self.read_string(value.into())));
            } else {
                println!("0x{:x}: 0x{:x}", a, value);
            }

        }
    }

    pub fn read_bytes(&mut self, addr:u64, sz:usize) -> &[u8] {
        let mem = match self.get_mem_by_addr(addr) {
            Some(v) => v,
            None => return &[0;0],
        };
        mem.read_bytes(addr, sz)
    }

    pub fn read_string_of_bytes(&mut self, addr:u64, sz:usize) -> String {
        let mut svec:Vec<String> = Vec::new();
        let bytes = self.read_bytes(addr, sz);
        for bs in bytes.iter() {   
            svec.push(format!("{:02x} ", bs));
        }
        let s:String = svec.into_iter().collect();
        s
    }

    pub fn read_string(&self, addr:u64) -> String {
        let mut bytes:Vec<char> = Vec::new();
        let mut b:u8;
        let mut i:u64 = 0;

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
        s
    }

    pub fn read_wide_string(&self, addr:u64) -> String {
        let mut bytes:Vec<char> = Vec::new();
        let mut b:u8;
        let mut i:u64 = 0;

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
        s
    }

    pub fn search_string(&self, kw:&str, map_name:&str) -> Option<Vec<u64>> {
        let mut found:Vec<u64> = Vec::new();

        for (name,mem) in self.maps.iter() {
            if name == map_name {

                for addr in mem.get_base()..mem.get_bottom() {
                    let bkw = kw.as_bytes();
                    let mut c = 0;
                    
                    for (i, bkwi) in bkw.iter().enumerate() {
                        let b = mem.read_byte(addr+(i as u64));

                        if b == *bkwi {
                            c+=1;
                        } else {
                            break;
                        }
                    }
                    
                    if c == kw.len() {
                        found.push(addr);
                    }

                }

                if !found.is_empty() {
                    return Some(found);
                } else {
                    return None;
                }
            }
        }
        println!("map not found");
        None
    }

    pub fn write_spaced_bytes(&mut self, addr:u64, sbs:String) -> bool {
        let bs:Vec<&str> = sbs.split(' ').collect();
        for bsi in bs.iter() {
            let b = u8::from_str_radix(bsi, 16).expect("bad num conversion");
            if !self.write_byte(addr, b) {
                return false;
            }
        }
        true
    }

    pub fn spaced_bytes_to_bytes(&self, sbs:&str) -> Vec<u8> {
        let bs:Vec<&str> = sbs.split(' ').collect();
        let mut bytes:Vec<u8> = Vec::new();
        for bsi in bs.iter() {
            let b = match u8::from_str_radix(bsi,16) {
                Ok(b) => b,
                Err(_) => {
                    println!("bad hex bytes");
                    return bytes;
                }
            };
            bytes.push(b);
        }
        bytes
    }

    pub fn search_spaced_bytes(&self, sbs:&str, map_name:&str) -> bool {
        let bytes = self.spaced_bytes_to_bytes(sbs);
        self.search_bytes(bytes, map_name)
    }

    pub fn search_space_bytes_in_all(&self, sbs:&str) -> Vec<u64> {
        let bytes = self.spaced_bytes_to_bytes(sbs);
        let mut found:Vec<u64> = Vec::new();

        for (name, mem) in self.maps.iter() {
            for addr in mem.get_base()..mem.get_bottom() {
                if addr < 0x70000000 {
                    
                    let mut c = 0;
                    for (i, bi) in bytes.iter().enumerate() {
                        let addri = addr + (i as u64);
                        if !mem.inside(addri) {
                            break;
                        }

                        let b = mem.read_byte(addri);
                        if b == *bi {
                            c += 1;
                        } else {
                            break;
                        }
                    
                    }

                    if c == bytes.len() {
                        found.push(addr);
                    }
                }
            }
        }

        found
    }

    pub fn search_string_in_all(&self, kw:String) {
        let mut found = false;
        for (name, mem) in self.maps.iter() {

            if mem.get_base() >= 0x7000000 {
                continue;
            }

            let results = match self.search_string(&kw, name) {
                Some(v) => v,
                None => { continue; }
            };

            for addr in results.iter() {
                if self.is_64bits {
                    println!("found at 0x{:x} '{}'", addr, self.read_string(*addr));
                } else {
                    println!("found at 0x{:x} '{}'", *addr as u32, self.read_string(*addr));
                }
                found = true;
            }
        }

        if !found {
            println!("not found.");
        }
    }
   
    pub fn search_bytes(&self, bkw:Vec<u8>, map_name:&str) -> bool {
        let mut found:bool = false;

        for (name,mem) in self.maps.iter() {
            if name == map_name {
                for addr in mem.get_base()..mem.get_bottom() {
                    let mut c = 0;
                  
                    for (i, bkwn) in bkw.iter().enumerate() {
                        let b = mem.read_byte(addr+(i as u64));
                        if b == *bkwn {
                            c += 1;
                        } else {
                            break;
                        }
                    }

                    if c == bkw.len() {
                        println!("found at 0x{:x}", addr);
                        found = true;
                    }

                }

                return found;
            }
        }
        println!("map not found");
        false
    }

    pub fn size(&self) -> usize {
        let mut sz:usize = 0;
        for (_,mem) in self.maps.iter() {
            sz += mem.size();
        }
        sz
    }

    pub fn overlapps(&self, addr:u64, sz:u64) -> bool {
        for a in addr..addr+sz {
            if self.is_mapped(a) {
                return true;
            }
        }
       false
    }

    pub fn show_allocs(&self) {
        for (name, mem) in self.maps.iter() {
            if name.starts_with("alloc_") || name.starts_with("valloc_") {
                println!("{} 0x{:x} - 0x{:x} ({})", name, mem.get_base(), mem.get_bottom(), mem.size());
            } 
        }
    }

    pub fn free(&mut self, name:&str) {
        self.maps.remove(name);
    }

    pub fn alloc(&self, sz:u64) -> Option<u64> {
        // super simple memory allocator

        let mut addr:u64 = 100;

        loop {
            addr += sz;
            
            if addr >= 0x70000000 {
                return None;
            }

            for (_,mem) in self.maps.iter() {
                if addr >= mem.get_base() && addr <= mem.get_bottom() {
                    continue;
                }
            }

            if !self.overlapps(addr, sz) {
                return Some(addr);
            }

        }
    }

    pub fn save_all_allocs(&mut self, path: String) {
        for (name, mem) in self.maps.iter() {
            if name.to_string().starts_with("alloc_") {
                let mut ppath = path.clone();
                ppath.push_str("/");
                ppath.push_str(name);
                ppath.push_str(".bin");
                mem.save(mem.get_base(), mem.size() as usize, ppath);
            }
        }

    }

    pub fn save(&mut self, addr:u64, size:u64, filename:String) {
        match self.get_mem_by_addr(addr) {
            Some(m) => {
                m.save(addr, size as usize, filename);
            },
            None => {
                println!("this address is not mapped.");
            }
        }
    }

    pub fn filter_string(&self, s:&mut String) {
        let valid = " 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ \t\x00".as_bytes();
        let sb = s.as_bytes();
        let mut p;
        let mut new_len:usize = 0;
        for i in 0..s.len() {
            new_len = i as usize;
            p = false;
            for j in 0..valid.len() {
                if sb[i as usize] == valid[j as usize] { 
                    p = true;
                    break;    
                }
            }
            if !p {
                break;
            }
        }

        *s = s[..new_len].to_string();
    }

    pub fn filter_replace_bytes(&self, s:&[u8]) -> Vec<u8> {
        let mut sanitized:Vec<u8> = Vec::new();
        let valid = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~".as_bytes();
        let mut p;

        for si in s.iter() {
            p = false;
            for validj in valid.iter() {
                if validj == si {
                    sanitized.push(*si);
                    p = true;
                    break;
                }
            }
            if !p {
                sanitized.push(b'.');
            }
        }

        sanitized
    }

    pub fn filter_replace_string(&self, s:&str) -> String {
        let valid = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~".as_bytes();
        let sb = s.as_bytes();
        let mut p;
        let mut dst:Vec<char> = Vec::new();

        for i in 0..s.len() {
            p = false;
            for j in 0..valid.len() {
                if sb[i as usize] == valid[j as usize] {
                    dst.push(sb[i] as char);
                    p = true;
                    break;    
                }
            }
            if !p {
                dst.push('.');
            }
        }

        let sdst:String = dst.into_iter().collect();
        sdst
    }

    pub fn mem_test(&self) -> bool {
        for (name1, mem1) in self.maps.iter() {
            for (name2, mem2) in self.maps.iter() {

                if name1 != name2 {

                    for addr1 in mem1.get_base()..mem1.get_bottom() {
                        if mem2.inside(addr1) {
                            println!("/!\\ {} overlaps with {}", name1, name2);
                            println!("/!\\ 0x{:x}-0x{:x} vs 0x{:x}-0x{:x}", mem1.get_base(), mem1.get_bottom(), mem2.get_base(), mem2.get_bottom());
                            return false;
                        }
                    }

                }
            }

            if (mem1.get_base() + (mem1.size() as u64)) != mem1.get_bottom() {
                println!("/!\\ memory bottom dont match, mem: {}", name1);
                return false;
            }

        }

        true
    }

}


