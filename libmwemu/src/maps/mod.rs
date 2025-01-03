pub mod mem64;

use crate::constants;
use mem64::Mem64;
use serde::{Serialize, Deserialize};
use std::str;

#[derive(Clone, Serialize, Deserialize)]
pub struct Maps {
    pub maps: Vec<Mem64>,
    pub is_64bits: bool,
}

impl Default for Maps {
    fn default() -> Self {
        Self::new()
    }
}

impl Maps {
    pub fn new() -> Maps {
        Maps {
            maps: Vec::new(),
            is_64bits: false,
        }
    }

    pub fn clear(&mut self) {
        self.maps.clear();
    }

    pub fn get_base(&self) -> Option<u64> {
        for map in self.maps.iter() {
            if map.get_name().ends_with(".pe") {
                return Some(map.get_base());
            }
        }
        None
    }

    pub fn exists_mapname(&self, name: &str) -> bool {
        for map in self.maps.iter() {
            if map.get_name() == name {
                return true;
            }
        }
        false
    }

    // slow, better hold the object
    pub fn get_map_by_name(&self, name: &str) -> Option<&Mem64> {
        self.maps.iter().find(|&map| map.get_name() == name)
    }

    pub fn get_map_by_name_mut(&mut self, name: &str) -> Option<&mut Mem64> {
        self.maps.iter_mut().find(|map| map.get_name() == name)
    }

    pub fn create_map(&mut self, name: &str, base: u64, size: u64) -> Result<&mut Mem64, String> {
        //if size == 0 {
        //    return Err(format!("map size cannot be 0"));
        //}

        if self.get_mem_by_addr(base).is_some() {
            return Err(format!("this map address 0x{:x} already exists!", base));
        }

        if self.exists_mapname(name) {
            self.show_maps();
            return Err(format!("this map name {} already exists!", name));
        }

        let mut mem = Mem64::new();
        mem.set_name(name);
        mem.set_base(base);
        mem.set_size(size);

        let pos = self
            .maps
            .binary_search_by(|c| c.get_base().cmp(&base))
            .unwrap_or_else(|e| e);
        self.maps.insert(pos, mem);

        Ok(self.maps.get_mut(pos).unwrap())
    }

    pub fn write_qword(&mut self, addr: u64, value: u64) -> bool {
        for mem in self.maps.iter_mut() {
            if mem.inside(addr)
                && mem.inside(addr + 1)
                && mem.inside(addr + 2)
                && mem.inside(addr + 3)
                && mem.inside(addr + 4)
                && mem.inside(addr + 5)
                && mem.inside(addr + 6)
                && mem.inside(addr + 7)
            {
                mem.write_qword(addr, value);
                return true;
            }
        }

        for i in 0..8 {
            if !self.write_byte(addr + i, ((value >> (i * 8)) & 0xff) as u8) {
                return false;
            }
        }

        true
    }

    pub fn write_dword(&mut self, addr: u64, value: u32) -> bool {
        for mem in self.maps.iter_mut() {
            if mem.inside(addr)
                && mem.inside(addr + 1)
                && mem.inside(addr + 2)
                && mem.inside(addr + 3)
            {
                mem.write_dword(addr, value);
                return true;
            }
        }

        for i in 0..4 {
            if !self.write_byte(addr + i, ((value >> (i * 8)) & 0xff) as u8) {
                return false;
            }
        }

        true
    }

    pub fn write_word(&mut self, addr: u64, value: u16) -> bool {
        for mem in self.maps.iter_mut() {
            if mem.inside(addr) && mem.inside(addr + 1) {
                mem.write_word(addr, value);
                return true;
            }
        }

        for i in 0..2 {
            if !self.write_byte(addr + i, ((value >> (i * 8)) & 0xff) as u8) {
                return false;
            }
        }

        true
    }

    pub fn write_byte(&mut self, addr: u64, value: u8) -> bool {
        for mem in self.maps.iter_mut() {
            if mem.inside(addr) {
                mem.write_byte(addr, value);
                return true;
            }
        }
        log::info!("writing byte on non mapped zone 0x{:x}", addr);
        false
    }

    pub fn write_bytes(&mut self, addr: u64, data: Vec<u8>) {
        //TODO: fix map jump
        for mem in self.maps.iter_mut() {
            if mem.inside(addr) {
                mem.write_bytes(addr, &data);
                return;
            }
        }
    }

    pub fn write_bytes_slice(&mut self, addr: u64, data: &[u8]) {
        //TODO: fix map jump
        for mem in self.maps.iter_mut() {
            if mem.inside(addr) {
                mem.write_bytes(addr, data);
                return;
            }
        }
    }

    pub fn read_128bits_be(&self, addr: u64) -> Option<u128> {
        for mem in self.maps.iter() {
            if mem.inside(addr)
                && mem.inside(addr + 1)
                && mem.inside(addr + 2)
                && mem.inside(addr + 3)
                && mem.inside(addr + 4)
                && mem.inside(addr + 5)
                && mem.inside(addr + 6)
                && mem.inside(addr + 7)
                && mem.inside(addr + 8)
                && mem.inside(addr + 9)
                && mem.inside(addr + 10)
                && mem.inside(addr + 11)
                && mem.inside(addr + 12)
                && mem.inside(addr + 13)
                && mem.inside(addr + 14)
                && mem.inside(addr + 15)
            {
                let mut n: u128 = 0;
                let bytes = mem.read_bytes(addr, 16);
                for (i, byte) in bytes.iter().enumerate().take(16) {
                    n |= (*byte as u128) << (i * 8);
                }
                return Some(n);
            }
        }

        let mut n: u128 = 0;
        for i in 0..16 {
            let v = match self.read_byte(addr + i) {
                Some(v) => v,
                None => return None,
            };
            n |= (v as u128) << ((15 - i) * 8);
        }

        Some(n)
    }

    pub fn read_128bits_le(&self, addr: u64) -> Option<u128> {
        for mem in self.maps.iter() {
            if mem.inside(addr)
                && mem.inside(addr + 1)
                && mem.inside(addr + 2)
                && mem.inside(addr + 3)
                && mem.inside(addr + 4)
                && mem.inside(addr + 5)
                && mem.inside(addr + 6)
                && mem.inside(addr + 7)
                && mem.inside(addr + 8)
                && mem.inside(addr + 9)
                && mem.inside(addr + 10)
                && mem.inside(addr + 11)
                && mem.inside(addr + 12)
                && mem.inside(addr + 13)
                && mem.inside(addr + 14)
                && mem.inside(addr + 15)
            {
                let mut n: u128 = 0;
                let bytes = mem.read_bytes(addr, 16);
                for i in (0..16).rev() {
                    n |= (bytes[i] as u128) << (i * 8);
                }
                return Some(n);
            }
        }

        let mut n: u128 = 0;
        for i in 0..16 {
            let v = match self.read_byte(addr + i) {
                Some(v) => v,
                None => return None,
            };
            n |= (v as u128) << (i * 8);
        }

        Some(n)
    }

    pub fn read_qword(&self, addr: u64) -> Option<u64> {
        for mem in self.maps.iter() {
            if mem.inside(addr)
                && mem.inside(addr + 1)
                && mem.inside(addr + 2)
                && mem.inside(addr + 3)
                && mem.inside(addr + 4)
                && mem.inside(addr + 5)
                && mem.inside(addr + 6)
                && mem.inside(addr + 7)
            {
                return Some(mem.read_qword(addr));
            }
        }

        let mut n: u64 = 0;
        for i in 0..8 {
            let v = match self.read_byte(addr + i) {
                Some(v) => v,
                None => return None,
            };
            n |= (v as u64) << (i * 8);
        }

        Some(n)
    }

    pub fn read_dword(&self, addr: u64) -> Option<u32> {
        for mem in self.maps.iter() {
            if mem.inside(addr)
                && mem.inside(addr + 1)
                && mem.inside(addr + 2)
                && mem.inside(addr + 3)
            {
                return Some(mem.read_dword(addr));
            }
        }

        let mut n: u32 = 0;
        for i in 0..4 {
            let v = match self.read_byte(addr + i) {
                Some(v) => v,
                None => return None,
            };
            n |= (v as u32) << (i * 8);
        }

        Some(n)
    }

    pub fn read_word(&self, addr: u64) -> Option<u16> {
        for mem in self.maps.iter() {
            if mem.inside(addr) && mem.inside(addr + 1) {
                return Some(mem.read_word(addr));
            }
        }

        let mut n: u16 = 0;
        for i in 0..2 {
            let v = match self.read_byte(addr + i) {
                Some(v) => v,
                None => return None,
            };
            n |= (v as u16) << (i * 8);
        }

        Some(n)
    }

    pub fn read_byte(&self, addr: u64) -> Option<u8> {
        for mem in self.maps.iter() {
            if mem.inside(addr) {
                return Some(mem.read_byte(addr));
            }
        }
        None
    }

    pub fn get_mem_ref(&self, name: &str) -> &Mem64 {
        for mem in self.maps.iter() {
            if mem.get_name() == name {
                return mem;
            }
        }
        panic!("incorrect memory map name");
    }

    // deprecated
    pub fn get_mem(&mut self, name: &str) -> &mut Mem64 {
        for mem in self.maps.iter_mut() {
            if mem.get_name() == name {
                return mem;
            }
        }
        panic!("incorrect memory map name {}", name);
    }

    pub fn get_mem2(&mut self, name: &str) -> Option<&mut Mem64> {
        self.maps.iter_mut().find(|mem| mem.get_name() == name)
    }

    pub fn get_mem_by_addr(&mut self, addr: u64) -> Option<&mut Mem64> {
        self.maps.iter_mut().find(|mem| mem.inside(addr))
    }

    pub fn memset(&mut self, addr: u64, b: u8, amount: usize) {
        for i in 0..amount {
            self.write_byte(addr + i as u64, b);
        }
    }

    pub fn memcpy(&mut self, to: u64, from: u64, size: usize) -> bool {
        let mut b: u8;
        for i in 0..size {
            b = match self.read_byte(from + i as u64) {
                Some(v) => v,
                None => return false,
            };
            if !self.write_byte(to + i as u64, b) {
                return false;
            }
        }
        true
    }

    pub fn sizeof_wide(&self, unicode_str_ptr: u64) -> usize {
        let mut zero = false;
        let mut counter: usize = 0;

        for i in 0..usize::MAX {
            let b = self
                .read_byte(unicode_str_ptr + i as u64)
                .expect("maps.sizeof_wide controlled overflow");
            if b == 0 {
                if zero {
                    return counter / 2;
                }
                zero = true;
            } else {
                zero = false;
            }
            counter += 1;
        }

        0
    }

    pub fn write_string(&mut self, to: u64, from: &str) {
        let bs: Vec<u8> = from.bytes().collect();

        for (i, bsi) in bs.iter().enumerate() {
            self.write_byte(to + i as u64, *bsi);
        }
        self.write_byte(to + bs.len() as u64, 0x00);
    }

    pub fn write_wide_string(&mut self, to: u64, from: &str) {
        let bs: Vec<u8> = from.bytes().collect();
        let mut off = 0;
        for bsi in bs.iter() {
            self.write_byte(to + off, *bsi);
            self.write_byte(to + off + 1_u64, 0x00);
            off += 2;
        }
        self.write_byte(to + off, 0x00);
        self.write_byte(to + off + 1_u64, 0x00);
    }

    pub fn write_buffer(&mut self, to: u64, from: &[u8]) {
        for (i, fromi) in from.iter().enumerate() {
            self.write_byte(to + i as u64, *fromi);
        }
    }

    pub fn read_buffer(&mut self, from: u64, sz: usize) -> Vec<u8> {
        let mut buff: Vec<u8> = Vec::new();

        for i in 0..sz {
            let b = match self.read_byte(from + i as u64) {
                Some(v) => v,
                None => {
                    break;
                }
            };
            buff.push(b);
        }

        buff
    }

    pub fn print_maps_keyword(&self, kw: &str) {
        log::info!("--- maps ---");
        for mem in self.maps.iter() {
            let k = mem.get_name();

            let n = if k.len() < 20 { 20 - k.len() } else { 1 };
            let mut spcs: String = String::new();
            for i in 0..n {
                spcs.push(' ');
            }
            if k.contains(kw) {
                log::info!(
                    "{}{}0x{:x} - 0x{:x} ({})",
                    k,
                    spcs,
                    mem.get_base(),
                    mem.get_bottom(),
                    mem.size()
                );
            }
        }
        log::info!("memory usage: {} bytes", self.size());
        log::info!("---");
    }

    pub fn print_maps(&self) {
        log::info!("--- maps ---");
        for mem in self.maps.iter() {
            let k = mem.get_name();

            let n = if k.len() < 20 { 20 - k.len() } else { 1 };
            let mut spcs: String = String::new();
            for i in 0..n {
                spcs.push(' ');
            }
            log::info!(
                "{}{}0x{:x} - 0x{:x} ({})",
                k,
                spcs,
                mem.get_base(),
                mem.get_bottom(),
                mem.size()
            );
        }
        log::info!("memory usage: {} bytes", self.size());
        log::info!("---");
    }

    pub fn get_addr_base(&self, addr: u64) -> Option<u64> {
        for mem in self.maps.iter() {
            if mem.inside(addr) {
                return Some(mem.get_base());
            }
        }
        None
    }

    pub fn is_mapped(&self, addr: u64) -> bool {
        for mem in self.maps.iter() {
            if mem.inside(addr) {
                return true;
            }
        }
        false
    }

    pub fn show_addr_names(&self, addr: u64) {
        for mem in self.maps.iter() {
            if mem.inside(addr) {
                log::info!("{}", mem.get_name());
            }
        }
    }

    pub fn get_addr_name(&self, addr: u64) -> Option<String> {
        for mem in self.maps.iter() {
            if mem.inside(addr) {
                return Some(mem.get_name());
            }
        }
        None
    }

    pub fn dump(&self, addr: u64) {
        let mut count = 0;
        for i in 0..8 {
            let mut bytes: Vec<u8> = Vec::new();
            print!("0x{:x}: ", addr + i * 16);
            for _ in 0..16 {
                let b = self.read_byte(addr + count).unwrap_or(0);
                bytes.push(b);
                count += 1;
                print!("{:02x} ", b);
            }

            let pritable_bytes = self.filter_replace_bytes(&bytes);
            let s: String = match str::from_utf8(&pritable_bytes) {
                Ok(v) => v.to_string(),
                Err(n) => " -utf8err- ".to_string(),
            };

            println!("    {}", s);
        }
    }

    pub fn dump_n(&self, addr: u64, amount: u64) {
        let mut count: u64 = 0;
        for i in 0..8 {
            let mut bytes: Vec<u8> = Vec::new();
            print!("0x{:x}: ", addr + i * 16);
            for _ in 0..16 {
                let b = self.read_byte(addr + count).unwrap_or(0);
                bytes.push(b);
                count += 1;
                print!("{:02x} ", b);
                if count >= amount {
                    println!();
                    return;
                }
            }

            let pritable_bytes = self.filter_replace_bytes(&bytes);
            let s: String = match str::from_utf8(&pritable_bytes) {
                Ok(v) => v.to_string(),
                Err(n) => " -utf8err- ".to_string(),
            };

            println!("    {}", s);
        }
    }

    #[deprecated]
    pub fn dump2(&self, addr: u64) {
        let mut count = 0;
        for _ in 0..8 {
            let mut bytes: Vec<u8> = Vec::new();
            print!("0x{:x}: ", addr + count * 4);
            for _ in 0..4 {
                let dw = match self.read_dword(addr + count * 4) {
                    Some(v) => v,
                    None => {
                        log::info!("bad address");
                        return;
                    }
                };
                count += 1;
                bytes.push((dw & 0xff) as u8);
                bytes.push(((dw & 0xff00) >> 8) as u8);
                bytes.push(((dw & 0xff0000) >> 16) as u8);
                bytes.push(((dw & 0xff000000) >> 24) as u8);
                print!(
                    "{:02x} {:02x} {:02x} {:02x}  ",
                    dw & 0xff,
                    (dw & 0xff00) >> 8,
                    (dw & 0xff0000) >> 16,
                    (dw & 0xff000000) >> 24
                );
            }

            let pritable_bytes = self.filter_replace_bytes(&bytes);
            let s: String = match str::from_utf8(&pritable_bytes) {
                Ok(v) => v.to_string(),
                Err(n) => " -utf8err- ".to_string(),
            };

            log::info!("{}", s);
        }
    }

    pub fn dump_qwords(&self, addr: u64, n: u64) {
        let mut value: u64;

        for i in 0..n {
            let a = addr + i * 8;
            value = match self.read_qword(a) {
                Some(v) => v,
                None => break,
            };

            let name = match self.get_addr_name(value) {
                Some(v) => v,
                None => "".to_string(),
            };

            log::info!(
                "0x{:x}: 0x{:x} ({}) '{}'",
                a,
                value,
                name,
                self.filter_replace_string(&self.read_string(value))
            );
        }
    }

    pub fn dump_dwords(&self, addr: u64, n: u64) {
        let mut value: u32;

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

                log::info!(
                    "0x{:x}: 0x{:x} ({}) '{}'",
                    a,
                    value,
                    name,
                    self.filter_replace_string(&self.read_string(value.into()))
                );
            } else {
                log::info!("0x{:x}: 0x{:x}", a, value);
            }
        }
    }

    pub fn read_bytes(&mut self, addr: u64, sz: usize) -> &[u8] {
        let mem = match self.get_mem_by_addr(addr) {
            Some(v) => v,
            None => return &[0; 0],
        };
        mem.read_bytes(addr, sz)
    }

    pub fn read_string_of_bytes(&mut self, addr: u64, sz: usize) -> String {
        let mut svec: Vec<String> = Vec::new();
        let bytes = self.read_bytes(addr, sz);
        for bs in bytes.iter() {
            svec.push(format!("{:02x} ", bs));
        }
        let s: String = svec.into_iter().collect();
        s
    }

    pub fn read_string(&self, addr: u64) -> String {
        let mut bytes: Vec<char> = Vec::new();
        let mut b: u8;
        let mut i: u64 = 0;

        loop {
            b = match self.read_byte(addr + i) {
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

    pub fn read_wide_string(&self, addr: u64) -> String {
        let mut bytes: Vec<char> = Vec::new();
        let mut b: u8;
        let mut i: u64 = 0;

        loop {
            b = match self.read_byte(addr + i) {
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

    pub fn search_string(&self, kw: &str, map_name: &str) -> Option<Vec<u64>> {
        let mut found: Vec<u64> = Vec::new();

        for mem in self.maps.iter() {
            let name = mem.get_name();
            if name == map_name {
                for addr in mem.get_base()..mem.get_bottom() {
                    let bkw = kw.as_bytes();
                    let mut c = 0;

                    for (i, bkwi) in bkw.iter().enumerate() {
                        let b = mem.read_byte(addr + (i as u64));

                        if b == *bkwi {
                            c += 1;
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
        log::info!("map not found");
        None
    }

    pub fn write_spaced_bytes(&mut self, addr: u64, sbs: &str) -> bool {
        let mut waddr = addr;
        let bs: Vec<&str> = sbs.split(' ').collect();
        for bsi in bs.iter() {
            let b = u8::from_str_radix(bsi, 16).expect("bad num conversion");
            if !self.write_byte(waddr, b) {
                return false;
            }
            waddr += 1;
        }
        true
    }

    pub fn spaced_bytes_to_bytes(&self, sbs: &str) -> Vec<u8> {
        let bs: Vec<&str> = sbs.split(' ').collect();
        let mut bytes: Vec<u8> = Vec::new();
        for bsi in bs.iter() {
            let b = match u8::from_str_radix(bsi, 16) {
                Ok(b) => b,
                Err(_) => {
                    log::info!("bad hex bytes");
                    return bytes;
                }
            };
            bytes.push(b);
        }
        bytes
    }

    // search only one occurence from specific address
    pub fn search_spaced_bytes_from(&self, sbs: &str, saddr: u64) -> u64 {
        let bkw = self.spaced_bytes_to_bytes(sbs);
        for mem in self.maps.iter() {
            if mem.get_base() <= saddr && saddr < mem.get_bottom() {
                for addr in saddr..mem.get_bottom() {
                    let mut c = 0;

                    for (i, bkwn) in bkw.iter().enumerate() {
                        if addr + i as u64 >= mem.get_bottom() {
                            break;
                        }
                        let b = mem.read_byte(addr + (i as u64));
                        if b == *bkwn {
                            c += 1;
                        } else {
                            break;
                        }
                    }

                    if c == bkw.len() {
                        return addr;
                    }
                } // for

                return 0;
            }
        }
        0
    }

    // search only one occurence from specific address backward
    pub fn search_spaced_bytes_from_bw(&self, sbs: &str, saddr: u64) -> u64 {
        let bkw = self.spaced_bytes_to_bytes(sbs);
        for mem in self.maps.iter() {
            if mem.get_base() <= saddr && saddr < mem.get_bottom() {
                for addr in (mem.get_base()..=saddr).rev() {
                    let mut c = 0;

                    for (i, bkwn) in bkw.iter().enumerate() {
                        if addr + i as u64 >= mem.get_bottom() {
                            break;
                        }
                        let b = mem.read_byte(addr + (i as u64));
                        if b == *bkwn {
                            c += 1;
                        } else {
                            break;
                        }
                    }

                    if c == bkw.len() {
                        return addr;
                    }
                } // for

                return 0;
            }
        }
        0
    }

    pub fn search_spaced_bytes(&self, sbs: &str, map_name: &str) -> Vec<u64> {
        let bytes = self.spaced_bytes_to_bytes(sbs);
        self.search_bytes(bytes, map_name)
    }

    pub fn search_spaced_bytes_in_all(&self, sbs: &str) -> Vec<u64> {
        let bytes = self.spaced_bytes_to_bytes(sbs);
        let mut found: Vec<u64> = Vec::new();

        for mem in self.maps.iter() {
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

    //TODO: return a list with matches.
    pub fn search_string_in_all(&self, kw: String) {
        let mut found = false;
        for mem in self.maps.iter() {
            if mem.get_base() >= 0x7000000 {
                continue;
            }

            let results = match self.search_string(&kw, &mem.get_name()) {
                Some(v) => v,
                None => {
                    continue;
                }
            };

            for addr in results.iter() {
                if self.is_64bits {
                    log::info!("found at 0x{:x} '{}'", addr, self.read_string(*addr));
                } else {
                    log::info!(
                        "found at 0x{:x} '{}'",
                        *addr as u32,
                        self.read_string(*addr)
                    );
                }
                found = true;
            }
        }

        if !found {
            log::info!("not found.");
        }
    }

    pub fn search_bytes(&self, bkw: Vec<u8>, map_name: &str) -> Vec<u64> {
        let mut addrs: Vec<u64> = Vec::new();

        for mem in self.maps.iter() {
            if mem.get_name() == map_name {
                for addr in mem.get_base()..mem.get_bottom() {
                    let mut c = 0;

                    for (i, bkwn) in bkw.iter().enumerate() {
                        if addr + i as u64 >= mem.get_bottom() {
                            break;
                        }
                        let b = mem.read_byte(addr + (i as u64));
                        if b == *bkwn {
                            c += 1;
                        } else {
                            break;
                        }
                    }

                    if c == bkw.len() {
                        addrs.push(addr);
                    }
                }

                return addrs;
            }
        }
        addrs
    }

    pub fn size(&self) -> usize {
        let mut sz: usize = 0;
        for mem in self.maps.iter() {
            sz += mem.size();
        }
        sz
    }

    pub fn overlaps(&self, addr: u64, sz: u64) -> bool {
        for a in addr..addr + sz {
            if self.is_mapped(a) {
                return true;
            }
        }
        false
    }

    pub fn show_allocs(&self) {
        for mem in self.maps.iter() {
            let name = mem.get_name();
            if name.starts_with("alloc_") || name.starts_with("valloc_") {
                log::info!(
                    "{} 0x{:x} - 0x{:x} ({})",
                    name,
                    mem.get_base(),
                    mem.get_bottom(),
                    mem.size()
                );
            }
        }
    }

    pub fn show_maps(&self) {
        for mem in self.maps.iter() {
            let name = mem.get_name();
            log::info!(
                "{} 0x{:x} - 0x{:x} ({})",
                name,
                mem.get_base(),
                mem.get_bottom(),
                mem.size()
            );
        }
    }

    pub fn free(&mut self, name: &str) {
        let mut id_to_delete = 0;
        let mut remove = false;

        for i in 0..self.maps.len() {
            if self.maps[i].get_name() == name {
                id_to_delete = i;
                remove = true;
                break;
            }
        }
        if remove {
            self.maps.remove(id_to_delete);
        }
    }

    pub fn dealloc(&mut self, addr: u64) {
        let mut id_to_delete = 0;
        let mut remove = false;

        for i in 0..self.maps.len() {
            if self.maps[i].get_base() == addr {
                id_to_delete = i;
                remove = true;
                break;
            }
        }
        if remove {
            self.maps.remove(id_to_delete);
        }
    }

    pub fn lib64_alloc(&self, sz: u64) -> Option<u64> {
        self._alloc(sz, constants::LIBS64_MIN, constants::LIBS64_MAX, true)
    }

    pub fn lib32_alloc(&self, sz: u64) -> Option<u64> {
        self._alloc(sz, constants::LIBS32_MIN, constants::LIBS32_MAX, true)
    }

    pub fn alloc(&self, sz: u64) -> Option<u64> {
        if self.is_64bits {
            self._alloc(sz, 1, constants::LIBS64_MIN, false)
        } else {
            self._alloc(sz, 1, constants::LIBS32_MIN, false)
        }
    }

    fn _alloc(&self, sz: u64, bottom: u64, top: u64, lib: bool) -> Option<u64> {
        let mut prev: u64 = bottom;

        //log::info!("allocating {} bytes from 0x{:x} to 0x{:x}", sz, bottom, top);

        for i in 0..self.maps.len() {
            let mem = &self.maps[i];
            let base = mem.get_base();

            if lib && base < bottom {
                //log::info!("skipping: 0x{:x}", base);
                continue; // a lib finding allocs that are not lib
            }

            //log::info!("base: 0x{:x} prev: 0x{:x} sz: 0x{:x}", base, prev, sz);
            if prev > base {
                //self.show_maps();
                panic!("alloc error");
            }
            //log::info!("space: 0x{:x}", base - prev);
            if (base - prev) > sz {
                //log::info!("space found: 0x{:x}", prev);
                return Some(prev);
            }

            prev = mem.get_bottom();
        }

        if top - prev > sz {
            //log::info!("space found: 0x{:x} sz:{}", prev, sz);
            return Some(prev);
        }

        log::info!("no space found");
        None
    }

    pub fn alloc_deprecated(&self, sz: u64) -> Option<u64> {
        let mut addr: u64 = 0;
        let inc = 0x10;

        loop {
            addr += inc;

            if addr >= 0x70000000 {
                return None;
            }

            for mem in self.maps.iter() {
                if addr >= mem.get_base() && addr <= mem.get_bottom() {
                    addr = mem.get_bottom();
                    continue;
                }
            }

            if !self.overlaps(addr, sz) {
                return Some(addr);
            }
        }
    }

    pub fn save_all_allocs(&mut self, path: String) {
        for mem in self.maps.iter() {
            if mem.get_name().to_string().starts_with("alloc_") {
                let mut ppath = path.clone();
                ppath.push('/');
                ppath.push_str(&mem.get_name());
                ppath.push_str(".bin");
                mem.save(mem.get_base(), mem.size(), ppath);
            }
        }
    }

    pub fn save_all(&self, path: String) {
        for mem in self.maps.iter() {
            let mut ppath = path.clone();
            ppath.push('/');
            ppath.push_str(&format!("{:x}-{}", mem.get_base(), mem.get_name()));
            ppath.push_str(".bin");
            mem.save(mem.get_base(), mem.size(), ppath);
        }
    }

    pub fn save(&mut self, addr: u64, size: u64, filename: String) {
        //TODO: return a boolean or option.
        match self.get_mem_by_addr(addr) {
            Some(m) => {
                m.save(addr, size as usize, filename);
            }
            None => {
                log::info!("this address is not mapped.");
            }
        }
    }

    pub fn filter_string(&self, s: &mut String) {
        let valid = " 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ \t\x00".as_bytes();
        s.retain(|c| valid.contains(&(c as u8)));
    }

    pub fn filter_replace_bytes(&self, s: &[u8]) -> Vec<u8> {
        let mut sanitized: Vec<u8> = Vec::new();
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

    pub fn filter_replace_string(&self, s: &str) -> String {
        let valid = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~".as_bytes();
        let sb = s.as_bytes();
        let mut p;
        let mut dst: Vec<char> = Vec::new();

        for i in 0..s.len() {
            p = false;
            for j in 0..valid.len() {
                if sb[i] == valid[j] {
                    dst.push(sb[i] as char);
                    p = true;
                    break;
                }
            }
            if !p {
                dst.push('.');
            }
        }

        let sdst: String = dst.into_iter().collect();
        sdst
    }

    pub fn mem_test(&self) -> bool {
        for mem1 in self.maps.iter() {
            let name1 = mem1.get_name();

            for mem2 in self.maps.iter() {
                let name2 = mem2.get_name();

                if name1 != name2 {
                    for addr1 in mem1.get_base()..mem1.get_bottom() {
                        if mem2.inside(addr1) {
                            log::info!("/!\\ {} overlaps with {}", name1, name2);
                            log::info!(
                                "/!\\ 0x{:x}-0x{:x} vs 0x{:x}-0x{:x}",
                                mem1.get_base(),
                                mem1.get_bottom(),
                                mem2.get_base(),
                                mem2.get_bottom()
                            );
                            return false;
                        }
                    }
                }
            }

            if (mem1.get_base() + (mem1.size() as u64)) != mem1.get_bottom() {
                log::info!("/!\\ memory bottom dont match, mem: {}", name1);
                return false;
            }
        }

        true
    }
}
