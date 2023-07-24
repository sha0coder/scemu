use super::err::ScemuError;
use crate::emu::maps::Maps;
use super::maps::mem64::Mem64;
use super::constants;
use std::fs::File;
use std::io::Read;

macro_rules! read_u8 {
    ($raw:expr, $off:expr) => {
        $raw[$off]
    };
}

macro_rules! read_u16_le {
    ($raw:expr, $off:expr) => {
        (($raw[$off + 1] as u16) << 8) | ($raw[$off] as u16)
    };
}

macro_rules! read_u32_le {
    ($raw:expr, $off:expr) => {
        (($raw[$off + 3] as u32) << 24)
            | (($raw[$off + 2] as u32) << 16)
            | (($raw[$off + 1] as u32) << 8)
            | ($raw[$off] as u32)
    };
}

macro_rules! read_u64_le {
    ($raw:expr, $off:expr) => {
        (($raw[$off + 7] as u64) << 56)
            | (($raw[$off + 6] as u64) << 48)
            | (($raw[$off + 5] as u64) << 40)
            | (($raw[$off + 4] as u64) << 32)
            | (($raw[$off + 3] as u64) << 24)
            | (($raw[$off + 2] as u64) << 16)
            | (($raw[$off + 1] as u64) << 8)
            | ($raw[$off] as u64)
    };
}



pub const EI_NIDENT:usize = 16;
pub const ELFCLASS64:u8 = 0x02;
pub const DT_NEEDED:u64 = 1;
pub const DT_NULL:u64 = 0;
pub const DT_STRTAB:u64 = 5;

#[derive(Debug)]
pub struct Elf64 {
    pub bin: Vec<u8>,
    pub elf_hdr: Elf64Ehdr,
    pub elf_phdr: Vec<Elf64Phdr>,
    pub elf_shdr: Vec<Elf64Shdr>,
    pub elf_strtab: Vec<u8>,
}

impl Elf64 {
    pub fn parse(filename: &str) -> Result<Elf64, ScemuError> {
        let mut mem: Mem64 = Mem64::new();
        if !mem.load(&filename) {
          return Err(ScemuError::new("cannot open elf binary"));
        }
        let bin = mem.get_mem(); 

        let ehdr:Elf64Ehdr = Elf64Ehdr::parse(&bin);
        let mut ephdr:Vec<Elf64Phdr> = Vec::new();
        let mut eshdr:Vec<Elf64Shdr> = Vec::new();
        let mut off = ehdr.e_phoff as usize;

        for _ in 0..ehdr.e_phnum {
            let phdr:Elf64Phdr = Elf64Phdr::parse(&bin, off);
            ephdr.push(phdr);
            off += ehdr.e_phentsize as usize;
        }

        off = ehdr.e_shoff as usize;

        for _ in 0..ehdr.e_shnum {
            let shdr:Elf64Shdr = Elf64Shdr::parse(&bin, off);
            eshdr.push(shdr);
            off += ehdr.e_shentsize as usize;
        }

        let off_strtab = eshdr[ehdr.e_shstrndx as usize].sh_offset as usize;
        let sz_strtab = eshdr[ehdr.e_shstrndx as usize].sh_size as usize;
        let blob_strtab = bin[off_strtab..(off_strtab+sz_strtab)].to_vec();


        Ok(Elf64 {
          bin: bin,
          elf_hdr: ehdr,
          elf_phdr: ephdr,
          elf_shdr: eshdr,
          elf_strtab: blob_strtab,
        })
    }

    pub fn is_loadable(&self, addr:u64) -> bool {
        for phdr in &self.elf_phdr {
            if phdr.p_type == constants::PT_LOAD {
                if phdr.p_vaddr > 0 && (phdr.p_vaddr <= addr || addr <= (phdr.p_vaddr+phdr.p_memsz)) {
                    return true;
                }
            }
        }
        return false;
    }

    pub fn get_section_name(&self, offset:usize) -> String {
        let end = self.elf_strtab[offset..].iter().position(|&c| c == 0).unwrap_or(self.elf_strtab.len() - offset);
        let s = std::str::from_utf8(&self.elf_strtab[offset..offset + end]).expect("error reading elf64 shstrtab");
        return s.to_string();
    }

    pub fn load(&mut self, maps: &mut Maps, name:&str) {
        maps.clear();

        let hdr = maps.create_map("elf64.hdr");
        hdr.set_base(0x400000);
        hdr.set_size(0x200);
        hdr.write_bytes(0x400000, &self.bin[..0x200]);

        for shdr in &self.elf_shdr { 
            if self.is_loadable(shdr.sh_addr) {
                let map_name:String;
                let sname = self.get_section_name(shdr.sh_name as usize);
                if sname == ".text" {
                    map_name = "code".to_string();
                } else {
                    map_name = format!("{}{}", name, self.get_section_name(shdr.sh_name as usize));
                }
                println!("loading map {} 0x{:x} sz:{}", &map_name, shdr.sh_addr, shdr.sh_size);
                let mem = maps.create_map(&map_name);
                mem.set_base(shdr.sh_addr.into());
                mem.set_size(shdr.sh_size.into());

                let mut end_off = (shdr.sh_offset + shdr.sh_size) as usize;
                if end_off > self.bin.len() {
                    end_off = self.bin.len();
                }
    
                let segment = &self.bin[shdr.sh_offset as usize..end_off];
                //println!("reading from offset {} to {}", shdr.sh_offset, end_off); 
                mem.write_bytes(shdr.sh_addr, segment);
                //println!("loaded.");
            }
        }
    }

    pub fn get_dynamic(&self) -> Vec<String> {
        let mut libs:Vec<String> = Vec::new();

        for shdr in &self.elf_shdr {
            if self.get_section_name(shdr.sh_name as usize) == ".dynamic" {
                let mut off = shdr.sh_offset as usize;
                let mut off_strtab:u64 = 0;

                loop { 
                    let d_tag:u64 = read_u64_le!(self.bin, off);
                    let d_val:u64 = read_u64_le!(self.bin, off+8);

                    if d_tag == DT_NULL { break }
                    if d_tag == DT_STRTAB {
                        off_strtab = d_val;
                        break;
                    }
                    off += 16;
                }

                if off_strtab == 0 {
                    println!("dt_strtab not found");
                    return libs;
                }

                off = shdr.sh_offset as usize;
                loop {
                    let d_tag:u64 = read_u64_le!(self.bin, off);
                    let d_val:u64 = read_u64_le!(self.bin, off+8);

                    if d_tag == DT_NULL { break }
                    if d_tag == DT_NEEDED {
                        let off_lib = (off_strtab + d_val) as usize;
                        let off_lib_end = self.bin[off_lib..].iter().position(|&c| c == 0)
                            .expect("error searching on DT_STRTAB");
                        let lib_name = std::str::from_utf8(&self.bin[off_lib..off_lib + off_lib_end])
                            .expect("libname on DT_STRTAB is not utf-8");
                        libs.push(lib_name.to_string());
                    }
                    off += 16;
                }

                break;
            }
        }

        return libs;
    }

    pub fn is_elf64(filename:&str) -> bool {
        let mut fd = File::open(filename).expect("file not found");
        let mut raw = vec![0u8; 5];
        fd.read_exact(&mut raw).expect("couldnt read the file");

        if raw[0] == 0x7f &&
            raw[1] == b'E' &&
            raw[2] == b'L' && 
            raw[3] == b'F' &&
            raw[4] == ELFCLASS64 {
                return true;
        }
        false 
    }
}


#[derive(Debug)]
pub struct Elf64Ehdr {
    pub e_ident: [u8; EI_NIDENT],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

impl Elf64Ehdr {
    pub fn new() -> Elf64Ehdr { 
        Elf64Ehdr {
            e_ident: [0; EI_NIDENT],
            e_type: 0,
            e_machine: 0,
            e_version: 0,
            e_entry: 0,
            e_phoff: 0,
            e_shoff: 0,
            e_flags: 0,
            e_ehsize: 0,
            e_phentsize: 0,
            e_phnum: 0,
            e_shentsize: 0,
            e_shnum: 0,
            e_shstrndx: 0,
        }
    }

    pub fn parse(bin: &[u8]) -> Elf64Ehdr { 
        let off = EI_NIDENT as u64;
        Elf64Ehdr {
            e_ident: [
                read_u8!(bin, 0),
                read_u8!(bin, 1),
                read_u8!(bin, 2),
                read_u8!(bin, 3),
                read_u8!(bin, 4),
                read_u8!(bin, 5),
                read_u8!(bin, 6),
                read_u8!(bin, 7),
                read_u8!(bin, 8),
                read_u8!(bin, 9),
                read_u8!(bin, 10),
                read_u8!(bin, 11),
                read_u8!(bin, 12),
                read_u8!(bin, 13),
                read_u8!(bin, 14),
                read_u8!(bin, 15),
            ],
            e_type: read_u16_le!(bin, 16),
            e_machine: read_u16_le!(bin, 18),
            e_version: read_u32_le!(bin, 20),
            e_entry: read_u64_le!(bin, 24),
            e_phoff: read_u64_le!(bin, 32),
            e_shoff: read_u64_le!(bin, 40),
            e_flags: read_u32_le!(bin, 48),
            e_ehsize: read_u16_le!(bin, 52),
            e_phentsize: read_u16_le!(bin, 54),
            e_phnum: read_u16_le!(bin, 56),
            e_shentsize: read_u16_le!(bin, 58),
            e_shnum: read_u16_le!(bin, 60),
            e_shstrndx: read_u16_le!(bin, 62),
        }
    }
}

#[derive(Debug)]
pub struct Elf64Phdr {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

impl Elf64Phdr {
    pub fn parse(bin: &[u8], phoff: usize) -> Elf64Phdr {
        Elf64Phdr {
            p_type: read_u32_le!(bin, phoff),
            p_flags: read_u32_le!(bin, phoff+4),
            p_offset: read_u64_le!(bin, phoff+8),
            p_vaddr: read_u64_le!(bin, phoff+16),
            p_paddr: read_u64_le!(bin, phoff+24),
            p_filesz: read_u64_le!(bin, phoff+32),
            p_memsz: read_u64_le!(bin, phoff+40),
            p_align: read_u64_le!(bin, phoff+48),
        }
    }
}

#[derive(Debug)]
pub struct Elf64Shdr {
    pub sh_name: u32,
    pub sh_type: u32,
    pub sh_flags: u64,
    pub sh_addr: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u64,
    pub sh_entsize: u64,
}

impl Elf64Shdr {
    pub fn parse(bin: &[u8], shoff: usize) -> Elf64Shdr {
        Elf64Shdr {
            sh_name: read_u32_le!(bin, shoff),
            sh_type: read_u32_le!(bin, shoff+4),
            sh_flags: read_u64_le!(bin, shoff+8),
            sh_addr: read_u64_le!(bin, shoff+16),
            sh_offset: read_u64_le!(bin, shoff+24),
            sh_size: read_u64_le!(bin, shoff+32),
            sh_link: read_u32_le!(bin, shoff+40),
            sh_info: read_u32_le!(bin, shoff+44),
            sh_addralign: read_u64_le!(bin, shoff+48),
            sh_entsize: read_u64_le!(bin, 56),
        }
    }
}




