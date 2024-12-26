use super::err::MwemuError;
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



pub const EI_NIDENT:usize = 16;
pub const ELFCLASS32:u8 = 0x01;

#[derive(Debug)]
pub struct Elf32 {
    pub bin: Vec<u8>,
    pub elf_hdr: Elf32Ehdr,
    pub elf_phdr: Vec<Elf32Phdr>,
    pub elf_shdr: Vec<Elf32Shdr>,
}

impl Elf32 {
    pub fn parse(filename: &str) -> Result<Elf32, MwemuError> {
        let mut mem: Mem64 = Mem64::new();
        if !mem.load(&filename) {
            return Err(MwemuError::new("cannot open elf binary"));
        }
        let bin = mem.get_mem();

        let ehdr:Elf32Ehdr = Elf32Ehdr::parse(&bin);

        Ok(Elf32 {
            bin: bin,
            elf_hdr: ehdr,
            elf_phdr: Vec::new(),
            elf_shdr: Vec::new(),
        })
    }

    pub fn load(&mut self, maps: &mut Maps) {
        maps.clear();
        let mut off = self.elf_hdr.e_phoff as usize;
 
        for _ in 0..self.elf_hdr.e_phnum {
            let phdr:Elf32Phdr = Elf32Phdr::parse(&self.bin, off);
            self.elf_phdr.push(phdr);
            off += self.elf_hdr.e_phentsize as usize;
        }

        off = self.elf_hdr.e_shoff as usize;

        for _ in 0..self.elf_hdr.e_shnum {
            let shdr:Elf32Shdr = Elf32Shdr::parse(&self.bin, off);
            self.elf_shdr.push(shdr);
            off += self.elf_hdr.e_shentsize as usize;
        }

        for phdr in &self.elf_phdr {
            if phdr.p_type == constants::PT_LOAD {

                /*
                for shdr in &self.elf_shdr {
                    if shdr.sh_addr >= phdr.p_vaddr &&
                        shdr.sh_addr < phdr.p_vaddr+phdr.p_memsz {
                            let end = self.bin.iter().skip(off)
                                .position(|&x| x == 0x00).unwrap_or(0) + off;
                            let name = std::str::from_utf8(&self.bin[off..end]).unwrap();
                            log::info!("la seccion {} es pt_load", &name);

                    }
                }*/

                let mem = maps.create_map(&format!("code"), phdr.p_vaddr.into(), phdr.p_memsz.into()).expect("cannot create code map from load_programs elf32");
                if phdr.p_filesz >phdr.p_memsz {
                    log::info!("p_filesz > p_memsz bigger in file than in memory.");
                }
                log::info!("segment {} - {}", phdr.p_offset, (phdr.p_offset+phdr.p_filesz));
                let segment = &self.bin[phdr.p_offset as usize..
                    (phdr.p_offset + phdr.p_filesz) as usize];
                mem.write_bytes(phdr.p_vaddr.into(), segment);
            }
        }

    }

    pub fn is_elf32(filename:&str) -> bool {
        //log::info!("checking if elf32: {}", filename);
        let mut fd = File::open(filename).expect("file not found");
        let mut raw = vec![0u8; 5];
        fd.read_exact(&mut raw).expect("couldnt read the file");

        if raw[0] == 0x7f &&
            raw[1] == b'E' &&
            raw[2] == b'L' && 
            raw[3] == b'F' &&
            raw[4] == ELFCLASS32 {
                return true;
        }
        false 
    }
}

#[derive(Debug)]
pub struct Elf32Ehdr {
    pub e_ident: [u8; EI_NIDENT],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u32,
    pub e_phoff: u32,
    pub e_shoff: u32,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

impl Elf32Ehdr {
    pub fn new() -> Elf32Ehdr { 
        Elf32Ehdr {
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

    pub fn parse(bin: &[u8]) -> Elf32Ehdr { 
        let off = EI_NIDENT as u64;
        Elf32Ehdr {
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
            e_entry: read_u32_le!(bin, 24),
            e_phoff: read_u32_le!(bin, 28),
            e_shoff: read_u32_le!(bin, 32),
            e_flags: read_u32_le!(bin, 36),
            e_ehsize: read_u16_le!(bin, 40),
            e_phentsize: read_u16_le!(bin, 42),
            e_phnum: read_u16_le!(bin, 44),
            e_shentsize: read_u16_le!(bin, 46),
            e_shnum: read_u16_le!(bin, 48),
            e_shstrndx: read_u16_le!(bin, 50),
        }
    }
}

#[derive(Debug)]
pub struct Elf32Phdr {
    pub p_type: u32,
    pub p_offset: u32,
    pub p_vaddr: u32,
    pub p_paddr: u32,
    pub p_filesz: u32,
    pub p_memsz: u32,
    pub p_flags: u32,
    pub p_align: u32,
}

impl Elf32Phdr {
    pub fn parse(bin: &[u8], phoff: usize) -> Elf32Phdr {
        Elf32Phdr {
            p_type: read_u32_le!(bin, phoff),
            p_offset: read_u32_le!(bin, phoff+4),
            p_vaddr: read_u32_le!(bin, phoff+8),
            p_paddr: read_u32_le!(bin, phoff+12),
            p_filesz: read_u32_le!(bin, phoff+16),
            p_memsz: read_u32_le!(bin, phoff+20),
            p_flags: read_u32_le!(bin, phoff+24),
            p_align: read_u32_le!(bin, phoff+28),
        }
    }
}

#[derive(Debug)]
pub struct Elf32Shdr {
    pub sh_name: u32,
    pub sh_type: u32,
    pub sh_flags: u32,
    pub sh_addr: u32,
    pub sh_offset: u32,
    pub sh_size: u32,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u32,
    pub sh_entsize: u32,
}

impl Elf32Shdr {
    pub fn parse(bin: &[u8], shoff: usize) -> Elf32Shdr {
        Elf32Shdr {
            sh_name: read_u32_le!(bin, shoff),
            sh_type: read_u32_le!(bin, shoff+4),
            sh_flags: read_u32_le!(bin, shoff+8),
            sh_addr: read_u32_le!(bin, shoff+12),
            sh_offset: read_u32_le!(bin, shoff+16),
            sh_size: read_u32_le!(bin, shoff+20),
            sh_link: read_u32_le!(bin, shoff+24),
            sh_info: read_u32_le!(bin, shoff+28),
            sh_addralign: read_u32_le!(bin, shoff+32),
            sh_entsize: read_u32_le!(bin, 36),
        }
    }
}


