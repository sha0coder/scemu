use super::constants;
use super::err::MwemuError;
use super::maps::mem64::Mem64;
use crate::maps::Maps;
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

/*
macro_rules! write_u64_le {
    ($raw:expr, $off:expr, $val:expr) => {
        $raw[$off] = $val as u8;
        $raw[$off + 1] = ($val >> 8) as u8;
        $raw[$off + 2] = ($val >> 16) as u8;
        $raw[$off + 3] = ($val >> 24) as u8;
        $raw[$off + 4] = ($val >> 32) as u8;
        $raw[$off + 5] = ($val >> 40) as u8;
        $raw[$off + 6] = ($val >> 48) as u8;
        $raw[$off + 7] = ($val >> 56) as u8;
    };
}*/

pub const EI_NIDENT: usize = 16;
pub const ELFCLASS64: u8 = 0x02;
pub const DT_NEEDED: u64 = 1;
pub const DT_NULL: u64 = 0;
pub const DT_STRTAB: u64 = 5;
pub const STT_FUNC: u8 = 2;
pub const STT_OBJECT: u8 = 1;
pub const ELF64_DYN_BASE: u64 = 0x555555554000;
pub const ELF64_STA_BASE: u64 = 0x400000;
pub const LIBC_BASE: u64 = 0x7ffff7da7000;
pub const LD_BASE: u64 = 0x7ffff7fd2000;

#[derive(Debug)]
pub struct Elf64 {
    pub bin: Vec<u8>,
    pub elf_hdr: Elf64Ehdr,
    pub elf_phdr: Vec<Elf64Phdr>,
    pub elf_shdr: Vec<Elf64Shdr>,
    pub elf_strtab: Vec<u8>, // no sense, use offset instead repeat the blob
    pub init: Option<u64>,
    pub elf_dynsym: Vec<Elf64Sym>,
    pub elf_dynstr_off: u64,
    pub elf_got_off: u64,
}

impl Elf64 {
    pub fn parse(filename: &str) -> Result<Elf64, MwemuError> {
        let mut mem: Mem64 = Mem64::new();
        if !mem.load(filename) {
            return Err(MwemuError::new("cannot open elf binary"));
        }
        let bin = mem.get_mem();

        let ehdr: Elf64Ehdr = Elf64Ehdr::parse(&bin);
        let mut ephdr: Vec<Elf64Phdr> = Vec::new();
        let mut eshdr: Vec<Elf64Shdr> = Vec::new();
        let mut off = ehdr.e_phoff as usize;
        let dynsym: Vec<Elf64Sym> = Vec::new();

        // loading programs
        for _ in 0..ehdr.e_phnum {
            let phdr: Elf64Phdr = Elf64Phdr::parse(&bin, off);
            ephdr.push(phdr);
            off += ehdr.e_phentsize as usize;
        }

        off = ehdr.e_shoff as usize;

        // loading sections
        for _ in 0..ehdr.e_shnum {
            let shdr: Elf64Shdr = Elf64Shdr::parse(&bin, off);
            eshdr.push(shdr);
            off += ehdr.e_shentsize as usize;
        }

        let mut off_strtab: usize = 0;
        let mut sz_strtab: usize = 0;
        if (ehdr.e_shstrndx as usize) < eshdr.len() {
            off_strtab = eshdr[ehdr.e_shstrndx as usize].sh_offset as usize;
            sz_strtab = eshdr[ehdr.e_shstrndx as usize].sh_size as usize;
        }
        let mut blob_strtab: Vec<u8> = vec![];
        if off_strtab > 0 {
            blob_strtab = bin[off_strtab..(off_strtab + sz_strtab)].to_vec();
        }
        let dynstr: Vec<String> = Vec::new();

        Ok(Elf64 {
            bin,
            elf_hdr: ehdr,
            elf_phdr: ephdr,
            elf_shdr: eshdr,
            elf_strtab: blob_strtab,
            init: None,
            elf_dynsym: dynsym,
            elf_dynstr_off: 0,
            elf_got_off: 0,
        })
    }

    pub fn is_loadable(&self, addr: u64) -> bool {
        for phdr in &self.elf_phdr {
            if phdr.p_type == constants::PT_LOAD
                && phdr.p_vaddr > 0
                && (phdr.p_vaddr <= addr || addr <= (phdr.p_vaddr + phdr.p_memsz))
            {
                //log::info!("vaddr 0x{:x}", phdr.p_vaddr);
                return true;
            }
        }
        false
    }

    pub fn get_section_name(&self, offset: usize) -> String {
        let end = self.elf_strtab[offset..]
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(self.elf_strtab.len() - offset);
        let s = std::str::from_utf8(&self.elf_strtab[offset..offset + end])
            .expect("error reading elf64 shstrtab");
        s.to_string()
    }

    pub fn sym_get_addr_from_name(&self, name: &str) -> Option<u64> {
        for sym in self.elf_dynsym.iter() {
            log::info!("{} == {}", &sym.st_dynstr_name, name);
            if sym.st_dynstr_name == name {
                return Some(sym.st_value);
            }
        }
        None
    }

    pub fn sym_get_name_from_addr(&self, addr: u64) -> String {
        for sym in self.elf_dynsym.iter() {
            if sym.st_value == addr {
                return sym.st_dynstr_name.clone();
            }
        }
        String::new()
    }

    /*
    pub fn dynsym_offset_to_addr(&self, off: usize) -> u64 {
        for sym in self.elf_dynsym.iter() {
            if sym.st_name as usize == off {
                return
            }
        }
        return 0;
    }

    pub fn dynstr_name_to_offset(&self, name: &str) -> Option<usize> {
        for i in 0..self.elf_dynstr.len() {
            if name == self.elf_dynstr[i] {
                return Some(i);
            }
        }
        None
    }*/

    pub fn load_programs(&mut self, maps: &mut Maps, name: &str, is_lib: bool, dyn_link: bool) {
        let mut i = 0;
        for phdr in &self.elf_phdr {
            if phdr.p_type == constants::PT_LOAD {
                i += 1;

                let vaddr: u64;

                if is_lib {
                    if name.contains("libc") {
                        vaddr = phdr.p_vaddr + LIBC_BASE;
                    } else if name.contains("ld-linux") {
                        vaddr = phdr.p_vaddr + LD_BASE;
                    } else if dyn_link {
                        vaddr = phdr.p_vaddr + ELF64_DYN_BASE;
                    } else {
                        unreachable!("static with lib???");
                    }
                } else if dyn_link {
                    vaddr = phdr.p_vaddr + ELF64_DYN_BASE;
                } else {
                    vaddr = phdr.p_vaddr; // + ELF64_STA_BASE;
                }

                let map = maps
                    .create_map(&format!("{}_{}", name, i), vaddr, phdr.p_memsz)
                    .expect("cannot create map from load_programs elf64");
                let start = phdr.p_offset as usize;
                let end = (phdr.p_offset + phdr.p_filesz) as usize;

                map.write_bytes(vaddr, &self.bin[start..end]);
            }
        }
    }

    pub fn load(
        &mut self,
        maps: &mut Maps,
        name: &str,
        is_lib: bool,
        dynamic_linking: bool,
        force_base: u64,
    ) {
        if dynamic_linking {
            self.load_programs(maps, name, is_lib, dynamic_linking);
        } else {
            let mut elf64_base = ELF64_STA_BASE;
            if force_base != 0x3c0000 {
                elf64_base = force_base;
            }
            // elf executable need to map the header.
            let hdr = maps
                .create_map("elf64.hdr", elf64_base, 0x4000)
                .expect("cannot create elf64.hdr map");
            hdr.write_bytes(elf64_base, &self.bin[..0x4000]);
        }

        // pre-load .dynstr
        for shdr in &self.elf_shdr {
            let sname = self.get_section_name(shdr.sh_name as usize);
            if sname == ".dynstr" {
                self.elf_dynstr_off = shdr.sh_offset;
            }
        }

        // map sections
        for shdr in &self.elf_shdr {
            let sname = self.get_section_name(shdr.sh_name as usize);

            // get .got offset
            if sname == ".got" {
                self.elf_got_off = shdr.sh_offset;
            }

            // load dynsym
            if sname == ".dynsym" {
                let mut off = shdr.sh_offset as usize;

                for _ in 0..(shdr.sh_size / Elf64Sym::size() as u64) {
                    let mut sym = Elf64Sym::parse(&self.bin, off);

                    if (sym.get_st_type() == STT_FUNC || sym.get_st_type() == STT_OBJECT)
                        && sym.st_value > 0
                    {
                        let off2 = (self.elf_dynstr_off + sym.st_name as u64) as usize;
                        let end = self.bin[off2..]
                            .iter()
                            .position(|&c| c == 0)
                            .unwrap_or(self.bin.len());
                        if let Ok(string) = std::str::from_utf8(&self.bin[off2..(end + off2)]) {
                            sym.st_dynstr_name = string.to_string();
                        }

                        self.elf_dynsym.push(sym);
                    }
                    off += Elf64Sym::size();
                }
            }

            if !is_lib && !dynamic_linking {
                //TODO: clean this block since is_lib cases are not reachable.

                // map if its vaddr is on a PT_LOAD program
                if self.is_loadable(shdr.sh_addr) {
                    let map_name: String = if sname == ".text" && !is_lib {
                        //maps.exists_mapname("code") {
                        "code".to_string()
                    } else {
                        format!("{}{}", name, sname) //self.get_section_name(shdr.sh_name as usize));
                    };
                    if sname == ".init" {
                        self.init = Some(shdr.sh_addr);
                    }

                    //log::info!("loading map {} 0x{:x} sz:{}", &map_name, shdr.sh_addr, shdr.sh_size);
                    let base: u64;
                    if dynamic_linking {
                        if shdr.sh_addr < 0x8000 {
                            base = shdr.sh_addr + ELF64_DYN_BASE + 0x4000;
                        } else {
                            base = shdr.sh_addr + ELF64_DYN_BASE;
                        }
                    } else {
                        base = shdr.sh_addr;
                    }

                    let mem = maps
                        .create_map(&map_name, base, shdr.sh_size)
                        .expect("cannot create map from load_programs elf64");

                    let mut end_off = (shdr.sh_offset + shdr.sh_size) as usize;
                    if end_off > self.bin.len() {
                        end_off = self.bin.len();
                    }

                    let segment = &self.bin[shdr.sh_offset as usize..end_off];
                    if dynamic_linking {
                        if shdr.sh_addr < 0x8000 {
                            mem.write_bytes(shdr.sh_addr + ELF64_DYN_BASE + 0x4000, segment);
                        } else {
                            mem.write_bytes(shdr.sh_addr + ELF64_DYN_BASE, segment);
                        }
                    } else {
                        mem.write_bytes(shdr.sh_addr, segment);
                    }
                }
            }
        }
    }

    pub fn craft_got_sym(&self, addr: u64, got: &mut Mem64, sym_name: &str) {
        if let Some(mut sym_addr) = self.sym_get_addr_from_name(sym_name) {
            if sym_name.contains("libc") {
                sym_addr += LIBC_BASE;
            }
            log::info!("crafting got 0x{:x} <- 0x{:x} {}", addr, sym_addr, sym_name);
            got.write_qword(addr, sym_addr);
        } else {
            log::info!("crafting got error, no symbol {}", sym_name);
        }
    }

    // elf64_libc.craft_got(&maps, "elf64bin");

    pub fn craft_libc_got(&mut self, maps: &mut Maps, name: &str) {
        let got = maps.get_mem(&format!("{}.got", name));
        let got_base = got.get_base();

        self.craft_got_sym(got_base, got, "__GI___libc_free");
        self.craft_got_sym(got_base + (8 * 2), got, "__libc_start_main");
        self.craft_got_sym(got_base + (8 * 4), got, "__GI___libc_malloc");
        self.craft_got_sym(got_base + (8 * 6), got, "__cxa_finalize");
        self.craft_got_sym(got_base + (8 * 9), got, "_dl_runtime_resolve_xsavec");
    }

    pub fn get_dynamic(&self) -> Vec<String> {
        let mut libs: Vec<String> = Vec::new();

        for shdr in &self.elf_shdr {
            if self.get_section_name(shdr.sh_name as usize) == ".dynamic" {
                let mut off = shdr.sh_offset as usize;
                let mut off_strtab: u64 = 0;

                loop {
                    let d_tag: u64 = read_u64_le!(self.bin, off);
                    let d_val: u64 = read_u64_le!(self.bin, off + 8);

                    if d_tag == DT_NULL {
                        break;
                    }
                    if d_tag == DT_STRTAB {
                        if d_val > self.bin.len() as u64 {
                            off_strtab = d_val - self.elf_phdr[2].p_vaddr;
                        } else {
                            off_strtab = d_val;
                        }

                        break;
                    }
                    off += 16;
                }

                if off_strtab == 0 {
                    log::info!("dt_strtab not found");
                    return libs;
                }

                off = shdr.sh_offset as usize;
                loop {
                    let d_tag: u64 = read_u64_le!(self.bin, off);
                    let d_val: u64 = read_u64_le!(self.bin, off + 8);

                    if d_tag == DT_NULL {
                        break;
                    }
                    if d_tag == DT_NEEDED {
                        let off_lib = (off_strtab + d_val) as usize;
                        if off_lib > self.bin.len() {
                            off += 16;
                            continue;
                        }
                        let off_lib_end = self.bin[off_lib..]
                            .iter()
                            .position(|&c| c == 0)
                            .expect("error searching on DT_STRTAB");
                        let lib_name =
                            std::str::from_utf8(&self.bin[off_lib..off_lib + off_lib_end])
                                .expect("libname on DT_STRTAB is not utf-8");
                        log::info!("lib: {}", lib_name);
                        libs.push(lib_name.to_string());
                    }
                    off += 16;
                }

                break;
            }
        }

        libs
    }

    pub fn is_elf64(filename: &str) -> bool {
        //log::info!("checking if elf64: {}", filename);
        let mut fd = File::open(filename).expect("file not found");
        let mut raw = vec![0u8; 5];
        fd.read_exact(&mut raw).expect("couldnt read the file");

        if raw[0] == 0x7f
            && raw[1] == b'E'
            && raw[2] == b'L'
            && raw[3] == b'F'
            && raw[4] == ELFCLASS64
        {
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
            p_flags: read_u32_le!(bin, phoff + 4),
            p_offset: read_u64_le!(bin, phoff + 8),
            p_vaddr: read_u64_le!(bin, phoff + 16),
            p_paddr: read_u64_le!(bin, phoff + 24),
            p_filesz: read_u64_le!(bin, phoff + 32),
            p_memsz: read_u64_le!(bin, phoff + 40),
            p_align: read_u64_le!(bin, phoff + 48),
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
            sh_type: read_u32_le!(bin, shoff + 4),
            sh_flags: read_u64_le!(bin, shoff + 8),
            sh_addr: read_u64_le!(bin, shoff + 16),
            sh_offset: read_u64_le!(bin, shoff + 24),
            sh_size: read_u64_le!(bin, shoff + 32),
            sh_link: read_u32_le!(bin, shoff + 40),
            sh_info: read_u32_le!(bin, shoff + 44),
            sh_addralign: read_u64_le!(bin, shoff + 48),
            sh_entsize: read_u64_le!(bin, 56),
        }
    }
}

#[derive(Debug)]
pub struct Elf64Sym {
    pub st_dynstr_name: String,
    pub st_name: u32,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: u16,
    pub st_value: u64,
    pub st_size: u64,
}

impl Elf64Sym {
    pub fn parse(bin: &[u8], off: usize) -> Elf64Sym {
        Elf64Sym {
            st_dynstr_name: String::new(),
            st_name: read_u32_le!(bin, off),
            st_info: read_u8!(bin, off + 4),
            st_other: read_u8!(bin, off + 5),
            st_shndx: read_u16_le!(bin, off + 6),
            st_value: read_u64_le!(bin, off + 8),
            st_size: read_u64_le!(bin, off + 16),
        }
    }

    pub fn size() -> usize {
        24
    }

    pub fn get_st_type(&self) -> u8 {
        self.st_info & 0x0f
    }
}
