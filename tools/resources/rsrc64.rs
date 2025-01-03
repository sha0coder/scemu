/*
 * PE64 Structures and loader
 */

use crate::emu;
use crate::structures;
use crate::pe32;
use crate::pe32::PE32;
use crate::winapi64;
use std::fs::File;
use std::io::Read;
use std::str;

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

/*
macro_rules! write_u32_le {
    ($raw:expr, $off:expr, $val:expr) => {
        $raw[$off + 0] = ($val & 0x000000ff) as u8;
        $raw[$off + 1] = (($val & 0x0000ff00) >> 8) as u8;
        $raw[$off + 2] = (($val & 0x00ff0000) >> 16) as u8;
        $raw[$off + 3] = (($val & 0xff000000) >> 24) as u8;
    };
}*/

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

macro_rules! write_u64_le {
    ($raw:expr, $off:expr, $val:expr) => {
        $raw[$off + 0] = ($val & 0x00000000_000000ff) as u8;
        $raw[$off + 1] = (($val & 0x00000000_0000ff00) >> 8) as u8;
        $raw[$off + 2] = (($val & 0x00000000_00ff0000) >> 16) as u8;
        $raw[$off + 3] = (($val & 0x00000000_ff000000) >> 24) as u8;
        $raw[$off + 4] = (($val & 0x000000ff_00000000) >> 32) as u8;
        $raw[$off + 5] = (($val & 0x0000ff00_00000000) >> 40) as u8;
        $raw[$off + 6] = (($val & 0x00ff0000_00000000) >> 48) as u8;
        $raw[$off + 7] = (($val & 0xff000000_00000000) >> 56) as u8;
    };
}

/*
#[derive(Debug)]
pub struct ImageDataDirectory64 {
    pub virtual_address: u64,
    pub size: u32,
}

impl ImageDataDirectory64 {
    pub fn load(raw: &Vec<u8>, off: usize) -> ImageDataDirectory64 {
        ImageDataDirectory64 {
            virtual_address: read_u64_le!(raw, off),
            size: read_u32_le!(raw, off+8),
        }
    }

    pub fn print(&self) {
        log::info!("{:#x?}", self);
    }
}*/

const IMAGE_FILE_DLL: u16 = 0x2000;

#[derive(Debug)]
pub struct ImageOptionalHeader64 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    //pub base_of_data: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directory: Vec<pe32::ImageDataDirectory>, //  IMAGE_NUMBEROF_DIRECTORY_ENTRIES
}

impl ImageOptionalHeader64 {
    pub fn load(raw: &Vec<u8>, off: usize) -> ImageOptionalHeader64 {
        let mut dd: Vec<pe32::ImageDataDirectory> = Vec::new();
        let mut pos = 112; //+ 144;   //108;
        for i in 0..pe32::IMAGE_NUMBEROF_DIRECTORY_ENTRIES {
            let idd = pe32::ImageDataDirectory::load(raw, off + pos);
            //log::info!("{} 0x{:x} {}", i, idd.virtual_address, idd.size);
            dd.push(idd);
            pos += 8;
        }

        ImageOptionalHeader64 {
            magic: read_u16_le!(raw, off),
            major_linker_version: read_u8!(raw, off + 2),
            minor_linker_version: read_u8!(raw, off + 3),
            size_of_code: read_u32_le!(raw, off + 4),
            size_of_initialized_data: read_u32_le!(raw, off + 8),
            size_of_uninitialized_data: read_u32_le!(raw, off + 12),
            address_of_entry_point: read_u32_le!(raw, off + 16),
            base_of_code: read_u32_le!(raw, off + 20),
            //base_of_data: read_u32_le!(raw, off+24),
            image_base: read_u64_le!(raw, off + 24),
            section_alignment: read_u32_le!(raw, off + 32),
            file_alignment: read_u32_le!(raw, off + 36),
            major_operating_system_version: read_u16_le!(raw, off + 40),
            minor_operating_system_version: read_u16_le!(raw, off + 42),
            major_image_version: read_u16_le!(raw, off + 44),
            minor_image_version: read_u16_le!(raw, off + 46),
            major_subsystem_version: read_u16_le!(raw, off + 48),
            minor_subsystem_version: read_u16_le!(raw, off + 50),
            win32_version_value: read_u32_le!(raw, off + 52),
            size_of_image: read_u32_le!(raw, off + 56),
            size_of_headers: read_u32_le!(raw, off + 60),
            checksum: read_u32_le!(raw, off + 64),
            subsystem: read_u16_le!(raw, off + 68),
            dll_characteristics: read_u16_le!(raw, off + 70),
            size_of_stack_reserve: read_u64_le!(raw, off + 72),
            size_of_stack_commit: read_u64_le!(raw, off + 80),
            size_of_heap_reserve: read_u64_le!(raw, off + 88),
            size_of_heap_commit: read_u64_le!(raw, off + 94),
            loader_flags: read_u32_le!(raw, off + 102),
            number_of_rva_and_sizes: read_u32_le!(raw, off + 106),
            data_directory: dd,
        }
    }

    pub fn print(&self) {
        log::info!("{:#x?}", self);
    }
}

#[derive(Debug)]
pub struct TlsDirectory64 {
    tls_data_start: u64,
    tls_data_end: u64,
    tls_index: u64, // DS:[FS:[2Ch]] + tls_index *4
    tls_callbacks: u64,
    zero_fill_size: u32, // size = tls_data_end - tls_data_start + zero_fill_size
    characteristic: u32,
}

impl TlsDirectory64 {
    pub fn load(raw: &[u8], off: usize) -> TlsDirectory64 {
        TlsDirectory64 {
            tls_data_start: read_u64_le!(raw, off),
            tls_data_end: read_u64_le!(raw, off + 8),
            tls_index: read_u64_le!(raw, off + 16),
            tls_callbacks: read_u64_le!(raw, off + 24),
            zero_fill_size: read_u32_le!(raw, off + 32),
            characteristic: read_u32_le!(raw, off + 36),
        }
    }

    pub fn print(&self) {
        log::info!("{:#x?}", self);
    }
}

#[derive(Debug)]
pub struct DelayLoadIAT {
    name_ptr: u32,
    iat_addr: u64,
    bound_iat: u64,
}

impl DelayLoadIAT {
    fn load(raw: &[u8], off: usize) -> DelayLoadIAT {
        DelayLoadIAT {
            name_ptr: read_u32_le!(raw, off),
            iat_addr: read_u64_le!(raw, off + 4),
            bound_iat: read_u64_le!(raw, off + 8),
        }
    }
}

pub struct PE64 {
    pub raw: Vec<u8>,
    pub dos: pe32::ImageDosHeader,
    pub nt: pe32::ImageNtHeaders,
    pub fh: pe32::ImageFileHeader,
    pub opt: ImageOptionalHeader64,
    pub sect_hdr: Vec<pe32::ImageSectionHeader>,
    pub delay_load_dir: Vec<pe32::DelayLoadDirectory>,
    pub image_import_descriptor: Vec<pe32::ImageImportDescriptor>,
}

impl PE64 {
    pub fn is_pe64(filename: &str) -> bool {
        // log::info!("checking if pe64: {}", filename);
        let mut fd = File::open(filename).expect("file not found");
        let mut raw = vec![0u8; pe32::ImageDosHeader::size()];
        fd.read_exact(&mut raw).expect("couldnt read the file");
        let dos = pe32::ImageDosHeader::load(&raw, 0);

        if dos.e_magic != 0x5a4d {
            return false;
        }

        if dos.e_lfanew >= fd.metadata().unwrap().len() as u32 {
            return false;
        }

        true
    }

    pub fn load_from_raw(raw: &[u8]) -> PE64 {
        let dos = pe32::ImageDosHeader::load(&raw, 0);
        let nt = pe32::ImageNtHeaders::load(&raw, dos.e_lfanew as usize);
        let fh = pe32::ImageFileHeader::load(&raw, dos.e_lfanew as usize + 4);
        let opt = ImageOptionalHeader64::load(&raw.to_vec(), dos.e_lfanew as usize + 24);
        let dos = pe32::ImageDosHeader::load(&raw, 0);
        let nt = pe32::ImageNtHeaders::load(&raw, dos.e_lfanew as usize);
        let fh = pe32::ImageFileHeader::load(&raw, dos.e_lfanew as usize + 4);
        let opt = ImageOptionalHeader64::load(&raw.to_vec(), dos.e_lfanew as usize + 24);
        let mut sect: Vec<pe32::ImageSectionHeader> = Vec::new();

        let mut off = dos.e_lfanew as usize + 24 + fh.size_of_optional_header as usize;
        for i in 0..fh.number_of_sections {
            let s = pe32::ImageSectionHeader::load(&raw, off);
            sect.push(s);
            off += pe32::SECTION_HEADER_SZ;
        }

        let importd: pe32::ImageImportDirectory;
        let exportd: pe32::ImageExportDirectory;
        let import_va = opt.data_directory[pe32::IMAGE_DIRECTORY_ENTRY_IMPORT].virtual_address;
        let export_va = opt.data_directory[pe32::IMAGE_DIRECTORY_ENTRY_EXPORT].virtual_address;
        let delay_load_va =
            opt.data_directory[pe32::IMAGE_DIRECTORY_ENTRY_DELAY_LOAD].virtual_address;
        let mut import_off: usize;
        let mut delay_load_off: usize;

        let mut image_import_descriptor: Vec<pe32::ImageImportDescriptor> = Vec::new();
        let mut delay_load_dir: Vec<pe32::DelayLoadDirectory> = Vec::new();

        if delay_load_va > 0 {
            //log::info!("delay load detected!");
            delay_load_off = PE32::vaddr_to_off(&sect, delay_load_va) as usize;
            if delay_load_off > 0 {
                loop {
                    let mut delay_load = pe32::DelayLoadDirectory::load(&raw, delay_load_off);
                    //log::info!("{:#x?}", delay_load);
                    if delay_load.handle == 0 || delay_load.name_ptr == 0 {
                        break;
                    }

                    let off = PE32::vaddr_to_off(&sect, delay_load.name_ptr) as usize;
                    if off > raw.len() {
                        panic!("the delay_load.name of pe64 is out of buffer");
                    }
                    let libname = PE32::read_string(&raw, off);
                    delay_load.name = libname.to_string();
                    delay_load_dir.push(delay_load);
                    delay_load_off += pe32::DelayLoadDirectory::size();
                }
            }
        }

        if import_va > 0 {
            import_off = PE32::vaddr_to_off(&sect, import_va) as usize;

            if import_off > 0 {
                loop {
                    let mut iid = pe32::ImageImportDescriptor::load(&raw, import_off);
                    if iid.name_ptr == 0 {
                        break;
                    }
                    let off = PE32::vaddr_to_off(&sect, iid.name_ptr) as usize;
                    if off > raw.len() {
                        panic!("the name of pe64 iid is out of buffer");
                    }

                    let libname = PE32::read_string(&raw, off);
                    iid.name = libname.to_string();

                    image_import_descriptor.push(iid);
                    import_off += pe32::ImageImportDescriptor::size();
                }
            } else {
                //log::info!("no import directory at va 0x{:x}.", import_va);
            }
        } else {
            //log::info!("no import directory at va 0x{:x}", import_va);
        }

        PE64 {
            raw: raw.to_vec(),
            dos,
            fh,
            nt,
            opt,
            sect_hdr: sect,
            delay_load_dir,
            image_import_descriptor, //import_dir: importd,
                                     //export_dir: exportd,
        }
    }

    pub fn load(filename: &str) -> PE64 {
        //log::info!("loading pe64: {}", filename);
        let mut fd = File::open(filename).expect("pe64 binary not found");
        let mut raw: Vec<u8> = Vec::new();
        fd.read_to_end(&mut raw)
            .expect("couldnt read the pe64 binary");
        PE64::load_from_raw(&raw)
    }

    pub fn size(&self) -> u64 {
        self.raw.len() as u64
    }

    pub fn mem_size(&self) -> usize {
        let mut sz = 0;
        for i in 0..self.sect_hdr.len() {
            let sect = &self.sect_hdr[i];
            if sect.virtual_size > sect.size_of_raw_data {
                sz += sect.virtual_size as usize;
            } else {
                sz += sect.size_of_raw_data as usize;
            }
        }
        sz
    }

    pub fn is_dll(&self) -> bool {
        self.fh.characteristics & IMAGE_FILE_DLL != 0
    }

    pub fn get_raw(&self) -> &[u8] {
        &self.raw[0..self.raw.len()]
    }

    pub fn get_headers(&self) -> &[u8] {
        &self.raw[0..self.opt.size_of_headers as usize]
    }

    pub fn clear(&mut self) {
        self.raw.clear();
        self.sect_hdr.clear();
    }

    pub fn num_of_sections(&self) -> usize {
        self.sect_hdr.len()
    }

    pub fn get_section_ptr_by_name(&self, name: &str) -> Option<&[u8]> {
        for i in 0..self.sect_hdr.len() {
            if self.sect_hdr[i].get_name() == name {
                let off = self.sect_hdr[i].pointer_to_raw_data as usize;
                let sz = self.sect_hdr[i].virtual_size as usize;
                let section_ptr = &self.raw[off..off + sz];
                return Some(section_ptr);
            }
        }
        None
    }

    pub fn get_section(&self, id: usize) -> &pe32::ImageSectionHeader {
        &self.sect_hdr[id]
    }

    pub fn get_section_ptr(&self, id: usize) -> &[u8] {
        if id > self.sect_hdr.len() {
            panic!("/!\\ warning: invalid section id {}", id);
        }
        let off = self.sect_hdr[id].pointer_to_raw_data as usize;
        let sz = self.sect_hdr[id].size_of_raw_data as usize; //TODO: coger sz en disk
        if off + sz > self.raw.len() {
            log::info!(
                "/!\\ warning: id:{} name:{} raw sz:{} off:{} sz:{}  off+sz:{}",
                id,
                self.sect_hdr[id].get_name(),
                self.raw.len(),
                off,
                sz,
                off + sz
            );
            //sz = self.raw.len() - off - 1;
            if off > self.raw.len() {
                return &[];
            }
            return &self.raw[off..];
        }
        let section_ptr = &self.raw[off..off + sz];
        section_ptr
    }

    pub fn get_section_vaddr(&self, id: usize) -> u32 {
        self.sect_hdr[id].virtual_address
    }

    pub fn get_tls_callbacks(&self, vaddr: u32) -> Vec<u64> {
        // = PE32::vaddr_to_off(&self.sect_hdr, vaddr) as usize;
        let mut callbacks: Vec<u64> = Vec::new();
        //if tls_off == 0 {

        if self.opt.data_directory.len() < pe32::IMAGE_DIRECTORY_ENTRY_TLS {
            log::info!("/!\\ alert there is .tls section but not tls directory entry");
            return callbacks;
        }

        let entry_tls = self.opt.data_directory[pe32::IMAGE_DIRECTORY_ENTRY_TLS].virtual_address;
        let iat = self.opt.data_directory[pe32::IMAGE_DIRECTORY_ENTRY_IAT].virtual_address;
        let align = self.opt.file_alignment;

        //tls_off = (entry_tls - (iat + align)) as usize;
        let tls_off = PE32::vaddr_to_off(&self.sect_hdr, entry_tls) as usize;

        let tls = TlsDirectory64::load(&self.raw, tls_off);
        tls.print();

        //let mut cb_off = tls.tls_callbacks - iat as u64 - self.opt.image_base - align as u64;
        let mut cb_off = PE32::vaddr_to_off(&self.sect_hdr, (tls.tls_callbacks & 0xffff) as u32);
        loop {
            let callback: u64 = read_u64_le!(&self.raw, cb_off as usize);
            if callback == 0 {
                break;
            }
            log::info!("0x{:x} TLS Callback: 0x{:x}", cb_off, callback);
            callbacks.push(callback);
            cb_off += 8;
        }

        callbacks
    }

    pub fn delay_load_binding(&mut self, emu: &mut emu::Emu) {
        log::info!("Delay load binding started ...");
        for i in 0..self.delay_load_dir.len() {
            let dld = &self.delay_load_dir[i];
            if dld.name.is_empty() {
                continue;
            }
            if winapi64::kernel32::load_library(emu, &dld.name) == 0 {
                panic!("cannot found the library `{}` on maps64", &dld.name);
            }

            let mut off_name = PE32::vaddr_to_off(&self.sect_hdr, dld.name_table) as usize;
            let mut off_addr = PE32::vaddr_to_off(&self.sect_hdr, dld.address_table) as usize;

            loop {
                if self.raw.len() <= off_name + 4 || self.raw.len() <= off_addr + 4 {
                    break;
                }

                let hint = pe32::HintNameItem::load(&self.raw, off_name);
                let addr = read_u32_le!(self.raw, off_addr); // & 0b01111111_11111111_11111111_11111111;
                let off2 = PE32::vaddr_to_off(&self.sect_hdr, hint.func_name_addr) as usize;
                if off2 == 0 {
                    //|| addr < 0x100 {
                    off_name += pe32::HintNameItem::size();
                    off_addr += 8;
                    continue;
                }
                let func_name = PE32::read_string(&self.raw, off2 + 2);
                //log::info!("IAT: 0x{:x} {}!{}", addr, iim.name, func_name);

                let real_addr = winapi64::kernel32::resolve_api_name(emu, &func_name);
                if real_addr == 0 {
                    break;
                }
                /*
                if emu.cfg.verbose >= 1 {
                    log::info!("binded 0x{:x} {}", real_addr, func_name);
                }*/
                write_u64_le!(self.raw, off_addr, real_addr);

                off_name += pe32::HintNameItem::size();
                off_addr += 8;
            }
        }
        log::info!("delay load bound!");
    }

    pub fn iat_binding(&mut self, emu: &mut emu::Emu) {
        // https://docs.microsoft.com/en-us/archive/msdn-magazine/2002/march/inside-windows-an-in-depth-look-into-the-win32-portable-executable-file-format-part-2#Binding

        if emu.cfg.verbose >= 1 {
            log::info!(
                "IAT binding started image_import_descriptor.len() = {} ...",
                self.image_import_descriptor.len()
            );
        }

        for i in 0..self.image_import_descriptor.len() {
            let iim = &self.image_import_descriptor[i];

            if iim.name.is_empty() {
                continue;
            }
            if winapi64::kernel32::load_library(emu, &iim.name) == 0 {
                log::info!("cannot found the library {} on maps64/", &iim.name);
                return;
            }

            if iim.original_first_thunk == 0 {
                self.iat_binding_alternative(emu, iim.first_thunk);
            } else {
                self.iat_binding_original(emu, iim.original_first_thunk, iim.first_thunk);
            }

        }
        log::info!("IAT Bound.");
    }

    pub fn iat_binding_alternative(&mut self, emu: &mut emu::Emu, first_thunk: u32) {
        // this function is called for every DLL that in iat.

        let mut off = PE32::vaddr_to_off(&self.sect_hdr, first_thunk) as usize;
        let ordinal:u16;

        loop {
            let entry = read_u64_le!(self.raw, off); 
            if entry == 0 {
                break;
            }
            if (entry & 0x80000000_00000000) != 0 {
                ordinal = (entry & 0xFFFF) as u16;
                println!("---- ordinal: {}", ordinal);
                unimplemented!("third variation of iat binding not implemented");

            } else {
                let name_rva = entry as u32;
                let name_off = PE32::vaddr_to_off(&self.sect_hdr, name_rva) as usize;
                let api_name = PE32::read_string(&self.raw, name_off+2);

                let real_addr = winapi64::kernel32::resolve_api_name(emu, &api_name);
                if real_addr > 0 {
                    write_u64_le!(self.raw, off, real_addr); // patch the IAT to do the binding
                }
            }


            off += 8;
        }
    }

    pub fn iat_binding_original(&mut self, emu: &mut emu::Emu, original_first_thunk: u32, first_thunk: u32) {
            // this function is called for every DLL in iat.

            let mut off_name =
                PE32::vaddr_to_off(&self.sect_hdr, original_first_thunk) as usize;
            let mut off_addr = PE32::vaddr_to_off(&self.sect_hdr, first_thunk) as usize;
            let mut flipflop = false;

            loop {
                if self.raw.len() <= off_name + 4 || self.raw.len() <= off_addr + 8 {
                    break;
                }

                let hint = pe32::HintNameItem::load(&self.raw, off_name);
                let addr = read_u32_le!(self.raw, off_addr); // & 0b01111111_11111111_11111111_11111111;
                let off2 = PE32::vaddr_to_off(&self.sect_hdr, hint.func_name_addr) as usize;

                if off2 == 0 {
                    off_name += pe32::HintNameItem::size();
                    if flipflop {
                        break;
                    }
                    flipflop = true;
                    continue;
                }
                flipflop = false;
                let func_name = PE32::read_string(&self.raw, off2 + 2);
                //println!("resolving func_name: {}", func_name);
                let real_addr = winapi64::kernel32::resolve_api_name(emu, &func_name);
                if real_addr == 0 {
                    break;
                }

                /*if emu.cfg.verbose >= 1 {
                    log::info!("binded 0x{:x} {}", real_addr, func_name);
                }*/

                let fake_addr = read_u64_le!(self.raw, off_addr);

                //println!("writing real_addr: 0x{:x} {} 0x{:x} -> 0x{:x} ", off_addr, func_name, fake_addr, real_addr);
                write_u64_le!(self.raw, off_addr, real_addr);

                off_name += pe32::HintNameItem::size();
                off_addr += 8;
            }

    }

    pub fn import_addr_to_name(&self, paddr: u64) -> String {
        if paddr == 0 {
            return String::new();
        }

        for i in 0..self.image_import_descriptor.len() {
            let iim = &self.image_import_descriptor[i];

            if iim.name.is_empty() {
                continue;
            }

            // Walking function names.
            let mut off_name =
                PE32::vaddr_to_off(&self.sect_hdr, iim.original_first_thunk) as usize;

            //log::info!("----> 0x{:x}", iim.first_thunk);
            let mut off_addr = PE32::vaddr_to_off(&self.sect_hdr, iim.first_thunk) as usize;
            //off_addr += 8;

            loop {
                if self.raw.len() <= off_name + 4 || self.raw.len() <= off_addr + 8 {
                    break;
                }

                let hint = pe32::HintNameItem::load(&self.raw, off_name);
                let addr = read_u32_le!(self.raw, off_addr); // & 0b01111111_11111111_11111111_11111111;
                let off2 = PE32::vaddr_to_off(&self.sect_hdr, hint.func_name_addr) as usize;
                if off2 == 0 {
                    //|| addr < 0x100 {
                    off_name += pe32::HintNameItem::size();
                    //off_addr += 8;
                    continue;
                }

                if addr == paddr as u32 {
                    let func_name = PE32::read_string(&self.raw, off2 + 2);
                    return func_name;
                }

                off_name += pe32::HintNameItem::size();
                off_addr += 8;
            }
        }

        String::new()
    }

    pub fn locate_resource_data_entry(&self, rsrc: &[u8], off: usize, level: u32, type_id: Option<u32>, name_id: Option<u32>, type_name: Option<&str>, name: Option<&str>) -> Option<structures::ImageResourceDataEntry64> {
        if level >= 10 {
            return None;
        }

        let mut dir = structures::ImageResourceDirectory::new();
        dir.characteristics = read_u32_le!(rsrc, off);
        dir.time_date_stamp = read_u32_le!(rsrc, off + 4);
        dir.major_version = read_u16_le!(rsrc, off + 8);
        dir.minor_version = read_u16_le!(rsrc, off + 10);
        dir.number_of_named_entries = read_u16_le!(rsrc, off + 12);
        dir.number_of_id_entries = read_u16_le!(rsrc, off + 14);

        let entries = dir.number_of_named_entries + dir.number_of_id_entries;

        for i in 0..entries {
            let mut entry = structures::ImageResourceDirectoryEntry::new();
            let off2 = off + i as usize * 8 + structures::ImageResourceDirectory::size() as usize;
            entry.name_or_id = read_u32_le!(rsrc, off2);
            entry.data_or_directory = read_u32_le!(rsrc, off2 + 4);

            let matched:bool;

            if entry.is_id() {
                if level == 0 && type_id.is_some() && type_id.unwrap() == entry.get_name_or_id() {
                    println!("type_id matched");
                    matched = true;
                } else if level == 1 && name_id.is_some() && name_id.unwrap() == entry.get_name_or_id() {
                    println!("name_id matched");
                    matched = true;
                } else {
                    matched = false;
                }
            } else {
                if level == 0 && type_name.is_some() && type_name.unwrap() == self.get_resource_name(&entry) {
                    println!("type_name matched");
                    matched = true;
                } else if level == 1 && name.is_some() && name.unwrap() == self.get_resource_name(&entry) {
                    println!("name matched");
                    matched = true;
                } else {
                    matched = false;
                }
            }

            if matched {
                if entry.is_directory() {
                    return self.locate_resource_data_entry(rsrc, off2, level + 1, type_id, name_id, type_name, name);
                } else {
                    let mut data_entry = structures::ImageResourceDataEntry64::new();
                    let off = PE32::vaddr_to_off(&self.sect_hdr, entry.get_offset()) as usize;
                    data_entry.offset_to_data = read_u64_le!(self.raw, off);
                    data_entry.size = read_u64_le!(self.raw, off + 8);
                    data_entry.code_page = read_u64_le!(self.raw, off + 16);
                    data_entry.reserved = read_u64_le!(self.raw, off + 24);
            
                    return Some(data_entry);
                }
            }
        }

        None
    }

    pub fn get_resource(&self, type_id: Option<u32>, name_id: Option<u32>, type_name: Option<&str>, name: Option<&str>) -> Option<(u64, usize)> {
        // to query a resource, we need the type and name, and both could be a string or an id.
        // it resturn the address on memory of the resource but without the base address, the api will add it.
        
        let rsrc = self.get_section_ptr_by_name(".rsrc");
        if rsrc.is_none() {
            return None;
        }

        let rsrc = rsrc.unwrap();


        let data_entry = self.locate_resource_data_entry(rsrc, 0, 0, type_id, name_id, type_name, name);
        if data_entry.is_none() {
            return None;
        }
        let data_entry = data_entry.unwrap();
        let data_off = PE32::vaddr_to_off(&self.sect_hdr, data_entry.offset_to_data as u32) as usize - self.opt.image_base as usize;
        return Some((data_off as u64, data_entry.size as usize));
    }

    pub fn get_resource_name(&self, entry: &structures::ImageResourceDirectoryEntry) -> String {
        let off = PE32::vaddr_to_off(&self.sect_hdr, entry.get_name_or_id() as u32) as usize;
        let length = u16::from_le_bytes([self.raw[off], self.raw[off + 1]]) as usize;
        let string_start = off + 2;
        let utf16_data: Vec<u16> = (0..length)
            .map(|i| {
            let idx = string_start + i * 2;
            u16::from_le_bytes([self.raw[idx], self.raw[idx + 1]])
        }).collect(); 

        String::from_utf16_lossy(&utf16_data)
    }



}
