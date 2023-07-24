/*
 * PE64 Structures and loader
 */

use crate::emu;
use crate::emu::pe32;
use crate::emu::pe32::PE32;
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

macro_rules! write_u32_le {
    ($raw:expr, $off:expr, $val:expr) => {
        $raw[$off + 0] = ($val & 0x000000ff) as u8;
        $raw[$off + 1] = (($val & 0x0000ff00) >> 8) as u8;
        $raw[$off + 2] = (($val & 0x00ff0000) >> 16) as u8;
        $raw[$off + 3] = (($val & 0xff000000) >> 24) as u8;
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
      $raw[$off+0]  = ($val & 0x00000000_000000ff) as u8;
      $raw[$off+1] = (($val & 0x00000000_0000ff00) >> 8) as u8;
      $raw[$off+2] = (($val & 0x00000000_00ff0000) >> 16) as u8;
      $raw[$off+3] = (($val & 0x00000000_ff000000) >> 24) as u8;
      $raw[$off+4] = (($val & 0x000000ff_00000000) >> 32) as u8;
      $raw[$off+5] = (($val & 0x0000ff00_00000000) >> 40) as u8;
      $raw[$off+6] = (($val & 0x00ff0000_00000000) >> 48) as u8;
      $raw[$off+7] = (($val & 0xff000000_00000000) >> 56) as u8;
    }
}*/

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
        println!("{:#x?}", self);
    }
}*/

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
            //println!("{} 0x{:x} {}", i, idd.virtual_address, idd.size);
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
        println!("{:#x?}", self);
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
    pub fn load(raw: &Vec<u8>, off: usize) -> TlsDirectory64 {
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
        println!("{:#x?}", self);
    }
}

pub struct PE64 {
    raw: Vec<u8>,
    pub dos: pe32::ImageDosHeader,
    pub nt: pe32::ImageNtHeaders,
    pub fh: pe32::ImageFileHeader,
    pub opt: ImageOptionalHeader64,
    sect_hdr: Vec<pe32::ImageSectionHeader>,
    pub image_import_descriptor: Vec<pe32::ImageImportDescriptor>,
}

impl PE64 {
    pub fn is_pe64(filename: &str) -> bool {
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

        return true;
    }

    pub fn load(filename: &str) -> PE64 {
        let mut fd = File::open(filename).expect("pe64 binary not found");
        let mut raw: Vec<u8> = Vec::new();
        fd.read_to_end(&mut raw)
            .expect("couldnt read the pe64 binary");

        let dos = pe32::ImageDosHeader::load(&raw, 0);
        let nt = pe32::ImageNtHeaders::load(&raw, dos.e_lfanew as usize);
        let fh = pe32::ImageFileHeader::load(&raw, dos.e_lfanew as usize + 4);
        let opt = ImageOptionalHeader64::load(&raw, dos.e_lfanew as usize + 24);
        let mut sect: Vec<pe32::ImageSectionHeader> = Vec::new();

        let mut off = dos.e_lfanew as usize + 264;
        for i in 0..fh.number_of_sections {
            let s = pe32::ImageSectionHeader::load(&raw, off);
            sect.push(s);
            off += pe32::SECTION_HEADER_SZ;
        }

        let importd: pe32::ImageImportDirectory;
        let exportd: pe32::ImageExportDirectory;
        let import_va = opt.data_directory[pe32::IMAGE_DIRECTORY_ENTRY_IMPORT].virtual_address;
        let export_va = opt.data_directory[pe32::IMAGE_DIRECTORY_ENTRY_EXPORT].virtual_address;
        let mut import_off: usize;

        let mut image_import_descriptor: Vec<pe32::ImageImportDescriptor> = Vec::new();

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
                //println!("no import directory at va 0x{:x}.", import_va);
            }
        } else {
            //println!("no import directory at va 0x{:x}", import_va);
        }

        PE64 {
            raw: raw,
            dos: dos,
            fh: fh,
            nt: nt,
            opt: opt,
            sect_hdr: sect,
            image_import_descriptor: image_import_descriptor, //import_dir: importd,
                                                              //export_dir: exportd,
        }
    }

    pub fn get_raw(&self) -> &[u8] {
        return &self.raw[0..self.raw.len()];
    }

    pub fn get_headers(&self) -> &[u8] {
        return &self.raw[0..self.opt.size_of_headers as usize];
    }

    pub fn clear(&mut self) {
        self.raw.clear();
        self.sect_hdr.clear();
    }

    pub fn num_of_sections(&self) -> usize {
        return self.sect_hdr.len();
    }

    pub fn get_section_ptr_by_name(&self, name: &str) -> &[u8] {
        for i in 0..self.sect_hdr.len() {
            if self.sect_hdr[i].get_name() == name {
                let off = self.sect_hdr[i].pointer_to_raw_data as usize;
                let sz = self.sect_hdr[i].virtual_size as usize;
                let section_ptr = &self.raw[off..off + sz];
                return section_ptr;
            }
        }
        panic!("section name {} not found", name);
        //return &[];
    }

    pub fn get_section(&self, id: usize) -> &pe32::ImageSectionHeader {
        return &self.sect_hdr[id];
    }

    pub fn get_section_ptr(&self, id: usize) -> &[u8] {
        let off = self.sect_hdr[id].pointer_to_raw_data as usize;
        let mut sz = self.sect_hdr[id].size_of_raw_data as usize; //TODO: coger sz en disk no en va
        if off + sz >= self.raw.len() {
            println!(
                "/!\\ warning: raw sz:{} off:{} sz:{}  off+sz:{}",
                self.raw.len(),
                off,
                sz,
                off + sz
            );
            sz = self.raw.len() - off - 1;
        }
        let section_ptr = &self.raw[off..off + sz];
        return section_ptr;
    }

    pub fn get_section_vaddr(&self, id: usize) -> u32 {
        return self.sect_hdr[id].virtual_address;
    }

    pub fn get_tls_callbacks(&self, vaddr: u32) -> Vec<u64> {
        let tls_off; // = PE32::vaddr_to_off(&self.sect_hdr, vaddr) as usize;
        let mut callbacks: Vec<u64> = Vec::new();
        //if tls_off == 0 {

        if self.opt.data_directory.len() < pe32::IMAGE_DIRECTORY_ENTRY_TLS {
            println!("/!\\ alert there is .tls section but not tls directory entry");
            return callbacks;
        }

        let entry_tls = &self.opt.data_directory[pe32::IMAGE_DIRECTORY_ENTRY_TLS].virtual_address;
        let iat = self.opt.data_directory[pe32::IMAGE_DIRECTORY_ENTRY_IAT].virtual_address;
        let align = self.opt.file_alignment;

        tls_off = (entry_tls - (iat + align)) as usize;
        //println!("tls_off = (entry_tls - (iat + align))");
        //println!("{:x} - ({:x} + {:x})", entry_tls, iat, align);
        //}

        //println!("vaddr: 0x{:x} tls_off 0x{:x} {}", vaddr, tls_off, tls_off);
        let tls = TlsDirectory64::load(&self.raw, tls_off);
        tls.print();

        let mut cb_off = tls.tls_callbacks - iat as u64 - self.opt.image_base - align as u64;
        loop {
            let callback: u64 = read_u64_le!(&self.raw, cb_off as usize);
            if callback == 0 {
                break;
            }
            println!("TLS Callback: 0x{:x}", callback);
            callbacks.push(callback);
            cb_off += 8;
        }

        callbacks
    }

    pub fn iat_binding(&mut self, emu: &mut emu::Emu) {
        // https://docs.microsoft.com/en-us/archive/msdn-magazine/2002/march/inside-windows-an-in-depth-look-into-the-win32-portable-executable-file-format-part-2#Binding

        println!("IAT binding started ...");
        for i in 0..self.image_import_descriptor.len() {
            let iim = &self.image_import_descriptor[i];
            //println!("import: {}", iim.name);

            if emu::winapi64::kernel32::load_library(emu, &iim.name) == 0 {
                panic!("cannot found the library {} on maps64/", &iim.name);
            }

            // Walking function names.
            let mut off_name =
                PE32::vaddr_to_off(&self.sect_hdr, iim.original_first_thunk) as usize;
            let mut off_addr = PE32::vaddr_to_off(&self.sect_hdr, iim.first_thunk) as usize;

            loop {
                let hint = pe32::HintNameItem::load(&self.raw, off_name);
                if hint.func_name_addr == 0 {
                    break;
                }
                let addr = read_u32_le!(self.raw, off_addr); // & 0b01111111_11111111_11111111_11111111;
                let off2 = PE32::vaddr_to_off(&self.sect_hdr, hint.func_name_addr) as usize;
                if off2 == 0 {
                    //|| addr < 0x100 {
                    off_name += pe32::HintNameItem::size();
                    off_addr += 4;
                    continue;
                }
                let func_name = PE32::read_string(&self.raw, off2 + 2);
                //println!("0x{:x} {}!{}", addr, iim.name, func_name);

                let real_addr = emu::winapi64::kernel32::resolve_api_name(emu, &func_name);
                //println!("real addr: 0x{:x}", real_addr);
                if emu.cfg.verbose >= 1 {
                    println!("binded 0x{:x} {}", real_addr, func_name);
                }

                write_u32_le!(self.raw, off_addr, real_addr);

                off_name += pe32::HintNameItem::size();
                off_addr += 4;
            }
        }
        println!("IAT Bound.");
    }
}
