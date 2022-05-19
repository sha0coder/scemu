/*
 * PE32 Structures and loader
*/

use std::str;

macro_rules! read_u8 {
    ($raw:expr, $off:expr) => {
        $raw[$off]
    }
}

macro_rules! read_u16_le {
    ($raw:expr, $off:expr) => {
        (($raw[$off+1] as u16) << 8) | ($raw[$off] as u16)
    }
}

macro_rules! read_u32_le {
    ($raw:expr, $off:expr) => {
          (($raw[$off+3] as u32) << 24) | (($raw[$off+2] as u32) << 16) | (($raw[$off+1] as u32) << 8) | ($raw[$off] as u32)
    }
}

pub const IMAGE_DOS_SIGNATURE:u16 = 0x5A4D;
pub const IMAGE_OS2_SIGNATURE:u16 = 0x544E;
pub const IMAGE_OS2_SIGNATURE_LE:u16 = 0x45AC;
pub const IMAGE_NT_SIGNATURE:u32 = 0x00004550;
pub const IMAGE_SIZEOF_FILE_HEADER:u8 = 20;
pub const IMAGE_NUMBEROF_DIRECTORY_ENTRIES:usize = 16;
pub const SECTION_HEADER_SZ:u8 = 40;

pub const IMAGE_DIRECTORY_ENTRY_EXPORT:u8 = 0;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT:u8 = 1;
pub const IMAGE_DIRECTORY_ENTRY_RESOURCE:u8 = 2;
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION:u8 = 3;
pub const IMAGE_DIRECTORY_ENTRY_SECURITY:u8 = 4;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC:u8 = 5;
pub const IMAGE_DIRECTORY_ENTRY_DEBUG:u8 = 6;
pub const IMAGE_DIRECTORY_ENTRY_COPYRIGHT:u8 = 7;
pub const IMAGE_DIRECTORY_ENTRY_GLOBALPTR:u8 = 8;
pub const IMAGE_DIRECTORY_ENTRY_TLS:u8 = 9;
pub const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:u8 = 10;

pub const IMAGE_SIZEOF_SHORT_NAME:usize = 8;
pub const IMAGE_DEBUG_TYPE_UNKNOWN:u8 = 0;
pub const IMAGE_DEBUG_TYPE_COFF:u8 = 1;
pub const IMAGE_DEBUG_TYPE_CODEVIEW:u8 = 2;
pub const IMAGE_DEBUG_TYPE_FPO:u8 = 3;
pub const IMAGE_DEBUG_TYPE_MISC:u8 = 4;


#[derive(Debug)]
pub struct ImageDosHeader {
    pub e_magic: u16,		// Magic number
	pub e_cblp: u16, 		// Bytes on last page of file
	pub e_cp: u16,		    // Pages in file
 	pub e_crlc: u16, 		// Relocations
 	pub e_cparhdr: u16,	    // Size of header in paragraphs
 	pub e_minalloc: u16,    // Minimum extra paragraphs needed
 	pub e_maxalloc: u16,    // Maximum extra paragraphs needed
  	pub e_ss: u16,		    // Initial (relative) SS value
  	pub e_sp: u16,		    // Initial SP value
 	pub e_csum: u16,	    // Checksum
 	pub e_ip: u16,		    // Initial IP value
 	pub e_cs: u16,		    // Initial (relative) CS value
	pub e_lfarlc: u16,	    // File address of relocation table
	pub e_ovno: u16,	    // Overlay number
	pub e_res: [u16;4],	    // Reserved words
	pub e_oemid: u16,		// OEM identifier (for e_oeminfo)
	pub e_oeminfo: u16,	    // OEM information; e_oemid specific
	pub e_res2:	[u16;10],	// Reserved words
	pub e_lfanew: u32,	    // File address of new exe header
}

impl ImageDosHeader {
    pub fn load(raw: &Vec<u8>, off: usize) -> ImageDosHeader {
        ImageDosHeader {
            e_magic: read_u16_le!(raw, off),
            e_cblp: read_u16_le!(raw, off+2),
            e_cp: read_u16_le!(raw, off+4),
            e_crlc: read_u16_le!(raw, off+6),
            e_cparhdr: read_u16_le!(raw, off+8),
            e_minalloc: read_u16_le!(raw, off+10),
            e_maxalloc: read_u16_le!(raw, off+12),
            e_ss: read_u16_le!(raw, off+14),
            e_sp: read_u16_le!(raw, off+16),
            e_csum: read_u16_le!(raw, off+18),
            e_ip: read_u16_le!(raw, off+20),  
            e_cs: read_u16_le!(raw, off+22),
            e_lfarlc: read_u16_le!(raw, off+24),
            e_ovno: read_u16_le!(raw, off+26),
            e_res: [read_u16_le!(raw, off+28), read_u16_le!(raw, off+30), read_u16_le!(raw, off+32), read_u16_le!(raw, off+34)], 
            e_oemid: read_u16_le!(raw, off+36),
            e_oeminfo: read_u16_le!(raw, off+38),
            e_res2: [0,0,0,0,0,0,0,0,0,0],
            e_lfanew: read_u32_le!(raw, off+60),
        }
    }

    pub fn print(&self) {
        println!("{:#x?}", self);
    }
}


#[derive(Debug)]
pub struct ImageNtHeaders {
    pub signature: u32,
}

impl ImageNtHeaders {
    pub fn load(raw: &Vec<u8>, off: usize) -> ImageNtHeaders {
        ImageNtHeaders {
            signature: read_u32_le!(raw, off),
        }
    }

    pub fn print(&self) {
        println!("{:#x?}", self);
    }
}


#[derive(Debug)]
pub struct ImageFileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

impl ImageFileHeader {
    pub fn load(raw: &Vec<u8>, off: usize) -> ImageFileHeader {
        ImageFileHeader {
            machine: read_u16_le!(raw, off),
            number_of_sections: read_u16_le!(raw, off+2),
            time_date_stamp: read_u32_le!(raw, off+4),
            pointer_to_symbol_table: read_u32_le!(raw, off+8),
            number_of_symbols: read_u32_le!(raw, off+12),
            size_of_optional_header: read_u16_le!(raw, off+16),
            characteristics: read_u16_le!(raw, off+18),
        }
    }

    pub fn print(&self) {
        println!("{:#x?}", self);
    }
}


#[derive(Debug)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

impl ImageDataDirectory {
    pub fn load(raw: &Vec<u8>, off: usize) -> ImageDataDirectory {
        ImageDataDirectory {
            virtual_address: read_u32_le!(raw, off),
            size: read_u32_le!(raw, off+4),
        }
    }

    pub fn print(&self) {
        println!("{:#x?}", self);
    }
}


#[derive(Debug)]
pub struct ImageOptionalHeader {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: u32,
    pub image_base: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub reserved1: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u32,
    pub size_of_stack_commit: u32,
    pub size_of_heap_reserve: u32,
    pub size_of_heap_commit: u32,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directory: Vec<ImageDataDirectory> //  IMAGE_NUMBEROF_DIRECTORY_ENTRIES
}

impl ImageOptionalHeader {
    pub fn load(raw: &Vec<u8>, off: usize) -> ImageOptionalHeader {
        let mut dd: Vec<ImageDataDirectory> = Vec::new();
        let mut pos = 96;
        for i in 0..IMAGE_NUMBEROF_DIRECTORY_ENTRIES {
              dd.push( ImageDataDirectory::load(raw, off+pos) );
              pos += 8;
        }

        ImageOptionalHeader {
            magic: read_u16_le!(raw, off),
            major_linker_version: read_u8!(raw, off+2),
            minor_linker_version: read_u8!(raw, off+3),
            size_of_code: read_u32_le!(raw, off+4),
            size_of_initialized_data: read_u32_le!(raw, off+8),
            size_of_uninitialized_data: read_u32_le!(raw, off+12),
            address_of_entry_point: read_u32_le!(raw, off+16),
            base_of_code: read_u32_le!(raw, off+20),
            base_of_data: read_u32_le!(raw, off+24),
            image_base: read_u32_le!(raw, off+28),
            section_alignment: read_u32_le!(raw, off+32),
            file_alignment: read_u32_le!(raw, off+36),
            major_operating_system_version: read_u16_le!(raw, off+40),
            minor_operating_system_version: read_u16_le!(raw, off+42),
            major_image_version: read_u16_le!(raw, off+44),
            minor_image_version: read_u16_le!(raw, off+46),
            major_subsystem_version: read_u16_le!(raw, off+48),
            minor_subsystem_version: read_u16_le!(raw, off+50),
            reserved1: read_u32_le!(raw, off+52),
            size_of_image: read_u32_le!(raw, off+56),
            size_of_headers: read_u32_le!(raw, off+60),
            checksum: read_u32_le!(raw, off+64),
            subsystem: read_u16_le!(raw, off+68),
            dll_characteristics: read_u16_le!(raw, off+70),
            size_of_stack_reserve: read_u32_le!(raw, off+72),
            size_of_stack_commit: read_u32_le!(raw, off+76),
            size_of_heap_reserve: read_u32_le!(raw, off+80),
            size_of_heap_commit: read_u32_le!(raw, off+84),
            loader_flags: read_u32_le!(raw, off+88),
            number_of_rva_and_sizes: read_u32_le!(raw, off+92),
            data_directory: dd,
        }
    }

    pub fn print(&self) {
        println!("{:#x?}", self);
    }
}


#[derive(Debug)]
pub struct ImageSectionHeader {
    pub name: [u8;IMAGE_SIZEOF_SHORT_NAME],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

impl ImageSectionHeader {
    pub fn load(raw: &Vec<u8>, off: usize) -> ImageSectionHeader {
        let mut name:[u8;IMAGE_SIZEOF_SHORT_NAME] = [0;IMAGE_SIZEOF_SHORT_NAME];
        for i in off..off+IMAGE_SIZEOF_SHORT_NAME {
            name[i] = raw[i];
        }

        let off2 = off + IMAGE_SIZEOF_SHORT_NAME;

        ImageSectionHeader {
            name: name,
            virtual_size: read_u32_le!(raw, off2),
            virtual_address: read_u32_le!(raw, off2+4),
            size_of_raw_data: read_u32_le!(raw, off2+8),
            pointer_to_raw_data: read_u32_le!(raw, off2+12),
            pointer_to_relocations: read_u32_le!(raw, off2+16),
            pointer_to_linenumbers: read_u32_le!(raw, off2+20),
            number_of_relocations: read_u16_le!(raw, off2+24),
            number_of_linenumbers: read_u16_le!(raw, off2+26),
            characteristics: read_u32_le!(raw, off2+28),
        }
    }

    pub fn get_name(&self) -> String {
        let s = match str::from_utf8(&self.name) {
            Ok(v) => v,
            Err(_) => "",
        };

        s.to_string()
    }
    
    pub fn print(&self) {
        println!("{:#x?}", self);
    }
}







