use atty::Stream;
use csv::ReaderBuilder;
use iced_x86::{
    Decoder, DecoderOptions, Formatter, Instruction, InstructionInfoFactory, IntelFormatter,
    MemorySize, Mnemonic, OpKind, Register,
};
use std::io::Write as _;
use std::collections::BTreeMap;
use std::fs::File;
use std::sync::atomic;
use std::sync::Arc;
use std::time::Instant;

use crate::config::Config;
use crate::banzai::Banzai;
use crate::breakpoint::Breakpoint;
use crate::colors::Colors;
use crate::console::Console;
use crate::eflags::Eflags;
use crate::elf32::Elf32;
use crate::elf64::Elf64;
use crate::err::MwemuError;
use crate::flags::Flags;
use crate::fpu::FPU;
use crate::hooks::Hooks;
use crate::maps::Maps;
use crate::pe32::PE32;
use crate::pe64::PE64;
use crate::peb32;
use crate::peb64;
use crate::engine;
use crate::constants;
use crate::winapi32;
use crate::winapi64;
use crate::regs64::Regs64;
use crate::elf64;
use crate::regs64;
use crate::exception;
use crate::structures;
use crate::structures::MemoryOperation;
use crate::{get_bit, set_bit, to32};

pub struct Emu {
    pub regs: Regs64,
    pub pre_op_regs: Regs64,
    pub post_op_regs: Regs64,
    pub flags: Flags,
    pub pre_op_flags: Flags,
    pub post_op_flags: Flags,
    pub eflags: Eflags,
    pub fpu: FPU,
    pub maps: Maps,
    pub hooks: Hooks,
    pub exp: u64,
    pub break_on_alert: bool,
    pub bp: Breakpoint,
    pub seh: u64,
    pub veh: u64,
    pub feh: u64,
    pub eh_ctx: u32,
    pub cfg: Config,
    pub colors: Colors,
    pub pos: u64,
    pub force_break: bool,
    pub force_reload: bool,
    pub tls_callbacks: Vec<u64>,
    pub tls32: Vec<u32>,
    pub tls64: Vec<u64>,
    pub fls: Vec<u32>,
    pub out: String,
    pub instruction: Option<Instruction>,
    pub decoder_position: usize,
    pub memory_operations: Vec<MemoryOperation>,
    pub main_thread_cont: u64,
    pub gateway_return: u64,
    pub is_running: Arc<atomic::AtomicU32>,
    pub break_on_next_cmp: bool,
    pub break_on_next_return: bool,
    pub filename: String,
    pub enabled_ctrlc: bool,
    pub run_until_ret: bool,
    pub running_script: bool,
    pub banzai: Banzai,
    pub mnemonic: String,
    pub dbg: bool,
    pub linux: bool,
    pub fs: BTreeMap<u64, u64>,
    pub now: Instant,
    pub skip_apicall: bool,
    pub its_apicall: Option<u64>,
    pub last_instruction_size: usize,
    pub pe64: Option<PE64>,
    pub pe32: Option<PE32>,
    pub rep: Option<u64>,
    pub tick: usize,
    pub trace_file: Option<File>,
}

impl Default for Emu {
    fn default() -> Self {
        Self::new()
    }
}

impl Emu {
    pub fn new() -> Emu {
        Emu {
            regs: Regs64::new(),
            pre_op_regs: Regs64::new(),
            post_op_regs: Regs64::new(),
            flags: Flags::new(),
            pre_op_flags: Flags::new(),
            post_op_flags: Flags::new(),
            eflags: Eflags::new(),
            fpu: FPU::new(),
            maps: Maps::new(),
            hooks: Hooks::new(),
            exp: 0,
            break_on_alert: false,
            bp: Breakpoint::new(),
            seh: 0,
            veh: 0,
            feh: 0,
            eh_ctx: 0,
            cfg: Config::new(),
            colors: Colors::new(),
            pos: 0,
            force_break: false,
            force_reload: false,
            tls_callbacks: Vec::new(),
            tls32: Vec::new(),
            tls64: Vec::new(),
            fls: Vec::new(),
            out: String::new(),
            main_thread_cont: 0,
            gateway_return: 0,
            is_running: Arc::new(atomic::AtomicU32::new(0)),
            break_on_next_cmp: false,
            break_on_next_return: false,
            filename: String::new(),
            enabled_ctrlc: false, // TODO: make configurable with command line arg
            run_until_ret: false,
            running_script: false,
            banzai: Banzai::new(),
            mnemonic: String::new(),
            dbg: false,
            linux: false,
            fs: BTreeMap::new(),
            now: Instant::now(),
            skip_apicall: false,
            its_apicall: None,
            last_instruction_size: 0,
            pe64: None,
            pe32: None,
            instruction: None,
            decoder_position: 0,
            memory_operations: vec![],
            rep: None,
            tick: 0,
            trace_file: None
        }
    }

    pub fn open_trace_file(&mut self) {
        if let Some(filename) = self.cfg.trace_filename.clone() {
            self.trace_file = Some(File::create(filename).unwrap());
        }
    }

    pub fn set_base_address(&mut self, addr: u64) {
        self.cfg.code_base_addr = addr;
    }

    pub fn enable_debug_mode(&mut self) {
        self.dbg = true;
    }

    pub fn disable_debug_mode(&mut self) {
        self.dbg = false;
    }

    // configure the base address of stack map
    pub fn set_stack_address(&mut self, addr: u64) {
        self.cfg.stack_addr = addr;
    }

    // select the folder with maps32 or maps64 depending the arch, make sure to do init after this.
    pub fn set_maps_folder(&mut self, folder: &str) {
        let mut f = folder.to_string();
        f.push('/');
        self.cfg.maps_folder = folder.to_string();
    }

    // spawn a console on the instruction number, ie: 1 at the beginning.
    pub fn spawn_console_at(&mut self, exp: u64) {
        self.exp = exp;
    }

    pub fn spawn_console_at_addr(&mut self, addr: u64) {
        self.cfg.console2 = true;
        self.cfg.console_addr = addr;
        self.cfg.console_enabled = true;
    }

    pub fn get_base_addr(&self) -> Option<u64> {
        //TODO: fix this, now there is no code map.
        let map = match self.maps.get_map_by_name("code") {
            Some(m) => m,
            None => return None,
        };

        Some(map.get_base())
    }

    pub fn enable_ctrlc(&mut self) {
        self.enabled_ctrlc = true;
    }

    pub fn disable_ctrlc(&mut self) {
        self.enabled_ctrlc = false;
    }

    pub fn disable_console(&mut self) {
        self.cfg.console_enabled = false;
    }

    pub fn enable_console(&mut self) {
        self.cfg.console_enabled = true;
    }

    pub fn set_verbose(&mut self, n: u32) {
        self.cfg.verbose = n;
    }

    pub fn enable_banzai(&mut self) {
        self.cfg.skip_unimplemented = true;
    }

    pub fn disable_banzai(&mut self) {
        self.cfg.skip_unimplemented = false;
    }

    pub fn banzai_add(&mut self, name: &str, nparams: i32) {
        self.banzai.add(name, nparams);
    }

    pub fn update_ldr_entry_base(&mut self, libname: &str, base: u64) {
        if self.cfg.is_64bits {
            peb64::update_ldr_entry_base(libname, base, self);
        } else {
            peb32::update_ldr_entry_base(libname, base, self);
        }
    }

    pub fn link_library(&mut self, libname: &str) -> u64 {
        if self.cfg.is_64bits {
            winapi64::kernel32::load_library(self, libname)
        } else {
            winapi32::kernel32::load_library(self, libname)
        }
    }

    pub fn api_addr_to_name(&mut self, addr: u64) -> String {
        let name: String = if self.cfg.is_64bits {
            winapi64::kernel32::resolve_api_addr_to_name(self, addr)
        } else {
            winapi32::kernel32::resolve_api_addr_to_name(self, addr)
        };

        name
    }

    pub fn api_name_to_addr(&mut self, kw: &str) -> u64 {
        if self.cfg.is_64bits {
            let (addr, lib, name) = winapi64::kernel32::search_api_name(self, kw);
            addr
        } else {
            let (addr, lib, name) = winapi32::kernel32::search_api_name(self, kw);
            addr
        }
    }

    pub fn init_stack32(&mut self) {
        // default if not set via clap args
        if self.cfg.stack_addr == 0 {
            self.cfg.stack_addr = 0x212000;
            self.regs.set_esp(self.cfg.stack_addr + 0x1c000 + 4);
            self.regs
                .set_ebp(self.cfg.stack_addr + 0x1c000 + 4 + 0x1000);
        }

        let stack = self
            .maps
            .create_map("stack", self.cfg.stack_addr, 0x030000)
            .expect("cannot create stack map");

        assert!(self.regs.get_esp() < self.regs.get_ebp());
        assert!(self.regs.get_esp() > stack.get_base());
        assert!(self.regs.get_esp() < stack.get_bottom());
        assert!(self.regs.get_ebp() > stack.get_base());
        assert!(self.regs.get_ebp() < stack.get_bottom());
        assert!(stack.inside(self.regs.get_esp()));
        assert!(stack.inside(self.regs.get_ebp()));

        let teb_map = self.maps.get_mem("teb");
        let mut teb = structures::TEB::load_map(teb_map.get_base(), teb_map);
        teb.nt_tib.stack_base = self.cfg.stack_addr as u32;
        teb.nt_tib.stack_limit = (self.cfg.stack_addr + 0x30000) as u32;
        teb.save(teb_map);
    }

    pub fn init_stack64(&mut self) {
        // default if not set via clap args
        if self.cfg.stack_addr == 0 {
            self.cfg.stack_addr = 0x22a000;
            self.regs.rsp = self.cfg.stack_addr + 0x4000;
            self.regs.rbp = self.cfg.stack_addr + 0x4000 + 0x1000;
        }

        let stack = self
            .maps
            .create_map("stack", self.cfg.stack_addr, 0x6000)
            .expect("cannot create stack map");

        assert!(self.regs.rsp < self.regs.rbp);
        assert!(self.regs.rsp > stack.get_base());
        assert!(self.regs.rsp < stack.get_bottom());
        assert!(self.regs.rbp > stack.get_base());
        assert!(self.regs.rbp < stack.get_bottom());
        assert!(stack.inside(self.regs.rsp));
        assert!(stack.inside(self.regs.rbp));

        let teb_map = self.maps.get_mem("teb");
        let mut teb = structures::TEB64::load_map(teb_map.get_base(), teb_map);
        teb.nt_tib.stack_base = self.cfg.stack_addr;
        teb.nt_tib.stack_limit = self.cfg.stack_addr + 0x6000;
        teb.save(teb_map);
    }

    pub fn init_stack64_tests(&mut self) {
        let stack = self.maps.get_mem("stack");
        self.regs.rsp = 0x000000000014F4B0;
        self.regs.rbp = 0x0000000000000000;
        stack.set_base(0x0000000000149000);
        stack.set_size(0x0000000000007000);
    }

    pub fn init_regs_tests(&mut self) {
        self.regs.rax = 0x00000001448A76A4;
        self.regs.rbx = 0x000000007FFE0385;
        self.regs.rcx = 0x0000000140000000;
        self.regs.rdx = 0x0000000000000001;
        self.regs.rsi = 0x0000000000000001;
        self.regs.rdi = 0x000000007FFE0384;
        self.regs.r10 = 0x000000007FFE0384;
        self.regs.r11 = 0x0000000000000246;
        self.regs.r12 = 0x00000001448A76A4;
        self.regs.r14 = 0x0000000140000000;
    }

    pub fn init_flags_tests(&mut self) {
        self.flags.clear();

        self.flags.f_zf = true;
        self.flags.f_pf = true;
        self.flags.f_af = false;

        self.flags.f_of = false;
        self.flags.f_sf = false;
        self.flags.f_df = false;

        self.flags.f_cf = false;
        self.flags.f_tf = false;
        self.flags.f_if = true;

        self.flags.f_nt = false;
    }

    pub fn init(&mut self, clear_registers: bool, clear_flags: bool) {
        self.pos = 0;

        if !atty::is(Stream::Stdout) {
            self.cfg.nocolors = true;
            self.colors.disable();
            self.cfg.console_enabled = false;
            self.disable_ctrlc();
        }

        //log::info!("initializing regs");
        if clear_registers {
            self.regs.clear::<64>();
        }
        if clear_flags {
            self.flags.clear();
        }
        //self.regs.rand();

        if self.cfg.is_64bits {
            self.regs.rip = self.cfg.entry_point;
            self.maps.is_64bits = true;

            //self.init_regs_tests(); // TODO: not sure why this was on
            self.init_mem64();
            self.init_stack64();
            //self.init_stack64_tests();
            //self.init_flags_tests();
        } else {
            // 32bits
            self.regs.rip = self.cfg.entry_point;
            self.maps.is_64bits = false;
            self.regs.sanitize32();
            self.init_mem32();
            self.init_stack32();
        }

        // loading banzai on 32bits
        if !self.cfg.is_64bits {
            let mut rdr = ReaderBuilder::new()
                .from_path(format!("{}/banzai.csv", self.cfg.maps_folder))
                .expect("banzai.csv not found on maps folder, please download last mwemu maps");

            for result in rdr.records() {
                let record = result.expect("error parsing banzai.csv");
                let api = &record[0];
                let params: i32 = record[1].parse().expect("error parsing maps32/banzai.csv");

                self.banzai.add(api, params);
            }
        }

        //self.init_tests();
    }

    pub fn init_linux64(&mut self, dyn_link: bool) {
        self.regs.clear::<64>();
        self.flags.clear();
        self.flags.f_if = true;

        let orig_path = std::env::current_dir().unwrap();
        std::env::set_current_dir(self.cfg.maps_folder.clone());
        if dyn_link {
            //self.regs.rsp = 0x7fffffffe2b0;
            self.regs.rsp = 0x7fffffffe790;
            self.maps
                .create_map("linux_dynamic_stack", 0x7ffffffde000, 0x100000)
                .expect("cannot create linux_dynamic_stack map");
            //self.maps.create_map("dso_dyn").load_at(0x7ffff7ffd0000);
            self.maps
                .create_map("dso_dyn", 0x7ffff7ffd000, 0x100000)
                .expect("cannot create dso_dyn map");
            self.maps
                .create_map("linker", 0x7ffff7ffe000, 0x100000)
                .expect("cannot create linker map");
        } else {
            self.regs.rsp = 0x7fffffffe270;
            self.maps
                .create_map("linux_static_stack", 0x7ffffffde000, 0x100000)
                .expect("cannot create linux_static_stack map");
            self.maps
                .create_map("dso", 0x7ffff7ffd000, 0x100000)
                .expect("cannot create dso map");
        }
        let tls = self
            .maps
            .create_map("tls", 0x7ffff7fff000, 0xfff)
            .expect("cannot create tls map");
        tls.load("tls.bin");

        std::env::set_current_dir(orig_path);

        if dyn_link {
            //heap.set_base(0x555555579000);
        } else {
            let heap = self
                .maps
                .create_map("heap", 0x4b5b00, 0x4d8000 - 0x4b5000)
                .expect("cannot create heap map");
            heap.load("heap.bin");
        }

        self.regs.rbp = 0;

        self.fs.insert(0xffffffffffffffC8, 0); //0x4b6c50
        self.fs.insert(0xffffffffffffffD0, 0);
        self.fs.insert(0xffffffffffffffd8, 0x4b27a0);
        self.fs.insert(0xffffffffffffffa0, 0x4b3980);
        self.fs.insert(0x18, 0);
        self.fs.insert(40, 0x4b27a0);
    }

    pub fn init_mem32(&mut self) {
        log::info!("loading memory maps");

        let orig_path = std::env::current_dir().unwrap();
        std::env::set_current_dir(self.cfg.maps_folder.clone());

        //self.maps.create_map("m10000", 0x10000, 0).expect("cannot create m10000 map");
        //self.maps.create_map("m20000", 0x20000, 0).expect("cannot create m20000 map");
        //self.maps.create_map("code", self.cfg.code_base_addr, 0);

        //self.maps.write_byte(0x2c3000, 0x61); // metasploit trick

        std::env::set_current_dir(orig_path);

        peb32::init_peb(self);
        winapi32::kernel32::load_library(self, "ntdll.dll");
        let ntdll_base = self.maps.get_mem("ntdll.pe").get_base();
        peb32::update_peb_image_base(self, ntdll_base as u32);

        winapi32::kernel32::load_library(self, "kernel32.dll");
        winapi32::kernel32::load_library(self, "kernelbase.dll");
        winapi32::kernel32::load_library(self, "iphlpapi.dll");
        winapi32::kernel32::load_library(self, "ws2_32.dll");
        winapi32::kernel32::load_library(self, "advapi32.dll");
        //winapi32::kernel32::load_library(self, "comctl64.dll");
        winapi32::kernel32::load_library(self, "winhttp.dll");
        winapi32::kernel32::load_library(self, "wininet.dll");
        //winapi32::kernel32::load_library(self, "dnsapi.dll");
        winapi32::kernel32::load_library(self, "shell32.dll");
        //winapi32::kernel32::load_library(self, "shlwapi.dll");
    }

    pub fn init_tests(&mut self) {
        let mem = self
            .maps
            .create_map("test", 0, 1024)
            .expect("cannot create test map");
        mem.write_qword(0, 0x1122334455667788);
        assert!(mem.read_qword(0) == 0x1122334455667788);
        self.maps.free("test");

        // some tests
        assert!(get_bit!(0xffffff00u32, 0) == 0);
        assert!(get_bit!(0xffffffffu32, 5) == 1);
        assert!(get_bit!(0xffffff00u32, 5) == 0);
        assert!(get_bit!(0xffffff00u32, 7) == 0);
        assert!(get_bit!(0xffffff00u32, 8) == 1);

        let mut a: u32 = 0xffffff00;
        set_bit!(a, 0, 1);
        set_bit!(a, 1, 1);
        set_bit!(a, 2, 1);
        set_bit!(a, 3, 1);
        set_bit!(a, 4, 1);
        set_bit!(a, 5, 1);
        set_bit!(a, 6, 1);
        set_bit!(a, 7, 1);

        assert!(a == 0xffffffff);

        set_bit!(a, 0, 0);
        set_bit!(a, 1, 0);
        set_bit!(a, 2, 0);
        set_bit!(a, 3, 0);
        set_bit!(a, 4, 0);
        set_bit!(a, 5, 0);
        set_bit!(a, 6, 0);
        set_bit!(a, 7, 0);

        assert!(a == 0xffffff00);

        let mut r: u64;
        (r, _) = engine::logic::shrd(self, 0x9fd88893, 0x1b, 0x6, 32);
        assert!(r == 0x6e7f6222);
        (r, _) = engine::logic::shrd(self, 0x6fdcb03, 0x0, 0x6, 32);
        assert!(r == 0x1bf72c);
        (r, _) = engine::logic::shrd(self, 0x91545f1d, 0x6fe2, 0x6, 32);
        assert!(r == 0x8a45517c);
        (r, _) = engine::logic::shld(self, 0x1b, 0xf1a7eb1d, 0xa, 32);
        assert!(r == 0x6fc6);
        (r, _) = engine::logic::shld(self, 0x1, 0xffffffff, 4, 32);
        assert!(r == 0x1f);
        (r, _) = engine::logic::shld(self, 0x1, 0xffffffff, 33, 32);
        assert!(r == 0x3);
        (r, _) = engine::logic::shld(self, 0x144e471f8, 0x14F498, 0x3e, 64);
        assert!(r == 0x53d26);

        if self.maps.mem_test() {
            log::info!("memory test Ok.");
        } else {
            log::error!("It doesn't pass the memory tests!!");
            Console::spawn_console(self);
            std::process::exit(1);
        }
    }

    pub fn init_mem64(&mut self) {
        log::info!("loading memory maps");

        let orig_path = std::env::current_dir().unwrap();
        std::env::set_current_dir(self.cfg.maps_folder.clone());

        //self.maps.create_map("m10000", 0x10000, 0).expect("cannot create m10000 map");
        //self.maps.create_map("m20000", 0x20000, 0).expect("cannot create m20000 map");
        //self.maps.create_map("m520000", 0x520000, 0).expect("cannot create m520000 map");
        //self.maps.create_map("m53b000", 0x53b000, 0).expect("cannot create m53b000 map");
        //self.maps.create_map("code", self.cfg.code_base_addr, 0);

        std::env::set_current_dir(orig_path);

        peb64::init_peb(self);

        winapi64::kernel32::load_library(self, "ntdll.dll");
        let ntdll_base = self.maps.get_mem("ntdll.pe").get_base();
        peb64::update_peb_image_base(self, ntdll_base);

        winapi64::kernel32::load_library(self, "kernel32.dll");
        winapi64::kernel32::load_library(self, "kernelbase.dll");
        winapi64::kernel32::load_library(self, "iphlpapi.dll");
        winapi64::kernel32::load_library(self, "ws2_32.dll");
        winapi64::kernel32::load_library(self, "advapi32.dll");
        winapi64::kernel32::load_library(self, "comctl64.dll");
        winapi64::kernel32::load_library(self, "winhttp.dll");
        winapi64::kernel32::load_library(self, "wininet.dll");
        winapi64::kernel32::load_library(self, "dnsapi.dll");
        winapi64::kernel32::load_library(self, "shell32.dll");
        winapi64::kernel32::load_library(self, "shlwapi.dll");
    }

    pub fn filename_to_mapname(&self, filename: &str) -> String {
        let spl: Vec<&str> = filename.split('/').collect();
        let spl2: Vec<&str> = spl[spl.len() - 1].split('.').collect();
        spl2[0].to_string()
    }

    pub fn load_pe32(&mut self, filename: &str, set_entry: bool, force_base: u32) -> (u32, u32) {
        let is_maps = filename.contains("maps32/");
        let map_name = self.filename_to_mapname(filename);
        let mut pe32 = PE32::load(filename);
        let base: u32;

        // 1. base logic

        // base is forced by libmwemu
        if force_base > 0 {
            if self.maps.overlaps(force_base as u64, pe32.size() as u64) {
                panic!("the forced base address overlaps");
            } else {
                base = force_base;
            }

        // base is setted by user
        } else if !is_maps && self.cfg.code_base_addr != 0x3c0000 {
            base = self.cfg.code_base_addr as u32;
            if self.maps.overlaps(base as u64, pe32.size() as u64) {
                panic!("the setted base address overlaps");
            }

        // base is setted by image base (if overlapps, alloc)
        } else {
            // user's program
            if set_entry {
                if pe32.opt.image_base >= constants::LIBS32_MIN as u32 {
                    base = self
                        .maps
                        .alloc(pe32.mem_size() as u64 + 0xff)
                        .expect("out of memory") as u32;
                } else if self
                    .maps
                    .overlaps(pe32.opt.image_base as u64, pe32.mem_size() as u64)
                {
                    base = self
                        .maps
                        .alloc(pe32.mem_size() as u64 + 0xff)
                        .expect("out of memory") as u32;
                } else {
                    base = pe32.opt.image_base;
                }

            // system library
            } else {
                base = self
                    .maps
                    .lib32_alloc(pe32.mem_size() as u64)
                    .expect("out of memory") as u32;
            }
        }

        if set_entry {
            // 2. pe binding
            if !is_maps {
                pe32.iat_binding(self);
                pe32.delay_load_binding(self);
            }

            // 3. entry point logic
            if self.cfg.entry_point == 0x3c0000 {
                self.regs.rip = base as u64 + pe32.opt.address_of_entry_point as u64;
                log::info!("entry point at 0x{:x}", self.regs.rip);
            } else {
                self.regs.rip = self.cfg.entry_point;
                log::info!(
                    "entry point at 0x{:x} but forcing it at 0x{:x}",
                    base as u64 + pe32.opt.address_of_entry_point as u64,
                    self.regs.rip
                );
            }
        }

        // 4. map pe and then sections
        let pemap = self
            .maps
            .create_map(
                &format!("{}.pe", map_name),
                base.into(),
                pe32.opt.size_of_headers.into(),
            )
            .expect("cannot create pe map");
        pemap.memcpy(pe32.get_headers(), pe32.opt.size_of_headers as usize);

        for i in 0..pe32.num_of_sections() {
            let ptr = pe32.get_section_ptr(i);
            let sect = pe32.get_section(i);

            let sz: u64 = if sect.virtual_size > sect.size_of_raw_data {
                sect.virtual_size as u64
            } else {
                sect.size_of_raw_data as u64
            };

            if sz == 0 {
                log::info!("size of section {} is 0", sect.get_name());
                continue;
            }

            let mut sect_name = sect
                .get_name()
                .replace(" ", "")
                .replace("\t", "")
                .replace("\x0a", "")
                .replace("\x0d", "");

            if sect_name.is_empty() {
                sect_name = format!("{:x}", sect.virtual_address);
            }

            let map = match self.maps.create_map(
                &format!("{}{}", map_name, sect_name),
                base as u64 + sect.virtual_address as u64,
                sz,
            ) {
                Ok(m) => m,
                Err(e) => {
                    log::info!(
                        "weird pe, skipping section {} {} because overlaps",
                        map_name,
                        sect.get_name()
                    );
                    continue;
                }
            };

            if ptr.len() > sz as usize {
                panic!(
                    "overflow {} {} {} {}",
                    map_name,
                    sect.get_name(),
                    ptr.len(),
                    sz
                );
            }
            if !ptr.is_empty() {
                map.memcpy(ptr, ptr.len());
            }
        }

        // 5. ldr table entry creation and link
        if set_entry {
            let space_addr =
                peb32::create_ldr_entry(self, base, self.regs.rip as u32, &map_name, 0, 0x2c1950);
            peb32::update_ldr_entry_base("loader.exe", base as u64, self);
        }

        // 6. return values
        let pe_hdr_off = pe32.dos.e_lfanew;
        self.pe32 = Some(pe32);
        (base, pe_hdr_off)
    }

    pub fn load_pe64(&mut self, filename: &str, set_entry: bool, force_base: u64) -> (u64, u32) {
        let is_maps = filename.contains("maps64/");
        let map_name = self.filename_to_mapname(filename);
        let mut pe64 = PE64::load(filename);
        let base: u64;

        // 1. base logic

        // base is setted by libmwemu
        if force_base > 0 {
            if self.maps.overlaps(force_base, pe64.size()) {
                panic!("the forced base address overlaps");
            } else {
                base = force_base;
            }

        // base is setted by user
        } else if !is_maps && self.cfg.code_base_addr != 0x3c0000 {
            base = self.cfg.code_base_addr;
            if self.maps.overlaps(base, pe64.size()) {
                panic!("the setted base address overlaps");
            }

        // base is setted by image base (if overlapps, alloc)
        } else {
            // user's program
            if set_entry {
                if pe64.opt.image_base >= constants::LIBS64_MIN {
                    base = self.maps.alloc(pe64.size() + 0xff).expect("out of memory");
                } else if self.maps.overlaps(pe64.opt.image_base, pe64.size()) {
                    base = self.maps.alloc(pe64.size() + 0xff).expect("out of memory");
                } else {
                    base = pe64.opt.image_base;
                }

            // system library
            } else {
                base = self.maps.lib64_alloc(pe64.size()).expect("out of memory");
            }
        }

        if set_entry {
            // 2. pe binding
            if !is_maps {
                pe64.iat_binding(self);
                pe64.delay_load_binding(self);
            }

            // 3. entry point logic
            if self.cfg.entry_point == 0x3c0000 {
                self.regs.rip = base + pe64.opt.address_of_entry_point as u64;
                log::info!("entry point at 0x{:x}", self.regs.rip);
            } else {
                self.regs.rip = self.cfg.entry_point;
                log::info!(
                    "entry point at 0x{:x} but forcing it at 0x{:x} by -a flag",
                    base + pe64.opt.address_of_entry_point as u64,
                    self.regs.rip
                );
            }
        }

        // 4. map pe and then sections
        let pemap = self
            .maps
            .create_map(
                &format!("{}.pe", map_name),
                base,
                pe64.opt.size_of_headers.into(),
            )
            .expect("cannot create pe64 map");
        pemap.memcpy(pe64.get_headers(), pe64.opt.size_of_headers as usize);

        for i in 0..pe64.num_of_sections() {
            let ptr = pe64.get_section_ptr(i);
            let sect = pe64.get_section(i);

            let sz: u64 = if sect.virtual_size > sect.size_of_raw_data {
                sect.virtual_size as u64
            } else {
                sect.size_of_raw_data as u64
            };

            if sz == 0 {
                log::info!("size of section {} is 0", sect.get_name());
                continue;
            }

            let mut sect_name = sect
                .get_name()
                .replace(" ", "")
                .replace("\t", "")
                .replace("\x0a", "")
                .replace("\x0d", "");

            if sect_name.is_empty() {
                sect_name = format!("{:x}", sect.virtual_address);
            }

            let map = match self.maps.create_map(
                &format!("{}{}", map_name, sect_name),
                base + sect.virtual_address as u64,
                sz,
            ) {
                Ok(m) => m,
                Err(e) => {
                    log::info!(
                        "weird pe, skipping section because overlaps {} {}",
                        map_name,
                        sect.get_name()
                    );
                    continue;
                }
            };

            if ptr.len() > sz as usize {
                panic!(
                    "overflow {} {} {} {}",
                    map_name,
                    sect.get_name(),
                    ptr.len(),
                    sz
                );
            }

            if !ptr.is_empty() {
                map.memcpy(ptr, ptr.len());
            }
        }

        // 5. ldr table entry creation and link
        if set_entry {
            let space_addr =
                peb64::create_ldr_entry(self, base, self.regs.rip, &map_name, 0, 0x2c1950);
            peb64::update_ldr_entry_base("loader.exe", base, self);
        }

        // 6. return values
        let pe_hdr_off = pe64.dos.e_lfanew;
        self.pe64 = Some(pe64);
        (base, pe_hdr_off)
    }

    pub fn set_config(&mut self, cfg: Config) {
        self.cfg = cfg;
        if self.cfg.console {
            self.exp = self.cfg.console_num;
        }
        if self.cfg.nocolors {
            self.colors.disable();
        }
    }

    pub fn load_code(&mut self, filename: &str) {
        self.filename = filename.to_string();
        self.cfg.filename = self.filename.clone();

        //let map_name = self.filename_to_mapname(filename);
        //self.cfg.filename = map_name;

        if Elf32::is_elf32(filename) {
            self.linux = true;
            self.cfg.is_64bits = false;

            log::info!("elf32 detected.");
            let mut elf32 = Elf32::parse(filename).unwrap();
            elf32.load(&mut self.maps);
            self.regs.rip = elf32.elf_hdr.e_entry.into();
            let stack_sz = 0x30000;
            let stack = self.alloc("stack", stack_sz);
            self.regs.rsp = stack + (stack_sz / 2);
            //unimplemented!("elf32 is not supported for now");
        } else if Elf64::is_elf64(filename) {
            self.linux = true;
            self.cfg.is_64bits = true;
            self.maps.clear();

            log::info!("elf64 detected.");

            let mut elf64 = Elf64::parse(filename).unwrap();
            let dyn_link = !elf64.get_dynamic().is_empty();
            elf64.load(
                &mut self.maps,
                "elf64",
                false,
                dyn_link,
                self.cfg.code_base_addr,
            );
            self.init_linux64(dyn_link);

            if dyn_link {
                let mut ld = Elf64::parse("/lib64/ld-linux-x86-64.so.2").unwrap();
                ld.load(&mut self.maps, "ld-linux", true, dyn_link, 0x3c0000);
                log::info!("--- emulating ld-linux _start ---");

                self.regs.rip = ld.elf_hdr.e_entry + elf64::LD_BASE;
                self.run(None);
            } else {
                self.regs.rip = elf64.elf_hdr.e_entry;
            }

            /*
            for lib in elf64.get_dynamic() {
                log::info!("dynamic library {}", lib);
                let libspath = "/usr/lib/x86_64-linux-gnu/";
                let libpath = format!("{}{}", libspath, lib);
                let mut elflib = Elf64::parse(&libpath).unwrap();
                elflib.load(&mut self.maps, &lib, true);

                if lib.contains("libc") {
                    elflib.craft_libc_got(&mut self.maps, "elf64");
                }

                /*
                match elflib.init {
                    Some(addr) => {
                        self.call64(addr, &[]);
                    }
                    None => {}
                }*/
            }*/
        } else if !self.cfg.is_64bits && PE32::is_pe32(filename) {
            log::info!("PE32 header detected.");
            let (base, pe_off) = self.load_pe32(filename, true, 0);
            let ep = self.regs.rip;
            // emulating tls callbacks

            /*
            for i in 0..self.tls_callbacks.len() {
                self.regs.rip = self.tls_callbacks[i];
                log::info!("emulating tls_callback {} at 0x{:x}", i + 1, self.regs.rip);
                self.stack_push32(base);
                self.run(Some(base as u64));
            }*/

            self.regs.rip = ep;
        } else if self.cfg.is_64bits && PE64::is_pe64(filename) {
            log::info!("PE64 header detected.");
            let (base, pe_off) = self.load_pe64(filename, true, 0);
            let ep = self.regs.rip;

            // emulating tls callbacks
            /*
            for i in 0..self.tls_callbacks.len() {
                self.regs.rip = self.tls_callbacks[i];
                log::info!("emulating tls_callback {} at 0x{:x}", i + 1, self.regs.rip);
                self.stack_push64(base);
                self.run(Some(base));
            }*/

            self.regs.rip = ep;
        } else {
            // shellcode

            log::info!("shellcode detected.");

            if self.cfg.is_64bits {
                let (base, pe_off) = self.load_pe64(
                    &format!("{}/{}", self.cfg.maps_folder, "loader.exe"),
                    false,
                    0,
                );
                peb64::update_ldr_entry_base("loader.exe", base, self);
            } else {
                let (base, pe_off) = self.load_pe32(
                    &format!("{}/{}", self.cfg.maps_folder, "loader.exe"),
                    false,
                    0,
                );
                peb32::update_ldr_entry_base("loader.exe", base as u64, self);
            }

            if !self
                .maps
                .create_map("code", self.cfg.code_base_addr, 0)
                .expect("cannot create code map")
                .load(filename)
            {
                log::info!("shellcode not found, select the file with -f");
                std::process::exit(1);
            }
            let code = self.maps.get_mem("code");
            code.extend(0xffff); // this could overlap an existing map
        }

        if self.cfg.entry_point != 0x3c0000 {
            self.regs.rip = self.cfg.entry_point;
        }

        /*if self.cfg.code_base_addr != 0x3c0000 {
            let code = self.maps.get_mem("code");
            code.update_base(self.cfg.code_base_addr);
            code.update_bottom(self.cfg.code_base_addr + code.size() as u64);
        }*/
    }

    pub fn load_code_bytes(&mut self, bytes: &[u8]) {
        if self.cfg.verbose >= 1 {
            log::info!("Loading shellcode from bytes");
        }
        if self.cfg.code_base_addr != 0x3c0000 {
            let code = self.maps.get_mem("code");
            code.update_base(self.cfg.code_base_addr);
            code.update_bottom(self.cfg.code_base_addr + code.size() as u64);
        }
        let code = self.maps.get_mem("code");
        let base = code.get_base();
        code.set_size(bytes.len() as u64);
        code.write_bytes(base, bytes);
    }

    pub fn free(&mut self, name: &str) {
        self.maps.free(name);
    }

    pub fn alloc(&mut self, name: &str, size: u64) -> u64 {
        let addr = match self.maps.alloc(size) {
            Some(a) => a,
            None => {
                log::info!("low memory");
                return 0;
            }
        };
        self.maps
            .create_map(name, addr, size)
            .expect("cannot create map from alloc api");
        addr
    }

    pub fn stack_push32(&mut self, value: u32) -> bool {
        if self.cfg.stack_trace {
            log::info!("--- stack push32 ---");
            self.maps.dump_dwords(self.regs.get_esp(), 5);
        }

        if self.cfg.trace_mem {
            let name = match self.maps.get_addr_name(self.regs.get_esp()) {
                Some(n) => n,
                None => "not mapped".to_string(),
            };
            let memory_operation = MemoryOperation {
                pos: self.pos,
                rip: self.regs.rip,
                op: "write".to_string(),
                bits: 32,
                address: self.regs.get_esp() - 4,
                old_value: self.maps.read_dword(self.regs.get_esp()).unwrap_or(0) as u64,
                new_value: value as u64,
                name: name.clone(),
            };
            self.memory_operations.push(memory_operation);
            log::debug!("\tmem_trace: pos = {} rip = {:x} op = write bits = {} address = 0x{:x} value = 0x{:x} name = '{}'",
                self.pos, self.regs.rip, 32, self.regs.get_esp(), value, name);
        }

        self.regs.set_esp(self.regs.get_esp() - 4);

        /*
        let stack = self.maps.get_mem("stack");
        if stack.inside(self.regs.get_esp()) {
            if !self.maps.write_dword(self.regs.get_esp(), value) {
                //if !stack.write_dword(self.regs.get_esp(), value) {
                return false;
            }
        } else {
            let mem = match self.maps.get_mem_by_addr(self.regs.get_esp()) {
                Some(m) => m,
                None => {
                    log::info!(
                        "/!\\ pushing stack outside maps esp: 0x{:x}",
                        self.regs.get_esp()
                    );
                    Console::spawn_console(self);
                    return false;
                }
            };
            if !self.maps.write_dword(self.regs.get_esp(), value) {
                //if !mem.write_dword(self.regs.get_esp(), value) {
                return false;
            }
        }*/

        if self.maps.write_dword(self.regs.get_esp(), value) {
            true
        } else {
            log::info!("/!\\ pushing in non mapped mem 0x{:x}", self.regs.get_esp());
            false
        }
    }

    pub fn stack_push64(&mut self, value: u64) -> bool {
        if self.cfg.stack_trace {
            log::info!("--- stack push64  ---");
            self.maps.dump_qwords(self.regs.rsp, 5);
        }

        if self.cfg.trace_mem {
            let name = match self.maps.get_addr_name(self.regs.rsp) {
                Some(n) => n,
                None => "not mapped".to_string(),
            };
            let memory_operation = MemoryOperation {
                pos: self.pos,
                rip: self.regs.rip,
                op: "write".to_string(),
                bits: 64,
                address: self.regs.rsp - 8,
                old_value: self.maps.read_qword(self.regs.rsp).unwrap_or(0),
                new_value: value,
                name: name.clone(),
            };
            self.memory_operations.push(memory_operation);
            log::debug!("\tmem_trace: pos = {} rip = {:x} op = write bits = {} address = 0x{:x} value = 0x{:x} name = '{}'", self.pos, self.regs.rip, 64, self.regs.rsp, value, name);
        }

        self.regs.rsp -= 8;
        /*
        let stack = self.maps.get_mem("stack");
        if stack.inside(self.regs.rsp) {
            stack.write_qword(self.regs.rsp, value);
        } else {
            let mem = match self.maps.get_mem_by_addr(self.regs.rsp) {
                Some(m) => m,
                None => {
                    log::info!(
                        "pushing stack outside maps rsp: 0x{:x}",
                        self.regs.get_esp()
                    );
                    Console::spawn_console(self);
                    return false;
                }
            };
            mem.write_qword(self.regs.rsp, value);
        }*/

        if self.maps.write_qword(self.regs.rsp, value) {
            true
        } else {
            log::info!("/!\\ pushing in non mapped mem 0x{:x}", self.regs.rsp);
            false
        }
    }

    pub fn stack_pop32(&mut self, pop_instruction: bool) -> Option<u32> {
        if self.cfg.stack_trace {
            log::info!("--- stack pop32 ---");
            self.maps.dump_dwords(self.regs.get_esp(), 5);
        }

        /*
        let stack = self.maps.get_mem("stack");
        if stack.inside(self.regs.get_esp()) {
            //let value = stack.read_dword(self.regs.get_esp());
            let value = match self.maps.read_dword(self.regs.get_esp()) {
                Some(v) => v,
                None => {
                    log::info!("esp out of stack");
                    return None;
                }
            };
            if self.cfg.verbose >= 1
                && pop_instruction
                && self.maps.get_mem("code").inside(value.into())
            {
                log::info!("/!\\ poping a code address 0x{:x}", value);
            }
            self.regs.set_esp(self.regs.get_esp() + 4);
            return Some(value);
        }

        let mem = match self.maps.get_mem_by_addr(self.regs.get_esp()) {
            Some(m) => m,
            None => {
                log::info!(
                    "poping stack outside map  esp: 0x{:x}",
                    self.regs.get_esp() as u32
                );
                Console::spawn_console(self);
                return None;
            }
        };*/

        let value = match self.maps.read_dword(self.regs.get_esp()) {
            Some(v) => v,
            None => {
                log::info!("esp point to non mapped mem");
                return None;
            }
        };

        /*  walking mems in very pop is slow, and now we are not using "code" map
        if self.cfg.verbose >= 1
            && pop_instruction
            && self.maps.get_mem("code").inside(value.into())
        {
            log::info!("/!\\ poping a code address 0x{:x}", value);
        }
        */

        if self.cfg.trace_mem {
            // Record the read from stack memory
            let name = match self.maps.get_addr_name(self.regs.get_esp()) {
                Some(n) => n,
                None => "not mapped".to_string(),
            };
            let read_operation = MemoryOperation {
                pos: self.pos,
                rip: self.regs.rip,
                op: "read".to_string(),
                bits: 32,
                address: self.regs.get_esp(),
                old_value: 0, // not needed for read
                new_value: value as u64,
                name: name.clone(),
            };
            self.memory_operations.push(read_operation);
            log::debug!("\tmem_trace: pos = {} rip = {:x} op = read bits = {} address = 0x{:x} value = 0x{:x} name = '{}'", 
                self.pos, self.regs.rip, 32, self.regs.get_esp(), value, name);

            // Record the write to register
            let write_operation = MemoryOperation {
                pos: self.pos,
                rip: self.regs.rip,
                op: "write".to_string(),
                bits: 32,
                address: self.regs.get_esp(),
                old_value: self.maps.read_dword(self.regs.get_esp()).unwrap_or(0) as u64,
                new_value: value as u64, // new value being written
                name: "register".to_string(),
            };
            self.memory_operations.push(write_operation);
            log::debug!("\tmem_trace: pos = {} rip = {:x} op = write bits = {} address = 0x{:x} value = 0x{:x} name = 'register'", 
                self.pos, self.regs.rip, 32, self.regs.get_esp(), value);
        }

        self.regs.set_esp(self.regs.get_esp() + 4);
        Some(value)
    }

    pub fn stack_pop64(&mut self, pop_instruction: bool) -> Option<u64> {
        if self.cfg.stack_trace {
            log::info!("--- stack pop64 ---");
            self.maps.dump_qwords(self.regs.rsp, 5);
        }

        /*
        let stack = self.maps.get_mem("stack");
        if stack.inside(self.regs.rsp) {
            let value = stack.read_qword(self.regs.rsp);
            if self.cfg.verbose >= 1
                && pop_instruction
                && self.maps.get_mem("code").inside(value.into())
            {
                log::info!("/!\\ poping a code address 0x{:x}", value);
            }
            self.regs.rsp += 8;
            return Some(value);
        }

        let mem = match self.maps.get_mem_by_addr(self.regs.rsp) {
            Some(m) => m,
            None => {
                log::info!("poping stack outside map  esp: 0x{:x}", self.regs.rsp);
                Console::spawn_console(self);
                return None;
            }
        };

        let value = mem.read_qword(self.regs.rsp);
        */

        let value = match self.maps.read_qword(self.regs.rsp) {
            Some(v) => v,
            None => {
                log::info!("rsp point to non mapped mem");
                return None;
            }
        };

        if self.cfg.trace_mem {
            // Record the read from stack memory
            let name = match self.maps.get_addr_name(self.regs.rsp) {
                Some(n) => n,
                None => "not mapped".to_string(),
            };
            let read_operation = MemoryOperation {
                pos: self.pos,
                rip: self.regs.rip,
                op: "read".to_string(),
                bits: 64, // Changed from 32 to 64 for 64-bit operations
                address: self.regs.rsp,
                old_value: 0, // not needed for read
                new_value: value as u64,
                name: name.clone(),
            };
            self.memory_operations.push(read_operation);
            log::debug!("\tmem_trace: pos = {} rip = {:x} op = read bits = {} address = 0x{:x} value = 0x{:x} name = '{}'", 
                self.pos, self.regs.rip, 64, self.regs.rsp, value, name);

            // Record the write to register
            let write_operation = MemoryOperation {
                pos: self.pos,
                rip: self.regs.rip,
                op: "write".to_string(),
                bits: 64, // Changed from 32 to 64 for 64-bit operations
                address: self.regs.rsp,
                old_value: self.maps.read_qword(self.regs.rsp).unwrap_or(0),
                new_value: value as u64, // new value being written
                name: "register".to_string(),
            };
            self.memory_operations.push(write_operation);
            log::debug!("\tmem_trace: pos = {} rip = {:x} op = write bits = {} address = 0x{:x} value = 0x{:x} name = 'register'", 
                self.pos, self.regs.rip, 64, self.regs.rsp, value);
        }

        self.regs.rsp += 8;
        Some(value)
    }

    // this is not used on the emulation
    pub fn memory_operand_to_address(&mut self, operand: &str) -> u64 {
        let spl: Vec<&str> = operand.split('[').collect::<Vec<&str>>()[1]
            .split(']')
            .collect::<Vec<&str>>()[0]
            .split(' ')
            .collect();

        if operand.contains("fs:[") || operand.contains("gs:[") {
            let mem = operand.split(':').collect::<Vec<&str>>()[1];
            let value = self.memory_operand_to_address(mem);

            /*
            fs:[0x30]

            FS:[0x00] : Current SEH Frame
            FS:[0x18] : TEB (Thread Environment Block)
            FS:[0x20] : PID
            FS:[0x24] : TID
            FS:[0x30] : PEB (Process Environment Block)
            FS:[0x34] : Last Error Value
            */

            //let inm = self.get_inmediate(spl[0]);
            if self.cfg.verbose >= 1 {
                log::info!("FS ACCESS TO 0x{:x}", value);
            }

            if value == 0x30 {
                // PEB
                if self.cfg.verbose >= 1 {
                    log::info!("ACCESS TO PEB");
                }
                let peb = self.maps.get_mem("peb");
                return peb.get_base();
            }

            if value == 0x18 {
                if self.cfg.verbose >= 1 {
                    log::info!("ACCESS TO TEB");
                }
                let teb = self.maps.get_mem("teb");
                return teb.get_base();
            }

            if value == 0x2c {
                if self.cfg.verbose >= 1 {
                    log::info!("ACCESS TO CURRENT LOCALE");
                }
                return constants::EN_US_LOCALE as u64;
            }

            if value == 0xc0 {
                if self.cfg.verbose >= 1 {
                    log::info!("CHECKING IF ITS 32bits (ISWOW64)");
                }

                if self.cfg.is_64bits {
                    return 0;
                }

                return 1;
            }

            panic!("not implemented: {}", operand);
        }

        if spl.len() == 3 {
            //ie eax + 0xc
            let sign = spl[1];

            // weird case: [esi + eax*4]
            if spl[2].contains('*') {
                let spl2: Vec<&str> = spl[2].split('*').collect();
                if spl2.len() != 2 {
                    panic!(
                        "case ie [esi + eax*4] bad parsed the *  operand:{}",
                        operand
                    );
                }

                let reg1_val = self.regs.get_by_name(spl[0]);
                let reg2_val = self.regs.get_by_name(spl2[0]);
                let num = u64::from_str_radix(spl2[1].trim_start_matches("0x"), 16)
                    .expect("bad num conversion");

                if sign != "+" && sign != "-" {
                    panic!("weird sign2 {}", sign);
                }

                if sign == "+" {
                    return reg1_val + (reg2_val * num);
                }

                if sign == "-" {
                    return reg1_val - (reg2_val * num);
                }

                unimplemented!();
            }

            let reg = spl[0];
            let sign = spl[1];
            //log::info!("disp --> {}  operand:{}", spl[2], operand);

            let disp: u64 = if self.regs.is_reg(spl[2]) {
                self.regs.get_by_name(spl[2])
            } else {
                u64::from_str_radix(spl[2].trim_start_matches("0x"), 16).expect("bad disp")
            };

            if sign != "+" && sign != "-" {
                panic!("weird sign {}", sign);
            }

            if sign == "+" {
                let r: u64 = self.regs.get_by_name(reg) + disp;
                return r & 0xffffffff;
            } else {
                return self.regs.get_by_name(reg) - disp;
            }
        }

        if spl.len() == 1 {
            //ie [eax]
            let reg = spl[0];

            if reg.contains("0x") {
                let addr: u64 =
                    u64::from_str_radix(reg.trim_start_matches("0x"), 16).expect("bad disp2");
                return addr;
                // weird but could be a hardcoded address [0x11223344]
            }

            let reg_val = self.regs.get_by_name(reg);
            return reg_val;
        }

        0
    }

    // this is not used on the emulation
    pub fn memory_read(&mut self, operand: &str) -> Option<u64> {
        if operand.contains("fs:[0]") {
            if self.cfg.verbose >= 1 {
                log::info!("{} Reading SEH fs:[0] 0x{:x}", self.pos, self.seh);
            }
            return Some(self.seh);
        }

        let addr: u64 = self.memory_operand_to_address(operand);

        if operand.contains("fs:[") || operand.contains("gs:[") {
            return Some(addr);
        }

        let bits = self.get_size(operand);
        // check integrity of eip, esp and ebp registers

        let stack = self.maps.get_mem("stack");

        // could be normal using part of code as stack
        if !stack.inside(self.regs.get_esp()) {
            //hack: redirect stack
            self.regs.set_esp(stack.get_base() + 0x1ff);
            panic!("/!\\ fixing stack.")
        }

        match bits {
            64 => match self.maps.read_qword(addr) {
                Some(v) => {
                    if self.cfg.trace_mem {
                        let name = match self.maps.get_addr_name(addr) {
                            Some(n) => n,
                            None => "not mapped".to_string(),
                        };
                        let memory_operation = MemoryOperation {
                            pos: self.pos,
                            rip: self.regs.rip,
                            op: "read".to_string(),
                            bits: 64,
                            address: addr,
                            old_value: 0, // not needed for read?
                            new_value: v,
                            name: name.clone(),
                        };
                        self.memory_operations.push(memory_operation);
                        log::debug!("\tmem_trace: pos = {} rip = {:x} op = read bits = {} address = 0x{:x} value = 0x{:x} name = '{}'", self.pos, self.regs.rip, 64, addr, v, name);
                    }
                    Some(v)
                }
                None => None,
            },
            32 => match self.maps.read_dword(addr) {
                Some(v) => {
                    if self.cfg.trace_mem {
                        let name = match self.maps.get_addr_name(addr) {
                            Some(n) => n,
                            None => "not mapped".to_string(),
                        };
                        let memory_operation = MemoryOperation {
                            pos: self.pos,
                            rip: self.regs.rip,
                            op: "read".to_string(),
                            bits: 32,
                            address: addr,
                            old_value: 0, // not needed for read?
                            new_value: v as u64,
                            name: name.clone(),
                        };
                        self.memory_operations.push(memory_operation);
                        log::debug!("\tmem_trace: pos = {} rip = {:x} op = read bits = {} address = 0x{:x} value = 0x{:x} name = '{}'", self.pos, self.regs.rip, 32, addr, v, name);
                    }
                    Some(v.into())
                }
                None => None,
            },
            16 => match self.maps.read_word(addr) {
                Some(v) => {
                    if self.cfg.trace_mem {
                        let name = match self.maps.get_addr_name(addr) {
                            Some(n) => n,
                            None => "not mapped".to_string(),
                        };
                        let memory_operation = MemoryOperation {
                            pos: self.pos,
                            rip: self.regs.rip,
                            op: "read".to_string(),
                            bits: 16,
                            address: addr,
                            old_value: 0, // not needed for read?
                            new_value: v as u64,
                            name: name.clone(),
                        };
                        self.memory_operations.push(memory_operation);
                        log::debug!("\tmem_trace: pos = {} rip = {:x} op = read bits = {} address = 0x{:x} value = 0x{:x} name = '{}'", self.pos, self.regs.rip, 16, addr, v, name);
                    }
                    Some(v.into())
                }
                None => None,
            },
            8 => match self.maps.read_byte(addr) {
                Some(v) => {
                    if self.cfg.trace_mem {
                        let name = match self.maps.get_addr_name(addr) {
                            Some(n) => n,
                            None => "not mapped".to_string(),
                        };
                        let memory_operation = MemoryOperation {
                            pos: self.pos,
                            rip: self.regs.rip,
                            op: "read".to_string(),
                            bits: 8,
                            address: addr,
                            old_value: 0, // not needed for read?
                            new_value: v as u64,
                            name: name.clone(),
                        };
                        self.memory_operations.push(memory_operation);
                        log::debug!("\tmem_trace: pos = {} rip = {:x} op = read bits = {} address = 0x{:x} value = 0x{:x} name = '{}'", self.pos, self.regs.rip, 8, addr, v, name);
                    }
                    Some(v.into())
                }
                None => None,
            },
            _ => panic!("weird size: {}", operand),
        }
    }

    // this is not used on the emulation
    pub fn memory_write(&mut self, operand: &str, value: u64) -> bool {
        if operand.contains("fs:[0]") {
            log::info!("Setting SEH fs:[0]  0x{:x}", value);
            self.seh = value;
            return true;
        }

        let addr: u64 = self.memory_operand_to_address(operand);

        /*if !self.maps.is_mapped(addr) {
        panic!("writting in non mapped memory");
        }*/

        let name = match self.maps.get_addr_name(addr) {
            Some(n) => n,
            None => "error".to_string(),
        };

        if name == "code" {
            if self.cfg.verbose >= 1 {
                log::info!("/!\\ polymorfic code, write at 0x{:x}", addr);
            }
            self.force_break = true;
        }

        let bits = self.get_size(operand);

        if self.cfg.trace_mem {
            let memory_operation = MemoryOperation {
                pos: self.pos,
                rip: self.regs.rip,
                op: "write".to_string(),
                bits: bits as u32,
                address: addr,
                old_value: match bits {
                    64 => self.maps.read_qword(addr).unwrap_or(0),
                    32 => self.maps.read_dword(addr).unwrap_or(0) as u64,
                    16 => self.maps.read_word(addr).unwrap_or(0) as u64,
                    8 => self.maps.read_byte(addr).unwrap_or(0) as u64,
                    _ => unreachable!("weird size: {}", operand),
                },
                new_value: value,
                name: name.clone(),
            };
            self.memory_operations.push(memory_operation);
            log::debug!("\tmem_trace: pos = {} rip = {:x} op = write bits = {} address = 0x{:x} value = 0x{:x} name = '{}'", self.pos, self.regs.rip, 32, addr, value, name);
        }

        match bits {
            64 => self.maps.write_qword(addr, value),
            32 => self.maps.write_dword(addr, (value & 0xffffffff) as u32),
            16 => self.maps.write_word(addr, (value & 0x0000ffff) as u16),
            8 => self.maps.write_byte(addr, (value & 0x000000ff) as u8),
            _ => unreachable!("weird size: {}", operand),
        }
    }

    // this is not used on the emulation
    pub fn get_size(&self, operand: &str) -> u8 {
        if operand.contains("byte ptr") {
            return 8;
        } else if operand.contains("dword ptr") {
            return 32;
        } else if operand.contains("qword ptr") {
            return 64;
        } else if operand.contains("word ptr") {
            return 16;
        }

        let c: Vec<char> = operand.chars().collect();

        if operand.len() == 3 {
            if c[0] == 'e' {
                return 32;
            }
        } else if operand.len() == 2 {
            if c[1] == 'x' {
                return 16;
            }

            if c[1] == 'h' || c[1] == 'l' {
                return 8;
            }

            if c[1] == 'i' {
                return 16;
            }
        }

        panic!("weird size: {}", operand);
    }

    pub fn set_rip(&mut self, addr: u64, is_branch: bool) -> bool {
        self.force_reload = true;

        if addr == constants::RETURN_THREAD as u64 {
            log::info!("/!\\ Thread returned, continuing the main thread");
            self.regs.rip = self.main_thread_cont;
            Console::spawn_console(self);
            self.force_break = true;
            return true;
        }

        let name = match self.maps.get_addr_name(addr) {
            Some(n) => n,
            None => {
                let api_name = self.pe64.as_ref().unwrap().import_addr_to_name(addr);
                if !api_name.is_empty() {
                    self.gateway_return = self.stack_pop64(false).unwrap_or(0);
                    self.regs.rip = self.gateway_return;
                    winapi64::gateway(addr, "not_loaded".to_string(), self);
                    self.force_break = true;
                    return true;
                } else {
                    log::error!("/!\\ setting rip to non mapped addr 0x{:x}", addr);
                    self.exception();
                    return false;
                }
            }
        };

        let map_name = self.filename_to_mapname(&self.cfg.filename);
        if addr < constants::LIBS64_MIN
            || name == "code"
            || (!map_name.is_empty() && name.starts_with(&map_name))
            || name == "loader.text"
        {
            self.regs.rip = addr;
        } else if self.linux {
            self.regs.rip = addr; // in linux libs are no implemented are emulated
        } else {
            if self.cfg.verbose >= 1 {
                log::info!("/!\\ changing RIP to {} ", name);
            }

            if self.skip_apicall {
                self.its_apicall = Some(addr);
                return false;
            }

            self.gateway_return = self.stack_pop64(false).unwrap_or(0);
            self.regs.rip = self.gateway_return;

            let handle_winapi: bool = match self.hooks.hook_on_winapi_call {
                Some(hook_fn) => hook_fn(self, self.regs.rip, addr),
                None => true,
            };

            if handle_winapi {
                winapi64::gateway(addr, name, self);
            }
            self.force_break = true;
        }

        true
    }

    pub fn handle_winapi(&mut self, addr: u64) {
        let name = match self.maps.get_addr_name(addr) {
            Some(n) => n,
            None => {
                log::error!("/!\\ setting rip to non mapped addr 0x{:x}", addr);
                self.exception();
                return;
            }
        };
        if self.cfg.is_64bits {
            self.gateway_return = self.stack_pop64(false).unwrap_or(0);
            self.regs.rip = self.gateway_return;
            winapi64::gateway(addr, name, self);
        } else {
            self.gateway_return = self.stack_pop32(false).unwrap_or(0) as u64;
            self.regs.rip = self.gateway_return;
            winapi32::gateway(addr as u32, name, self);
        }
    }

    pub fn set_eip(&mut self, addr: u64, is_branch: bool) -> bool {
        self.force_reload = true;

        if addr == constants::RETURN_THREAD as u64 {
            log::info!("/!\\ Thread returned, continuing the main thread");
            self.regs.rip = self.main_thread_cont;
            Console::spawn_console(self);
            self.force_break = true;
            return true;
        }

        let name = match self.maps.get_addr_name(addr) {
            Some(n) => n,
            None => {
                let api_name = self.pe32.as_ref().unwrap().import_addr_to_name(addr as u32);
                if !api_name.is_empty() {
                    self.gateway_return = self.stack_pop32(false).unwrap_or(0) as u64;
                    self.regs.rip = self.gateway_return;
                    winapi32::gateway(addr as u32, "not_loaded".to_string(), self);
                    self.force_break = true;
                    return true;
                } else {
                    log::error!("/!\\ setting eip to non mapped addr 0x{:x}", addr);
                    self.exception();
                    return false;
                }
            }
        };

        let map_name = self.filename_to_mapname(&self.filename);
        if name == "code"
            || addr < constants::LIBS32_MIN
            || (!map_name.is_empty() && name.starts_with(&map_name))
            || name == "loader.text"
        {
            self.regs.set_eip(addr);
        } else {
            if self.cfg.verbose >= 1 {
                log::info!("/!\\ changing EIP to {} 0x{:x}", name, addr);
            }

            if self.skip_apicall {
                self.its_apicall = Some(addr);
                return false;
            }

            self.gateway_return = self.stack_pop32(false).unwrap_or(0).into();
            self.regs.set_eip(self.gateway_return);

            let handle_winapi: bool = match self.hooks.hook_on_winapi_call {
                Some(hook_fn) => hook_fn(self, self.regs.rip, addr),
                None => true,
            };

            if handle_winapi {
                winapi32::gateway(to32!(addr), name, self);
            }
            self.force_break = true;
        }

        true
    }

    pub fn featured_regs32(&self) {
        self.regs.show_eax(&self.maps, 0);
        self.regs.show_ebx(&self.maps, 0);
        self.regs.show_ecx(&self.maps, 0);
        self.regs.show_edx(&self.maps, 0);
        self.regs.show_esi(&self.maps, 0);
        self.regs.show_edi(&self.maps, 0);
        log::info!("\tesp: 0x{:x}", self.regs.get_esp() as u32);
        log::info!("\tebp: 0x{:x}", self.regs.get_ebp() as u32);
        log::info!("\teip: 0x{:x}", self.regs.get_eip() as u32);
    }

    pub fn featured_regs64(&self) {
        self.regs.show_rax(&self.maps, 0);
        self.regs.show_rbx(&self.maps, 0);
        self.regs.show_rcx(&self.maps, 0);
        self.regs.show_rdx(&self.maps, 0);
        self.regs.show_rsi(&self.maps, 0);
        self.regs.show_rdi(&self.maps, 0);
        log::info!("\trsp: 0x{:x}", self.regs.rsp);
        log::info!("\trbp: 0x{:x}", self.regs.rbp);
        log::info!("\trip: 0x{:x}", self.regs.rip);
        self.regs.show_r8(&self.maps, 0);
        self.regs.show_r9(&self.maps, 0);
        self.regs.show_r10(&self.maps, 0);
        self.regs.show_r11(&self.maps, 0);
        self.regs.show_r12(&self.maps, 0);
        self.regs.show_r13(&self.maps, 0);
        self.regs.show_r14(&self.maps, 0);
        self.regs.show_r15(&self.maps, 0);
    }

    pub fn exception(&mut self) {
        let addr: u64;
        let next: u64;

        let handle_exception: bool = match self.hooks.hook_on_exception {
            Some(hook_fn) => hook_fn(self, self.regs.rip),
            None => true,
        };

        /*if !handle_exception {
            return;
        }*/

        if self.veh > 0 {
            addr = self.veh;

            exception::enter(self);
            if self.cfg.is_64bits {
                self.set_rip(addr, false);
            } else {
                self.set_eip(addr, false);
            }
        } else {
            if self.seh == 0 {
                log::info!(
                    "exception without any SEH handler nor vector configured. pos = {}",
                    self.pos
                );
                if self.cfg.console_enabled {
                    Console::spawn_console(self);
                }
                return;
            }

            // SEH

            next = match self.maps.read_dword(self.seh) {
                Some(value) => value.into(),
                None => {
                    log::info!("exception wihout correct SEH");
                    return;
                }
            };

            addr = match self.maps.read_dword(self.seh + 4) {
                Some(value) => value.into(),
                None => {
                    log::info!("exception without correct SEH.");
                    return;
                }
            };

            let con = Console::new();
            con.print("jump the exception pointer (y/n)?");
            let cmd = con.cmd();
            if cmd == "y" {
                self.seh = next;
                exception::enter(self);
                if self.cfg.is_64bits {
                    self.set_rip(addr, false);
                } else {
                    self.set_eip(addr, false);
                }
            }
        }
    }

    pub fn disassemble(&mut self, addr: u64, amount: u32) -> String {
        let mut out = String::new();
        let map_name = self.maps.get_addr_name(addr).expect("address not mapped");
        let code = self.maps.get_mem(map_name.as_str());
        let block = code.read_from(addr);

        let bits: u32 = if self.cfg.is_64bits { 64 } else { 32 };
        let mut decoder = Decoder::with_ip(bits, block, addr, DecoderOptions::NONE);
        let mut formatter = IntelFormatter::new();
        formatter.options_mut().set_digit_separator("");
        formatter.options_mut().set_first_operand_char_index(6);
        let mut output = String::new();
        let mut instruction = Instruction::default();
        let mut count: u32 = 1;
        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);
            output.clear();
            formatter.format(&instruction, &mut output);
            if self.cfg.is_64bits {
                out.push_str(&format!("0x{:x}: {}\n", instruction.ip(), output));
                //log::info!("0x{:x}: {}", instruction.ip(), output);
            } else {
                out.push_str(&format!("0x{:x}: {}\n", instruction.ip32(), output));
                //log::info!("0x{:x}: {}", instruction.ip32(), output);
            }
            count += 1;
            if count == amount {
                break;
            }
        }
        out
    }

    pub fn get_operand_value(
        &mut self,
        ins: &Instruction,
        noperand: u32,
        do_derref: bool,
    ) -> Option<u64> {
        assert!(ins.op_count() > noperand);

        let value: u64 = match ins.op_kind(noperand) {
            OpKind::NearBranch64 => ins.near_branch64(),
            OpKind::NearBranch32 => ins.near_branch32().into(),
            OpKind::NearBranch16 => ins.near_branch16().into(),
            OpKind::FarBranch32 => ins.far_branch32().into(),
            OpKind::FarBranch16 => ins.far_branch16().into(),

            OpKind::Immediate64 => ins.immediate64(),
            OpKind::Immediate8 => ins.immediate8() as u64,
            OpKind::Immediate16 => ins.immediate16() as u64,
            OpKind::Immediate32 => ins.immediate32() as u64,
            OpKind::Immediate8to64 => ins.immediate8to64() as u64,
            OpKind::Immediate32to64 => ins.immediate32to64() as u64,
            OpKind::Immediate8to32 => ins.immediate8to32() as u32 as u64,
            OpKind::Immediate8to16 => ins.immediate8to16() as u16 as u64,

            /*OpKind::Immediate64 => ins.immediate64(),
            OpKind::Immediate8 => ins.immediate8().into(),
            OpKind::Immediate16 => ins.immediate16().into(),
            OpKind::Immediate32 => ins.immediate32() as u32 as u64,
            OpKind::Immediate8to64 => ins.immediate8to64() as u64,
            OpKind::Immediate32to64 => ins.immediate32to64() as u64,
            OpKind::Immediate8to32 => ins.immediate8to32() as u32 as u64,
            OpKind::Immediate8to16 => ins.immediate8to16() as u16 as u64,
            */
            OpKind::Register => self.regs.get_reg(ins.op_register(noperand)),
            OpKind::Memory => {
                let mut derref = do_derref;
                let mut fs = false;
                let mut gs = false;

                let mut mem_addr = ins
                    .virtual_address(noperand, 0, |reg, idx, _sz| {
                        if reg == Register::FS {
                            derref = false;
                            fs = true;

                            Some(0)
                        } else if reg == Register::GS {
                            derref = false;
                            gs = true;

                            Some(0)
                        } else {
                            Some(self.regs.get_reg(reg))
                        }
                    })
                    .expect("error reading memory");

                if fs {
                    if self.linux {
                        if let Some(val) = self.fs.get(&mem_addr) {
                            if self.cfg.verbose > 0 {
                                log::info!("reading FS[0x{:x}] -> 0x{:x}", mem_addr, *val);
                            }
                            if *val == 0 {
                                return Some(0); //0x7ffff7ff000);
                            }
                            return Some(*val);
                        } else {
                            if self.cfg.verbose > 0 {
                                log::info!("reading FS[0x{:x}] -> 0", mem_addr);
                            }
                            return Some(0); //0x7ffff7fff000);
                        }
                    }

                    let value: u64 = match mem_addr {
                        0xc0 => {
                            if self.cfg.verbose >= 1 {
                                log::info!(
                                    "{} Reading ISWOW64 is 32bits on a 64bits system?",
                                    self.pos
                                );
                            }
                            if self.cfg.is_64bits {
                                0
                            } else {
                                1
                            }
                        }
                        0x30 => {
                            let peb = self.maps.get_mem("peb");
                            if self.cfg.verbose >= 1 {
                                log::info!("{} Reading PEB 0x{:x}", self.pos, peb.get_base());
                            }
                            peb.get_base()
                        }
                        0x20 => {
                            if self.cfg.verbose >= 1 {
                                log::info!("{} Reading PID 0x{:x}", self.pos, 10);
                            }
                            10
                        }
                        0x24 => {
                            if self.cfg.verbose >= 1 {
                                log::info!("{} Reading TID 0x{:x}", self.pos, 101);
                            }
                            101
                        }
                        0x34 => {
                            if self.cfg.verbose >= 1 {
                                log::info!("{} Reading last error value 0", self.pos);
                            }
                            0
                        }
                        0x18 => {
                            let teb = self.maps.get_mem("teb");
                            if self.cfg.verbose >= 1 {
                                log::info!("{} Reading TEB 0x{:x}", self.pos, teb.get_base());
                            }
                            teb.get_base()
                        }
                        0x00 => {
                            if self.cfg.verbose >= 1 {
                                log::info!("Reading SEH 0x{:x}", self.seh);
                            }
                            self.seh
                        }
                        0x28 => {
                            // TODO  linux TCB
                            0
                        }
                        0x2c => {
                            if self.cfg.verbose >= 1 {
                                log::info!("Reading local ");
                            }
                            let locale = self.alloc("locale", 100);
                            self.maps.write_dword(locale, constants::EN_US_LOCALE);
                            //TODO: return a table of locales
                            /*
                            13071 0x41026e: mov   eax,[edx+eax*4]
                            =>r edx
                                edx: 0xc8 200 (locale)
                            =>r eax
                                eax: 0x409 1033
                            */

                            locale
                        }
                        _ => {
                            log::info!("unimplemented fs:[{}]", mem_addr);
                            return None;
                        }
                    };
                    mem_addr = value;
                }
                if gs {
                    let value: u64 = match mem_addr {
                        0x60 => {
                            let peb = self.maps.get_mem("peb");
                            if self.cfg.verbose >= 1 {
                                log::info!("{} Reading PEB 0x{:x}", self.pos, peb.get_base());
                            }
                            peb.get_base()
                        }
                        0x30 => {
                            let teb = self.maps.get_mem("teb");
                            if self.cfg.verbose >= 1 {
                                log::info!("{} Reading TEB 0x{:x}", self.pos, teb.get_base());
                            }
                            teb.get_base()
                        }
                        0x40 => {
                            if self.cfg.verbose >= 1 {
                                log::info!("{} Reading PID 0x{:x}", self.pos, 10);
                            }
                            10
                        }
                        0x48 => {
                            if self.cfg.verbose >= 1 {
                                log::info!("{} Reading TID 0x{:x}", self.pos, 101);
                            }
                            101
                        }
                        0x10 => {
                            let stack = self.maps.get_mem("stack");
                            if self.cfg.verbose >= 1 {
                                log::info!("{} Reading StackLimit 0x{:x}", self.pos, &stack.size());
                            }
                            stack.size() as u64
                        }
                        0x14 => {
                            unimplemented!("GS:[14]  get stack canary")
                        }
                        0x1488 => {
                            if self.cfg.verbose >= 1 {
                                log::info!("Reading SEH 0x{:x}", self.seh);
                            }
                            self.seh
                        }
                        0x8 => {
                            if self.cfg.verbose >= 1 {
                                log::info!("Reading SEH 0x{:x}", self.seh);
                            }
                            if self.cfg.is_64bits {
                                self.maps.get_mem("peb").get_base()
                            } else {
                                let teb = self.maps.get_mem("teb");
                                let teb_struct = structures::TEB::new(teb.get_base() as u32);
                                teb_struct.thread_id as u64
                            }
                        }
                        _ => {
                            log::info!("unimplemented gs:[{}]", mem_addr);
                            return None;
                        }
                    };
                    mem_addr = value;
                }

                let value: u64;
                if derref {
                    let sz = self.get_operand_sz(ins, noperand);

                    if let Some(hook_fn) = self.hooks.hook_on_memory_read {
                        hook_fn(self, self.regs.rip, mem_addr, sz)
                    }

                    value = match sz {
                        64 => match self.maps.read_qword(mem_addr) {
                            Some(v) => v,
                            None => {
                                log::info!("/!\\ error dereferencing qword on 0x{:x}", mem_addr);
                                self.exception();
                                return None;
                            }
                        },

                        32 => match self.maps.read_dword(mem_addr) {
                            Some(v) => v.into(),
                            None => {
                                log::info!("/!\\ error dereferencing dword on 0x{:x}", mem_addr);
                                self.exception();
                                return None;
                            }
                        },

                        16 => match self.maps.read_word(mem_addr) {
                            Some(v) => v.into(),
                            None => {
                                log::info!("/!\\ error dereferencing word on 0x{:x}", mem_addr);
                                self.exception();
                                return None;
                            }
                        },

                        8 => match self.maps.read_byte(mem_addr) {
                            Some(v) => v.into(),
                            None => {
                                log::info!("/!\\ error dereferencing byte on 0x{:x}", mem_addr);
                                self.exception();
                                return None;
                            }
                        },

                        _ => unimplemented!("weird size"),
                    };

                    if self.cfg.trace_mem {
                        let name = match self.maps.get_addr_name(mem_addr) {
                            Some(n) => n,
                            None => "not mapped".to_string(),
                        };
                        let memory_operation = MemoryOperation {
                            pos: self.pos,
                            rip: self.regs.rip,
                            op: "read".to_string(),
                            bits: sz,
                            address: mem_addr,
                            old_value: 0, // not needed for read?
                            new_value: value,
                            name: name.clone(),
                        };
                        self.memory_operations.push(memory_operation);
                        log::debug!("\tmem_trace: pos = {} rip = {:x} op = read bits = {} address = 0x{:x} value = 0x{:x} name = '{}'", self.pos, self.regs.rip, sz, mem_addr, value, name);
                    }

                    if mem_addr == self.bp.get_mem_read() {
                        log::info!("Memory breakpoint on read 0x{:x}", mem_addr);
                        if self.running_script {
                            self.force_break = true;
                        } else {
                            Console::spawn_console(self);
                        }
                    }
                } else {
                    value = mem_addr;
                }
                value
            }

            _ => unimplemented!("unimplemented operand type {:?}", ins.op_kind(noperand)),
        };
        Some(value)
    }

    pub fn set_operand_value(&mut self, ins: &Instruction, noperand: u32, value: u64) -> bool {
        assert!(ins.op_count() > noperand);

        match ins.op_kind(noperand) {
            OpKind::Register => {
                if self.regs.is_fpu(ins.op_register(noperand)) {
                    self.fpu.set_streg(ins.op_register(noperand), value as f64);
                } else {
                    self.regs.set_reg(ins.op_register(noperand), value);
                }
            }

            OpKind::Memory => {
                let mut write = true;
                let mem_addr = ins
                    .virtual_address(noperand, 0, |reg, idx, _sz| {
                        if reg == Register::FS || reg == Register::GS {
                            write = false;
                            if idx == 0 {
                                if self.linux {
                                    if self.cfg.verbose > 0 {
                                        log::info!("writting FS[0x{:x}] = 0x{:x}", idx, value);
                                    }
                                    if value == 0x4b6c50 {
                                        self.fs.insert(0xffffffffffffffc8, 0x4b6c50);
                                    }
                                    self.fs.insert(idx as u64, value);
                                } else {
                                    if self.cfg.verbose >= 1 {
                                        log::info!("fs:{:x} setting SEH to 0x{:x}", idx, value);
                                    }
                                    self.seh = value;
                                }
                            } else if self.linux {
                                if self.cfg.verbose > 0 {
                                    log::info!("writting FS[0x{:x}] = 0x{:x}", idx, value);
                                }
                                self.fs.insert(idx as u64, value);
                            } else {
                                unimplemented!("set FS:[{}] use same logic as linux", idx);
                            }
                            Some(0)
                        } else {
                            Some(self.regs.get_reg(reg))
                        }
                    })
                    .unwrap();

                if write {
                    let sz = self.get_operand_sz(ins, noperand);

                    let value2 = match self.hooks.hook_on_memory_write {
                        Some(hook_fn) => {
                            hook_fn(self, self.regs.rip, mem_addr, sz, value as u128) as u64
                        }
                        None => value,
                    };

                    let old_value = if self.cfg.trace_mem {
                        match sz {
                            64 => self.maps.read_qword(mem_addr).unwrap_or(0),
                            32 => self.maps.read_dword(mem_addr).unwrap_or(0) as u64,
                            16 => self.maps.read_word(mem_addr).unwrap_or(0) as u64,
                            8 => self.maps.read_byte(mem_addr).unwrap_or(0) as u64,
                            _ => unreachable!("weird size: {}", sz),
                        }
                    } else {
                        0
                    };

                    match sz {
                        64 => {
                            if !self.maps.write_qword(mem_addr, value2) {
                                if self.cfg.skip_unimplemented {
                                    let map_name = format!("banzai_{:x}", mem_addr);
                                    let map = self
                                        .maps
                                        .create_map(&map_name, mem_addr, 100)
                                        .expect("cannot create banzai map");
                                    map.write_qword(mem_addr, value2);
                                    return true;
                                } else {
                                    log::info!(
                                        "/!\\ exception dereferencing bad address. 0x{:x}",
                                        mem_addr
                                    );
                                    self.exception();
                                    return false;
                                }
                            }
                        }
                        32 => {
                            if !self.maps.write_dword(mem_addr, to32!(value2)) {
                                if self.cfg.skip_unimplemented {
                                    let map_name = format!("banzai_{:x}", mem_addr);
                                    let map = self
                                        .maps
                                        .create_map(&map_name, mem_addr, 100)
                                        .expect("cannot create banzai map");
                                    map.write_dword(mem_addr, to32!(value2));
                                    return true;
                                } else {
                                    log::info!(
                                        "/!\\ exception dereferencing bad address. 0x{:x}",
                                        mem_addr
                                    );
                                    self.exception();
                                    return false;
                                }
                            }
                        }
                        16 => {
                            if !self.maps.write_word(mem_addr, value2 as u16) {
                                if self.cfg.skip_unimplemented {
                                    let map_name = format!("banzai_{:x}", mem_addr);
                                    let map = self
                                        .maps
                                        .create_map(&map_name, mem_addr, 100)
                                        .expect("cannot create banzai map");
                                    map.write_word(mem_addr, value2 as u16);
                                    return true;
                                } else {
                                    log::info!(
                                        "/!\\ exception dereferencing bad address. 0x{:x}",
                                        mem_addr
                                    );
                                    self.exception();
                                    return false;
                                }
                            }
                        }
                        8 => {
                            if !self.maps.write_byte(mem_addr, value2 as u8) {
                                if self.cfg.skip_unimplemented {
                                    let map_name = format!("banzai_{:x}", mem_addr);
                                    let map = self
                                        .maps
                                        .create_map(&map_name, mem_addr, 100)
                                        .expect("cannot create banzai map");
                                    map.write_byte(mem_addr, value2 as u8);
                                    return true;
                                } else {
                                    log::info!(
                                        "/!\\ exception dereferencing bad address. 0x{:x}",
                                        mem_addr
                                    );
                                    self.exception();
                                    return false;
                                }
                            }
                        }
                        _ => unimplemented!("weird size"),
                    }

                    if self.cfg.trace_mem {
                        let name = match self.maps.get_addr_name(mem_addr) {
                            Some(n) => n,
                            None => "not mapped".to_string(),
                        };
                        let memory_operation = MemoryOperation {
                            pos: self.pos,
                            rip: self.regs.rip,
                            op: "write".to_string(),
                            bits: sz,
                            address: mem_addr,
                            old_value,
                            new_value: value2,
                            name: name.clone(),
                        };
                        self.memory_operations.push(memory_operation);
                        log::debug!("\tmem_trace: pos = {} rip = {:x} op = write bits = {} address = 0x{:x} value = 0x{:x} name = '{}'", self.pos, self.regs.rip, sz, mem_addr, value2, name);
                    }

                    /*
                    let name = match self.maps.get_addr_name(mem_addr) {
                        Some(n) => n,
                        None => "not mapped".to_string(),
                    };

                    if name == "code" {
                        if self.cfg.verbose >= 1 {
                            log::info!("/!\\ polymorfic code, addr 0x{:x}", mem_addr);
                        }
                        self.force_break = true;
                    }*/

                    if mem_addr == self.bp.get_mem_write() {
                        log::info!("Memory breakpoint on write 0x{:x}", mem_addr);
                        if self.running_script {
                            self.force_break = true;
                        } else {
                            Console::spawn_console(self);
                        }
                    }
                }
            }

            _ => unimplemented!("unimplemented operand type"),
        };
        true
    }

    pub fn get_operand_xmm_value_128(
        &mut self,
        ins: &Instruction,
        noperand: u32,
        do_derref: bool,
    ) -> Option<u128> {
        assert!(ins.op_count() > noperand);

        let value: u128 = match ins.op_kind(noperand) {
            OpKind::Register => self.regs.get_xmm_reg(ins.op_register(noperand)),

            OpKind::Immediate64 => ins.immediate64() as u128,
            OpKind::Immediate8 => ins.immediate8() as u128,
            OpKind::Immediate16 => ins.immediate16() as u128,
            OpKind::Immediate32 => ins.immediate32() as u128,
            OpKind::Immediate8to64 => ins.immediate8to64() as u128,
            OpKind::Immediate32to64 => ins.immediate32to64() as u128,
            OpKind::Immediate8to32 => ins.immediate8to32() as u32 as u128,
            OpKind::Immediate8to16 => ins.immediate8to16() as u16 as u128,

            OpKind::Memory => {
                let mem_addr = match ins
                    .virtual_address(noperand, 0, |reg, idx, _sz| Some(self.regs.get_reg(reg)))
                {
                    Some(addr) => addr,
                    None => {
                        log::info!("/!\\ xmm exception reading operand");
                        self.exception();
                        return None;
                    }
                };

                if do_derref {
                    if let Some(hook_fn) = self.hooks.hook_on_memory_read {
                        hook_fn(self, self.regs.rip, mem_addr, 128)
                    }

                    let value: u128 = match self.maps.read_128bits_le(mem_addr) {
                        Some(v) => v,
                        None => {
                            log::info!("/!\\ exception reading xmm operand at 0x{:x} ", mem_addr);
                            self.exception();
                            return None;
                        }
                    };
                    value
                } else {
                    mem_addr as u128
                }
            }
            _ => unimplemented!("unimplemented operand type {:?}", ins.op_kind(noperand)),
        };
        Some(value)
    }

    pub fn set_operand_xmm_value_128(&mut self, ins: &Instruction, noperand: u32, value: u128) {
        assert!(ins.op_count() > noperand);

        match ins.op_kind(noperand) {
            OpKind::Register => self.regs.set_xmm_reg(ins.op_register(noperand), value),
            OpKind::Memory => {
                let mem_addr = match ins
                    .virtual_address(noperand, 0, |reg, idx, _sz| Some(self.regs.get_reg(reg)))
                {
                    Some(addr) => addr,
                    None => {
                        log::info!("/!\\ exception setting xmm operand.");
                        self.exception();
                        return;
                    }
                };

                let value2 = match self.hooks.hook_on_memory_write {
                    Some(hook_fn) => hook_fn(self, self.regs.rip, mem_addr, 128, value),
                    None => value,
                };

                for (i, b) in value2.to_le_bytes().iter().enumerate() {
                    self.maps.write_byte(mem_addr + i as u64, *b);
                }
            }
            _ => unimplemented!("unimplemented operand type {:?}", ins.op_kind(noperand)),
        };
    }

    pub fn get_operand_ymm_value_256(
        &mut self,
        ins: &Instruction,
        noperand: u32,
        do_derref: bool,
    ) -> Option<regs64::U256> {
        assert!(ins.op_count() > noperand);

        let value: regs64::U256 = match ins.op_kind(noperand) {
            OpKind::Register => self.regs.get_ymm_reg(ins.op_register(noperand)),

            OpKind::Immediate64 => regs64::U256::from(ins.immediate64()),
            OpKind::Immediate8 => regs64::U256::from(ins.immediate8() as u64),
            OpKind::Immediate16 => regs64::U256::from(ins.immediate16() as u64),
            OpKind::Immediate32 => regs64::U256::from(ins.immediate32() as u64),
            OpKind::Immediate8to64 => regs64::U256::from(ins.immediate8to64() as u64),
            OpKind::Immediate32to64 => regs64::U256::from(ins.immediate32to64() as u64),
            OpKind::Immediate8to32 => regs64::U256::from(ins.immediate8to32() as u32 as u64),
            OpKind::Immediate8to16 => regs64::U256::from(ins.immediate8to16() as u16 as u64),

            OpKind::Memory => {
                let mem_addr = match ins
                    .virtual_address(noperand, 0, |reg, idx, _sz| Some(self.regs.get_reg(reg)))
                {
                    Some(addr) => addr,
                    None => {
                        log::info!("/!\\ xmm exception reading operand");
                        self.exception();
                        return None;
                    }
                };

                if do_derref {
                    if let Some(hook_fn) = self.hooks.hook_on_memory_read {
                        hook_fn(self, self.regs.rip, mem_addr, 256)
                    }

                    let bytes = self.maps.read_bytes(mem_addr, 32);
                    let value = regs64::U256::from_little_endian(bytes);

                    value
                } else {
                    regs64::U256::from(mem_addr as u64)
                }
            }
            _ => unimplemented!("unimplemented operand type {:?}", ins.op_kind(noperand)),
        };
        Some(value)
    }

    pub fn set_operand_ymm_value_256(
        &mut self,
        ins: &Instruction,
        noperand: u32,
        value: regs64::U256,
    ) {
        assert!(ins.op_count() > noperand);

        match ins.op_kind(noperand) {
            OpKind::Register => self.regs.set_ymm_reg(ins.op_register(noperand), value),
            OpKind::Memory => {
                let mem_addr = match ins
                    .virtual_address(noperand, 0, |reg, idx, _sz| Some(self.regs.get_reg(reg)))
                {
                    Some(addr) => addr,
                    None => {
                        log::info!("/!\\ exception setting xmm operand.");
                        self.exception();
                        return;
                    }
                };

                // ymm dont support value modification from hook, for now
                let value_u128: u128 = ((value.0[1] as u128) << 64) | value.0[0] as u128;
                let value2 = match self.hooks.hook_on_memory_write {
                    Some(hook_fn) => hook_fn(self, self.regs.rip, mem_addr, 256, value_u128),
                    None => value_u128,
                };

                let mut bytes: Vec<u8> = vec![0; 32];
                value.to_little_endian(&mut bytes);
                self.maps.write_bytes(mem_addr, bytes);
            }
            _ => unimplemented!("unimplemented operand type {:?}", ins.op_kind(noperand)),
        };
    }

    pub fn get_operand_sz(&self, ins: &Instruction, noperand: u32) -> u32 {
        let reg: Register = ins.op_register(noperand);
        if reg.is_xmm() {
            return 128;
        }
        if reg.is_ymm() {
            return 256;
        }

        let size: u32 = match ins.op_kind(noperand) {
            OpKind::NearBranch64 => 64,
            OpKind::NearBranch32 => 32,
            OpKind::NearBranch16 => 16,
            OpKind::FarBranch32 => 32,
            OpKind::FarBranch16 => 16,
            OpKind::Immediate8 => 8,
            OpKind::Immediate16 => 16,
            OpKind::Immediate32 => 32,
            OpKind::Immediate64 => 64,
            OpKind::Immediate8to32 => 32,
            OpKind::Immediate8to16 => 16,
            OpKind::Immediate32to64 => 64,
            OpKind::Immediate8to64 => 64, //TODO: this could be 8
            OpKind::Register => self.regs.get_size(ins.op_register(noperand)),
            OpKind::MemoryESEDI => 32,
            OpKind::MemorySegESI => 32,
            OpKind::Memory => {
                let mut info_factory = InstructionInfoFactory::new();
                let info = info_factory.info(ins);
                let mem = info.used_memory()[0];

                let size2: u32 = match mem.memory_size() {
                    MemorySize::Float16 => 16,
                    MemorySize::Float32 => 32,
                    MemorySize::Float64 => 64,
                    MemorySize::FpuEnv28 => 32,
                    MemorySize::UInt64 => 64,
                    MemorySize::UInt32 => 32,
                    MemorySize::UInt16 => 16,
                    MemorySize::UInt8 => 8,
                    MemorySize::Int64 => 64,
                    MemorySize::Int32 => 32,
                    MemorySize::Int16 => 16,
                    MemorySize::Int8 => 8,
                    MemorySize::QwordOffset => 64,
                    MemorySize::DwordOffset => 32,
                    MemorySize::WordOffset => 16,
                    MemorySize::Packed128_UInt64 => 64, // 128bits packed in 2 qwords
                    MemorySize::Packed128_UInt32 => 32, // 128bits packed in 4 dwords
                    MemorySize::Packed128_UInt16 => 16, // 128bits packed in 8 words
                    MemorySize::Bound32_DwordDword => 32,
                    MemorySize::Bound16_WordWord => 16,
                    MemorySize::Packed64_Float32 => 32,
                    MemorySize::Packed256_UInt16 => 16,
                    MemorySize::Packed256_UInt32 => 32,
                    MemorySize::Packed256_UInt64 => 64,
                    MemorySize::Packed256_UInt128 => 128,
                    MemorySize::Packed128_Float32 => 32,
                    MemorySize::SegPtr32 => 32,
                    _ => unimplemented!("memory size {:?}", mem.memory_size()),
                };

                size2
            }
            _ => unimplemented!("operand type {:?}", ins.op_kind(noperand)),
        };

        size
    }

    pub fn show_instruction(&self, color: &str, ins: &Instruction) {
        if self.cfg.verbose >= 2 {
            log::info!(
                "{}{} 0x{:x}: {}{}",
                color,
                self.pos,
                ins.ip(),
                self.out,
                self.colors.nc
            );
        }
    }

    pub fn show_instruction_ret(&self, color: &str, ins: &Instruction, addr: u64) {
        if self.cfg.verbose >= 2 {
            log::info!(
                "{}{} 0x{:x}: {} ; ret-addr: 0x{:x} ret-value: 0x{:x} {}",
                color,
                self.pos,
                ins.ip(),
                self.out,
                addr,
                self.regs.rax,
                self.colors.nc
            );
        }
    }

    pub fn show_instruction_pushpop(&self, color: &str, ins: &Instruction, value: u64) {
        if self.cfg.verbose >= 2 {
            log::info!(
                "{}{} 0x{:x}: {} ;0x{:x} {}",
                color,
                self.pos,
                ins.ip(),
                self.out,
                value,
                self.colors.nc
            );
        }
    }

    pub fn show_instruction_taken(&self, color: &str, ins: &Instruction) {
        if self.cfg.verbose >= 2 {
            log::info!(
                "{}{} 0x{:x}: {} taken {}",
                color,
                self.pos,
                ins.ip(),
                self.out,
                self.colors.nc
            );
        }
    }

    pub fn show_instruction_not_taken(&self, color: &str, ins: &Instruction) {
        if self.cfg.verbose >= 2 {
            log::info!(
                "{}{} 0x{:x}: {} not taken {}",
                color,
                self.pos,
                ins.ip(),
                self.out,
                self.colors.nc
            );
        }
    }

    pub fn stop(&mut self) {
        self.is_running.store(0, atomic::Ordering::Relaxed);
    }

    pub fn call32(&mut self, addr: u64, args: &[u64]) -> Result<u32, MwemuError> {
        if addr == self.regs.get_eip() {
            if addr == 0 {
                return Err(MwemuError::new(
                    "return address reached after starting the call32, change eip.",
                ));
            } else {
                self.regs.rip = 0;
            }
        }
        let orig_stack = self.regs.get_esp();
        for arg in args.iter().rev() {
            self.stack_push32(*arg as u32);
        }
        let ret_addr = self.regs.get_eip();
        self.stack_push32(ret_addr as u32);
        self.regs.set_eip(addr);
        self.run(Some(ret_addr))?;
        self.regs.set_esp(orig_stack);
        Ok(self.regs.get_eax() as u32)
    }

    pub fn call64(&mut self, addr: u64, args: &[u64]) -> Result<u64, MwemuError> {
        if addr == self.regs.rip {
            if addr == 0 {
                return Err(MwemuError::new(
                    "return address reached after starting the call64, change rip.",
                ));
            } else {
                self.regs.rip = 0;
            }
        }

        let n = args.len();
        if n >= 1 {
            self.regs.rcx = args[0];
        }
        if n >= 2 {
            self.regs.rdx = args[1];
        }
        if n >= 3 {
            self.regs.r8 = args[2];
        }
        if n >= 4 {
            self.regs.r9 = args[3];
        }
        let orig_stack = self.regs.rsp;
        if n > 4 {
            for arg in args.iter().skip(4).rev() {
                self.stack_push64(*arg);
            }
        }

        let ret_addr = self.regs.rip;
        self.stack_push64(ret_addr);
        self.regs.rip = addr;
        self.run(Some(ret_addr))?;
        self.regs.rsp = orig_stack;
        Ok(self.regs.rax)
    }

    pub fn run_until_ret(&mut self) -> Result<u64, MwemuError> {
        self.run_until_ret = true;
        self.run(None)
    }

    pub fn capture_pre_op(&mut self) {
        self.pre_op_regs = self.regs;
        self.pre_op_flags = self.flags;
    }

    pub fn capture_post_op(&mut self) {
        self.post_op_regs = self.regs;
        self.post_op_flags = self.flags;
    }

    pub fn write_to_trace_file(&mut self) {
        let index = self.pos - 1;

        let instruction = self.instruction.unwrap();
        let instruction_size = instruction.len();
        let instruction_bytes = self.maps.read_bytes(self.regs.rip, instruction_size);

        let mut comments = String::new();

        // dump all registers on first, only differences on next
        let mut registers = String::new();
        if index == 0 {
            registers = format!(
                "{} rax: {:x}-> {:x}",
                registers, self.pre_op_regs.rax, self.post_op_regs.rax
            );
            registers = format!(
                "{} rbx: {:x}-> {:x}",
                registers, self.pre_op_regs.rbx, self.post_op_regs.rbx
            );
            registers = format!(
                "{} rcx: {:x}-> {:x}",
                registers, self.pre_op_regs.rcx, self.post_op_regs.rcx
            );
            registers = format!(
                "{} rdx: {:x}-> {:x}",
                registers, self.pre_op_regs.rdx, self.post_op_regs.rdx
            );
            registers = format!(
                "{} rsp: {:x}-> {:x}",
                registers, self.pre_op_regs.rsp, self.post_op_regs.rsp
            );
            registers = format!(
                "{} rbp: {:x}-> {:x}",
                registers, self.pre_op_regs.rbp, self.post_op_regs.rbp
            );
            registers = format!(
                "{} rsi: {:x}-> {:x}",
                registers, self.pre_op_regs.rsi, self.post_op_regs.rsi
            );
            registers = format!(
                "{} rdi: {:x}-> {:x}",
                registers, self.pre_op_regs.rdi, self.post_op_regs.rdi
            );
            registers = format!(
                "{} r8: {:x}-> {:x}",
                registers, self.pre_op_regs.r8, self.post_op_regs.r8
            );
            registers = format!(
                "{} r9: {:x}-> {:x}",
                registers, self.pre_op_regs.r9, self.post_op_regs.r9
            );
            registers = format!(
                "{} r10: {:x}-> {:x}",
                registers, self.pre_op_regs.r10, self.post_op_regs.r10
            );
            registers = format!(
                "{} r11: {:x}-> {:x}",
                registers, self.pre_op_regs.r11, self.post_op_regs.r11
            );
            registers = format!(
                "{} r12: {:x}-> {:x}",
                registers, self.pre_op_regs.r12, self.post_op_regs.r12
            );
            registers = format!(
                "{} r13: {:x}-> {:x}",
                registers, self.pre_op_regs.r13, self.post_op_regs.r13
            );
            registers = format!(
                "{} r14: {:x}-> {:x}",
                registers, self.pre_op_regs.r14, self.post_op_regs.r14
            );
            registers = format!(
                "{} r15: {:x}-> {:x}",
                registers, self.pre_op_regs.r15, self.post_op_regs.r15
            );
        } else {
            registers = Regs64::diff(self.pre_op_regs, self.post_op_regs);
        }

        let mut flags = String::new();
        // dump all flags on first, only differences on next
        if index == 0 {
            flags = format!(
                "rflags: {:x}-> {:x}",
                self.pre_op_flags.dump(),
                self.post_op_flags.dump()
            );
        } else if self.pre_op_flags.dump() != self.post_op_flags.dump() {
            flags = format!(
                "rflags: {:x}-> {:x}",
                self.pre_op_flags.dump(),
                self.post_op_flags.dump()
            );
            comments = format!(
                "{} {}",
                comments,
                Flags::diff(self.pre_op_flags, self.post_op_flags)
            );
        }

        // dump all write memory operations
        let mut memory = String::new();
        for memory_op in self.memory_operations.iter() {
            if memory_op.op == "read" {
                continue;
            }
            memory = format!(
                "{} {:016X}: {:X}-> {:X}",
                memory, memory_op.address, memory_op.old_value, memory_op.new_value
            );
        }

        let mut trace_file = self.trace_file.as_ref().unwrap();
        writeln!(
            trace_file,
            r#""{index:02X}","{address:016X}","{bytes:02x?}","{disassembly}","{registers}","{memory}","{comments}""#, 
            index = index,
            address = self.pre_op_regs.rip,
            bytes = instruction_bytes,
            disassembly = self.out,
            registers = format!("{} {}", registers, flags),
            memory = memory,
            comments = comments
        ).expect("failed to write to trace file");
    }

    fn trace_specific_register(&self, reg: &str) {
        match reg {
            "rax" => self.regs.show_rax(&self.maps, self.pos),
            "rbx" => self.regs.show_rbx(&self.maps, self.pos),
            "rcx" => self.regs.show_rcx(&self.maps, self.pos),
            "rdx" => self.regs.show_rdx(&self.maps, self.pos),
            "rsi" => self.regs.show_rsi(&self.maps, self.pos),
            "rdi" => self.regs.show_rdi(&self.maps, self.pos),
            "rbp" => log::info!("\t{} rbp: 0x{:x}", self.pos, self.regs.rbp),
            "rsp" => log::info!("\t{} rsp: 0x{:x}", self.pos, self.regs.rsp),
            "rip" => log::info!("\t{} rip: 0x{:x}", self.pos, self.regs.rip),
            "r8" => self.regs.show_r8(&self.maps, self.pos),
            "r9" => self.regs.show_r9(&self.maps, self.pos),
            "r10" => self.regs.show_r10(&self.maps, self.pos),
            "r10d" => self.regs.show_r10d(&self.maps, self.pos),
            "r11" => self.regs.show_r11(&self.maps, self.pos),
            "r11d" => self.regs.show_r11d(&self.maps, self.pos),
            "r12" => self.regs.show_r12(&self.maps, self.pos),
            "r13" => self.regs.show_r13(&self.maps, self.pos),
            "r14" => self.regs.show_r14(&self.maps, self.pos),
            "r15" => self.regs.show_r15(&self.maps, self.pos),
            "eax" => self.regs.show_eax(&self.maps, self.pos),
            "ebx" => self.regs.show_ebx(&self.maps, self.pos),
            "ecx" => self.regs.show_ecx(&self.maps, self.pos),
            "edx" => self.regs.show_edx(&self.maps, self.pos),
            "esi" => self.regs.show_esi(&self.maps, self.pos),
            "edi" => self.regs.show_edi(&self.maps, self.pos),
            "esp" => log::info!("\t{} esp: 0x{:x}", self.pos, self.regs.get_esp() as u32),
            "ebp" => log::info!("\t{} ebp: 0x{:x}", self.pos, self.regs.get_ebp() as u32),
            "eip" => log::info!("\t{} eip: 0x{:x}", self.pos, self.regs.get_eip() as u32),
            "xmm1" => log::info!("\t{} xmm1: 0x{:x}", self.pos, self.regs.xmm1),
            _ => panic!("invalid register."),
        }
    }

    fn trace_string(&mut self) {
        let s = self.maps.read_string(self.cfg.string_addr);

        if s.len() >= 2 && s.len() < 80 {
            log::info!("\ttrace string -> 0x{:x}: '{}'", self.cfg.string_addr, s);
        } else {
            let w = self.maps.read_wide_string(self.cfg.string_addr);
            if w.len() < 80 {
                log::info!(
                    "\ttrace wide string -> 0x{:x}: '{}'",
                    self.cfg.string_addr,
                    w
                );
            } else {
                log::info!("\ttrace wide string -> 0x{:x}: ''", self.cfg.string_addr);
            }
        }
    }

    fn trace_memory_inspection(&mut self) {
        let addr: u64 = self.memory_operand_to_address(self.cfg.inspect_seq.clone().as_str());
        let bits = self.get_size(self.cfg.inspect_seq.clone().as_str());
        let value = self
            .memory_read(self.cfg.inspect_seq.clone().as_str())
            .unwrap_or(0);

        let mut s = self.maps.read_string(addr);
        self.maps.filter_string(&mut s);
        log::info!(
            "\tmem_inspect: rip = {:x} (0x{:x}): 0x{:x} {} '{}' {{{}}}",
            self.regs.rip,
            addr,
            value,
            value,
            s,
            self.maps
                .read_string_of_bytes(addr, constants::NUM_BYTES_TRACE)
        );
    }

    pub fn step(&mut self) -> bool {
        self.pos += 1;

        // exit
        if self.cfg.exit_position != 0 && self.pos == self.cfg.exit_position {
            log::info!("exit position reached");
            std::process::exit(0);
        }

        // code
        let code = match self.maps.get_mem_by_addr(self.regs.rip) {
            Some(c) => c,
            None => {
                log::info!(
                    "redirecting code flow to non maped address 0x{:x}",
                    self.regs.rip
                );
                Console::spawn_console(self);
                return false;
            }
        };

        // block
        let block = code.read_from(self.regs.rip).to_vec(); // reduce code block for more speed

        // decoder
        let mut decoder;
        if self.cfg.is_64bits {
            decoder = Decoder::with_ip(64, &block, self.regs.rip, DecoderOptions::NONE);
        } else {
            decoder = Decoder::with_ip(32, &block, self.regs.get_eip(), DecoderOptions::NONE);
        }

        // formatter
        let mut formatter = IntelFormatter::new();
        formatter.options_mut().set_digit_separator("");
        formatter.options_mut().set_first_operand_char_index(6);

        // get first instruction from iterator
        let ins = decoder.decode();
        let sz = ins.len();
        let addr = ins.ip();
        let position = decoder.position();

        // clear
        self.out.clear();
        self.memory_operations.clear();

        // format
        formatter.format(&ins, &mut self.out);
        self.instruction = Some(ins);
        self.decoder_position = position;
        // emulate
        let result_ok = engine::emulate_instruction(self, &ins, sz, true);
        self.last_instruction_size = sz;

        // update eip/rip
        if self.force_reload {
            self.force_reload = false;
        } else if self.cfg.is_64bits {
            self.regs.rip += sz as u64;
        } else {
            self.regs.set_eip(self.regs.get_eip() + sz as u64);
        }

        result_ok
    }

    ///  RUN ENGINE ///
    pub fn run(&mut self, end_addr: Option<u64>) -> Result<u64, MwemuError> {
        self.is_running.store(1, atomic::Ordering::Relaxed);
        let is_running2 = Arc::clone(&self.is_running);

        if self.enabled_ctrlc {
            ctrlc::set_handler(move || {
                log::info!("Ctrl-C detected, spawning console");
                is_running2.store(0, atomic::Ordering::Relaxed);
            })
            .expect("ctrl-c handler failed");
        }

        let mut looped: Vec<u64> = Vec::new();
        let mut prev_addr: u64 = 0;
        //let mut prev_prev_addr:u64 = 0;
        let mut repeat_counter: u32 = 0;

        if end_addr.is_none() {
            log::info!(" ----- emulation -----");
        }

        //let ins = Instruction::default();
        let mut formatter = IntelFormatter::new();
        formatter.options_mut().set_digit_separator("");
        formatter.options_mut().set_first_operand_char_index(6);

        //self.pos = 0;

        loop {
            while self.is_running.load(atomic::Ordering::Relaxed) == 1 {
                //log::info!("reloading rip 0x{:x}", self.regs.rip);
                let code = match self.maps.get_mem_by_addr(self.regs.rip) {
                    Some(c) => c,
                    None => {
                        log::info!(
                            "redirecting code flow to non maped address 0x{:x}",
                            self.regs.rip
                        );
                        Console::spawn_console(self);
                        return Err(MwemuError::new("cannot read program counter"));
                    }
                };
                let block = code.read_from(self.regs.rip).to_vec();
                let mut decoder;

                if self.cfg.is_64bits {
                    decoder = Decoder::with_ip(64, &block, self.regs.rip, DecoderOptions::NONE);
                } else {
                    decoder =
                        Decoder::with_ip(32, &block, self.regs.get_eip(), DecoderOptions::NONE);
                }

                let mut ins: Instruction = Instruction::default();
                let mut sz: usize = 0;
                let mut addr: u64 = 0;

                self.rep = None;
                while decoder.can_decode() {
                    if self.rep.is_none() {
                        ins = decoder.decode();
                        sz = ins.len();
                        addr = ins.ip();

                        if end_addr.is_some() && Some(addr) == end_addr {
                            return Ok(self.regs.rip);
                        }
                    }

                    self.out.clear();
                    formatter.format(&ins, &mut self.out);
                    self.instruction = Some(ins);
                    self.decoder_position = decoder.position();
                    self.memory_operations.clear();
                    self.pos += 1;

                    if self.cfg.exit_position != 0 && self.pos == self.cfg.exit_position {
                        log::info!("exit position reached");
                        std::process::exit(0);
                    }

                    if self.exp == self.pos
                        || self.pos == self.bp.get_instruction()
                        || self.bp.get_bp() == addr
                        || (self.cfg.console2 && self.cfg.console_addr == addr)
                    {
                        if self.running_script {
                            return Ok(self.regs.rip);
                        }

                        self.cfg.console2 = false;
                        log::info!("-------");
                        log::info!("{} 0x{:x}: {}", self.pos, ins.ip(), self.out);
                        Console::spawn_console(self);
                        if self.force_break {
                            self.force_break = false;
                            break;
                        }
                    }

                    // prevent infinite loop
                    if self.rep.is_none() {
                        if addr == prev_addr {
                            // || addr == prev_prev_addr {
                            repeat_counter += 1;
                        }
                        //prev_prev_addr = prev_addr;
                        prev_addr = addr;
                        if repeat_counter == 100 {
                            log::info!(
                                "infinite loop!  opcode: {}",
                                ins.op_code().op_code_string()
                            );
                            return Err(MwemuError::new("inifinite loop found"));
                        }

                        if self.cfg.loops {
                            // loop detector
                            looped.push(addr);
                            let mut count: u32 = 0;
                            for a in looped.iter() {
                                if addr == *a {
                                    count += 1;
                                }
                            }
                            if count > 2 {
                                log::info!("    loop: {} interations", count);
                            }
                            /*
                            if count > self.loop_limit {
                            panic!("/!\\ iteration limit reached");
                            }*/
                            //TODO: if more than x addresses remove the bottom ones
                        }
                    }

                    if self.cfg.trace_filename.is_some() && self.pos >= self.cfg.trace_start {
                        self.capture_pre_op();
                    }

                    if self.cfg.trace_reg {
                        for reg in self.cfg.reg_names.iter() {
                            self.trace_specific_register(reg);
                        }
                    }

                    if self.cfg.trace_string {
                        self.trace_string();
                    }

                    //let mut info_factory = InstructionInfoFactory::new();
                    //let info = info_factory.info(&ins);

                    if let Some(hook_fn) = self.hooks.hook_on_pre_instruction {
                        hook_fn(self, self.regs.rip, &ins, sz)
                    }

                    if ins.has_rep_prefix() || ins.has_repe_prefix() || ins.has_repne_prefix() {
                        if self.rep.is_none() {
                            self.rep = Some(0);
                        }

                        // if rcx is 0 in first rep step, skip instruction.
                        if self.regs.rcx == 0 {
                            self.rep = None;
                            if self.cfg.is_64bits {
                                self.regs.rip += sz as u64;
                            } else {
                                self.regs.set_eip(self.regs.get_eip() + sz as u64);
                            }
                            continue;
                        }
                    }

                    /*************************************/
                    let emulation_ok = engine::emulate_instruction(self, &ins, sz, false);
                    /*************************************/

                    if let Some(rep_count) = self.rep {
                        if self.regs.rcx > 0 {
                            self.regs.rcx -= 1;
                            if self.regs.rcx == 0 {
                                self.rep = None;
                            } else {
                                self.rep = Some(rep_count + 1);
                            }
                        }

                        // repe and repe are the same on x86 (0xf3) so you have to check if it is movement or comparison
                        let is_string_movement = matches!(
                            ins.mnemonic(),
                            Mnemonic::Movsb
                                | Mnemonic::Movsw
                                | Mnemonic::Movsd
                                | Mnemonic::Movsq
                                | Mnemonic::Stosb
                                | Mnemonic::Stosw
                                | Mnemonic::Stosd
                                | Mnemonic::Stosq
                                | Mnemonic::Lodsb
                                | Mnemonic::Lodsw
                                | Mnemonic::Lodsd
                                | Mnemonic::Lodsq
                        );
                        let is_string_comparison = matches!(
                            ins.mnemonic(),
                            Mnemonic::Cmpsb
                                | Mnemonic::Cmpsw
                                | Mnemonic::Cmpsd
                                | Mnemonic::Cmpsq
                                | Mnemonic::Scasb
                                | Mnemonic::Scasw
                                | Mnemonic::Scasd
                                | Mnemonic::Scasq
                        );
                        if is_string_movement {
                            // do not clear rep if it is a string movement
                        } else if is_string_comparison {
                            if ins.has_repe_prefix() && !self.flags.f_zf {
                                self.rep = None;
                            }
                            if ins.has_repne_prefix() && self.flags.f_zf {
                                self.rep = None;
                            }
                        } else {
                            unimplemented!("string instruction not supported");
                        }
                    }

                    if let Some(hook_fn) = self.hooks.hook_on_post_instruction {
                        hook_fn(self, self.regs.rip, &ins, sz, emulation_ok)
                    }

                    if self.cfg.inspect {
                        self.trace_memory_inspection();
                    }

                    if self.cfg.trace_filename.is_some() && self.pos >= self.cfg.trace_start {
                        self.capture_post_op();
                        self.write_to_trace_file();
                    }

                    if !emulation_ok {
                        if self.cfg.console_enabled {
                            Console::spawn_console(self);
                        } else {
                            return Err(MwemuError::new(&format!("emulation error at pos = {} rip = 0x{:x}", self.pos, self.regs.rip)));
                        }
                    }

                    if self.force_reload {
                        self.force_reload = false;
                        break;
                    }

                    if self.rep.is_none() {
                        if self.cfg.is_64bits {
                            self.regs.rip += sz as u64;
                        } else {
                            self.regs.set_eip(self.regs.get_eip() + sz as u64);
                        }
                    }

                    if self.force_break {
                        self.force_break = false;
                        break;
                    }
                } // end decoder loop
            } // end running loop

            self.is_running.store(1, atomic::Ordering::Relaxed);
            Console::spawn_console(self);
        } // end infinite loop
    } // end run
}
