use env_logger::Env;
use libmwemu::emu32;
use libmwemu::emu64;
use std::io::Write as _;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

#[pyclass]
pub struct Emu {
    emu: libmwemu::emu::Emu,
}

#[pymethods]
#[allow(deprecated)]
impl Emu {
    /// get pymwemu version.
    fn version(&self) -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }

    /// get last emulated mnemonic with name and parameters.
    fn get_prev_mnemonic(&self) -> PyResult<String> {
        Ok(self.emu.out.clone())
    }

    /// reset the instruction counter to zero.
    fn reset_pos(&mut self) {
        self.emu.pos = 0;
    }

    /// check if the emulator is in 64bits mode.
    fn is_64bits(&self) -> PyResult<bool> {
        Ok(self.emu.cfg.is_64bits)
    }

    /// check if the emulator is in 32bits mode.
    fn is_32bits(&self) -> PyResult<bool> {
        Ok(!self.emu.cfg.is_64bits)
    }

    /// change base address on ldr entry of a module
    fn update_ldr_entry_base(&mut self, libname: &str, base: u64) {
        self.emu.update_ldr_entry_base(libname, base);
    }

    /// Set 64bits mode, it's necessary to load the 64bits maps with load_maps() method.
    /// Or better can use: emu = pymwemu.init64()
    fn set_64bits(&mut self) {
        self.emu.cfg.is_64bits = true;
    }

    /// Set 32bits mode, it's necessary to load the 32bits maps with load_maps() method.
    /// Or better can use: emu = pymwemu.init32()
    fn set_32bits(&mut self) {
        self.emu.cfg.is_64bits = false;
    }

    /// disable the colored mode for instructions, api calls and other logs.
    fn disable_colors(&mut self) {
        self.emu.cfg.nocolors = true;
    }

    /// enable the colored mode.
    fn enable_colors(&mut self) {
        self.emu.cfg.nocolors = false;
    }

    /// trace all memory reads and writes.
    fn enable_trace_mem(&mut self) {
        self.emu.cfg.trace_mem = true;
    }

    /// disable the memory tracer.
    fn disable_trace_mem(&mut self) {
        self.emu.cfg.trace_mem = false;
    }

    /// trace all the registers printing them in every step.
    fn enable_trace_regs(&mut self) {
        self.emu.cfg.trace_regs = true;
    }

    /// disable the register tracer.
    fn disable_trace_regs(&mut self) {
        self.emu.cfg.trace_regs = false;
    }

    /// trace a specific list of registers, provide  array of strings with register names in lower case.
    fn enable_trace_reg(&mut self, regs: Vec<String>) {
        self.emu.cfg.trace_reg = true;
        self.emu.cfg.reg_names = regs;
    }

    /// disable the multi-register tracer.
    fn disable_trace_reg(&mut self) {
        self.emu.cfg.trace_reg = false;
        self.emu.cfg.reg_names.clear();
    }

    /// inspect sequence
    fn inspect_seq(&mut self, s: &str) {
        self.emu.cfg.inspect = true;
        self.emu.cfg.inspect_seq = s.to_string();
    }

    /// address to api name
    fn api_addr_to_name(&mut self, addr: u64) -> String {
        self.emu.api_addr_to_name(addr)
    }

    /// api name to address
    fn api_name_to_addr(&mut self, name: &str) -> u64 {
        self.emu.api_name_to_addr(name)
    }

    /// set the verbosity between 0 and 3.
    ///     0: only show api calls.
    ///     1: show api calls and some logs.
    ///     2: show also instructions (slower).
    ///     3: show every iteration of rep preffix.
    fn set_verbose(&mut self, verbose: u32) {
        self.emu.cfg.verbose = verbose;
    }

    /// Set the base address of stack memory map
    fn set_stack_base(&mut self, addr: u64) {
        self.emu.cfg.stack_addr = addr;
    }

    /// when the execution reached a specified amount of steps will spawn an interactive console.
    fn spawn_console_at_pos(&mut self, position: u64) {
        //self.emu.cfg.console = true;
        //self.emu.cfg.console_num = position;
        self.emu.cfg.console_enabled = true;
        self.emu.spawn_console_at(position);
    }

    /// when the execution reached a specified address will spawn an interactive console.
    fn spawn_console_at_addr(&mut self, addr: u64) {
        self.emu.cfg.console2 = true;
        self.emu.cfg.console_addr = addr;
        self.emu.cfg.console_enabled = true;
    }

    /// disable the console spawning.
    fn disable_spawn_console_at_pos(&mut self) {
        self.emu.cfg.console_num = 0;
    }

    /// allow to enable the console if its needed.
    fn enable_console(&mut self) {
        self.emu.cfg.console_enabled = true;
    }

    /// disable the console, to prevent to be spawned in some situations.
    fn disable_console(&mut self) {
        self.emu.cfg.console_enabled = false;
    }

    /// enable the loops counter, this feature slows down the emulation but count the iteration number.
    fn enable_count_loops(&mut self) {
        self.emu.cfg.loops = true;
    }

    /// disable the loops counting system.
    fn disable_count_loops(&mut self) {
        self.emu.cfg.loops = false;
    }

    /// enable tracing a string on a specified memory address.
    fn enable_trace_string(&mut self, addr: u64) {
        self.emu.cfg.trace_string = true;
        self.emu.cfg.string_addr = addr;
    }

    /// disable the string tracer.
    fn disable_trace_string(&mut self) {
        self.emu.cfg.trace_string = false;
        self.emu.cfg.string_addr = 0;
    }

    /// inspect a memory area by providing a stirng like 'dword ptr [esp + 0x8]'
    fn enable_inspect_sequence(&mut self, seq: &str) {
        self.emu.cfg.inspect = true;
        self.emu.cfg.inspect_seq = seq.to_string();
    }

    /// disable the memory inspector.
    fn disable_inspect_sequence(&mut self) {
        self.emu.cfg.inspect = false;
    }

    /*
    /// give the binary the posibility of connecting remote hosts to get next stage, use it safelly.
    fn enable_endpoint_mode(&mut self) {
        self.emu.cfg.endpoint = true;
    }

    /// disable the endpoint mode.
    fn disable_endpoint_mode(&mut self) {
        self.emu.cfg.endpoint = false;
    }*/

    /// change the default entry point.
    fn set_entry_point(&mut self, addr: u64) {
        self.emu.cfg.entry_point = addr;
    }

    /// rebase the program address.
    fn set_base_address(&mut self, addr: u64) {
        self.emu.cfg.code_base_addr = addr;
    }

    /// enable the stack tracer.
    fn enable_stack_trace(&mut self) {
        self.emu.cfg.stack_trace = true;
    }

    /// disable the stack tracer.
    fn disable_stack_trace(&mut self) {
        self.emu.cfg.stack_trace = false;
    }

    /// test mode use inline assembly to contrast the result of emulation and detect bugs.
    fn enable_test_mode(&mut self) {
        self.emu.cfg.test_mode = true;
    }

    /// disable the test mode.
    fn disable_test_mode(&mut self) {
        self.emu.cfg.test_mode = false;
    }

    /// Enable banzai mode. This mode keep emulating after finding unimplemented instructions or apis.
    fn enable_banzai_mode(&mut self) {
        self.emu.cfg.skip_unimplemented = true;
    }

    /// disable banzai mode.
    fn disable_banzai_mode(&mut self) {
        self.emu.cfg.skip_unimplemented = false;
    }

    /// Add API to banzai.
    fn banzai_add(&mut self, apiname: &str, nparams: i32) {
        self.emu.banzai_add(apiname, nparams);
    }

    /// enable the Control-C handling for spawning console.
    fn enable_ctrlc(&mut self) {
        self.emu.enable_ctrlc();
    }

    /// disable the Control-C handling.
    fn disable_ctrlc(&mut self) {
        self.emu.disable_ctrlc();
    }

    // end of config

    /// It is necessary to load the 32bits or 64bits maps folder for having a realistic memory layout.
    /// The maps can be downloaded from the https://github.com/sha0coder/mwemu
    fn load_maps(&mut self, folder: &str) {
        self.emu.cfg.maps_folder = folder.to_string();
        self.emu.init(false, false);
    }

    /// Load the binary to be emulated.
    fn load_binary(&mut self, filename: &str) {
        self.emu.load_code(filename);
    }

    /// Load code from bytes
    fn load_code_bytes(&mut self, bytes: &[u8]) {
        self.emu.load_code_bytes(bytes);
    }

    /// allocate a buffer on the emulated process address space.  
    fn alloc(&mut self, name: &str, size: u64) -> PyResult<u64> {
        Ok(self.emu.alloc(name, size))
    }

    /// allocate at specific address
    fn alloc_at(&mut self, name: &str, addr: u64, size: u64) {
        self.emu
            .maps
            .create_map(name, addr, size)
            .expect("pymwemu alloc_at out of memory");
    }

    /// load an aditional blob to the memory layout.
    fn load_map(&mut self, name: &str, filename: &str, base_addr: u64) {
        let map = self
            .emu
            .maps
            .create_map(name, base_addr, 1)
            .expect("pymwemu load_map out of memory");
        map.load(filename);
    }

    /// link library
    fn link_library(&mut self, filepath: &str) -> PyResult<u64> {
        Ok(self.emu.link_library(filepath))
    }

    /// push a 32bits value to the stack.
    fn stack_push32(&mut self, value: u32) -> PyResult<bool> {
        if self.emu.stack_push32(value) {
            Ok(true)
        } else {
            Err(PyValueError::new_err("pushing error"))
        }
    }

    /// push a 64bits value to the stack.
    fn stack_push64(&mut self, value: u64) -> PyResult<bool> {
        if self.emu.stack_push64(value) {
            Ok(true)
        } else {
            Err(PyValueError::new_err("pushing error"))
        }
    }

    /// pop a 32bits value from the stack.
    fn stack_pop32(&mut self) -> PyResult<u32> {
        match self.emu.stack_pop32(false) {
            Some(v) => Ok(v),
            None => Err(PyValueError::new_err("popping error")),
        }
    }

    /// pop a 64bits value from the stack.
    fn stack_pop64(&mut self) -> PyResult<u64> {
        match self.emu.stack_pop64(false) {
            Some(v) => Ok(v),
            None => Err(PyValueError::new_err("popping error")),
        }
    }

    /// set rip register, if rip point to an api will be emulated.
    fn set_rip(&mut self, addr: u64) -> PyResult<bool> {
        Ok(self.emu.set_rip(addr, false))
    }

    /// set eip register, if eip point to an api will be emulated.
    fn set_eip(&mut self, addr: u64) -> PyResult<bool> {
        Ok(self.emu.set_eip(addr, false))
    }

    /// spawn an interactive console.
    fn spawn_console(&mut self) {
        self.emu.cfg.console_enabled = true;
        self.emu.spawn_console();
    }

    /// disassemble an address.
    fn disassemble(&mut self, addr: u64, amount: u32) -> PyResult<String> {
        Ok(self.emu.disassemble(addr, amount))
    }

    /*
    fn stop(&mut self) {
        self.emu.stop();
    }*/

    /// start emulating the binary after finding the first return.
    fn run_until_return(&mut self) -> PyResult<u64> {
        match self.emu.run_until_ret() {
            Ok(pc) => Ok(pc),
            Err(e) => Err(PyValueError::new_err(e.message)),
        }
    }

    /// emulate a single step, this is slower than run(address) or run(0)
    fn step(&mut self) -> PyResult<bool> {
        Ok(self.emu.step())
    }

    /// Start emulating the binary until reach the provided end_addr.
    /// Use run() with no params for emulating forever. or call32/call64 for calling a function.
    fn run(&mut self, end_addr: Option<u64>) -> PyResult<u64> {
        match self.emu.run(end_addr) {
            Ok(pc) => Ok(pc),
            Err(e) => Err(PyValueError::new_err(e.message)),
        }
    }

    /// read the number of instructions emulated since now.
    fn get_position(&mut self) -> PyResult<u64> {
        Ok(self.emu.pos)
    }

    /// call a 32bits function, internally pushes params in reverse order.
    fn call32(&mut self, address: u64, params: Vec<u64>) -> PyResult<u32> {
        match self.emu.call32(address, &params) {
            Ok(pc) => Ok(pc),
            Err(e) => Err(PyValueError::new_err(e.message)),
        }
    }

    /// call a 64bits function, internally pushes params in reverse order.
    fn call64(&mut self, address: u64, params: Vec<u64>) -> PyResult<u64> {
        match self.emu.call64(address, &params) {
            Ok(pc) => Ok(pc),
            Err(e) => Err(PyValueError::new_err(e.message)),
        }
    }

    // registers

    /// read register value ie get_reg('rax')
    fn get_reg(&mut self, reg: &str) -> PyResult<u64> {
        if self.emu.regs.is_reg(reg) {
            return Ok(self.emu.regs.get_by_name(reg));
        }
        Err(PyValueError::new_err("invalid register name"))
    }

    /// set register value ie  set_reg('rax', 0x123), returns previous value.
    fn set_reg(&mut self, reg: &str, value: u64) -> PyResult<u64> {
        if self.emu.regs.is_reg(reg) {
            let prev = self.emu.regs.get_by_name(reg);
            self.emu.regs.set_by_name(reg, value);
            Ok(prev)
        } else {
            Err(PyValueError::new_err("invalid register name"))
        }
    }

    /// get the value of a xmm register.
    fn get_xmm(&mut self, reg: &str) -> PyResult<u128> {
        if self.emu.regs.is_xmm_by_name(reg) {
            return Ok(self.emu.regs.get_xmm_by_name(reg));
        }
        Err(PyValueError::new_err("invalid register name"))
    }

    /// set a value to a xmm register.
    fn set_xmm(&mut self, reg: &str, value: u128) -> PyResult<u128> {
        if self.emu.regs.is_xmm_by_name(reg) {
            let prev = self.emu.regs.get_xmm_by_name(reg);
            self.emu.regs.set_xmm_by_name(reg, value);
            Ok(prev)
        } else {
            Err(PyValueError::new_err("invalid register name"))
        }
    }

    // memory

    /*fn create_map(&mut self,  name:&str) {
        self.emu.maps.create_map(name);
    }*/

    /// write a little endian qword on memory.
    fn write_qword(&mut self, addr: u64, value: u64) -> PyResult<bool> {
        if self.emu.maps.write_qword(addr, value) {
            Ok(true)
        } else {
            Err(PyValueError::new_err("writting on non allocated address"))
        }
    }

    /// write a little endian dword on memory.
    fn write_dword(&mut self, addr: u64, value: u32) -> PyResult<bool> {
        if self.emu.maps.write_dword(addr, value) {
            Ok(true)
        } else {
            Err(PyValueError::new_err("writting on non allocated address"))
        }
    }

    /// write a little endian word on memory.
    fn write_word(&mut self, addr: u64, value: u16) -> PyResult<bool> {
        if self.emu.maps.write_word(addr, value) {
            Ok(true)
        } else {
            Err(PyValueError::new_err("writting on non allocated address"))
        }
    }

    /// write a byte on memory.
    fn write_byte(&mut self, addr: u64, value: u8) -> PyResult<bool> {
        if self.emu.maps.write_byte(addr, value) {
            Ok(true)
        } else {
            Err(PyValueError::new_err("writting on non allocated address"))
        }
    }

    /// read 128bits big endian.
    fn read_128bits_be(&self, addr: u64) -> PyResult<u128> {
        match self.emu.maps.read_128bits_be(addr) {
            Some(v) => Ok(v),
            None => Err(PyValueError::new_err("reading on non allocated address")),
        }
    }

    /// read 128bits little endian.
    fn read_128bits_le(&self, addr: u64) -> PyResult<u128> {
        match self.emu.maps.read_128bits_le(addr) {
            Some(v) => Ok(v),
            None => Err(PyValueError::new_err("reading on non allocated address")),
        }
    }

    /// read little endian qword.
    fn read_qword(&self, addr: u64) -> PyResult<u64> {
        match self.emu.maps.read_qword(addr) {
            Some(v) => Ok(v),
            None => Err(PyValueError::new_err("reading on non allocated address")),
        }
    }

    /// read little endian dword.
    fn read_dword(&self, addr: u64) -> PyResult<u32> {
        match self.emu.maps.read_dword(addr) {
            Some(v) => Ok(v),
            None => Err(PyValueError::new_err("reading on non allocated address")),
        }
    }

    /// read little endian word.
    fn read_word(&self, addr: u64) -> PyResult<u16> {
        match self.emu.maps.read_word(addr) {
            Some(v) => Ok(v),
            None => Err(PyValueError::new_err("reading on non allocated address")),
        }
    }

    /// read a byte from a memory address.
    fn read_byte(&self, addr: u64) -> PyResult<u8> {
        match self.emu.maps.read_byte(addr) {
            Some(v) => Ok(v),
            None => Err(PyValueError::new_err("reading on non allocated address")),
        }
    }

    /// fill a memory chunk starting at `address`, with a specified `amount` of bytes defined in `byte`.
    fn memset(&mut self, addr: u64, byte: u8, amount: usize) {
        self.emu.maps.memset(addr, byte, amount);
    }

    /// get the size of a wide string.
    fn sizeof_wide(&self, unicode_str_ptr: u64) -> PyResult<usize> {
        Ok(self.emu.maps.sizeof_wide(unicode_str_ptr))
    }

    /// write string on memory.
    fn write_string(&mut self, to: u64, from: &str) {
        self.emu.maps.write_string(to, from);
    }

    /// write a wide string on memory.
    pub fn write_wide_string(&mut self, to: u64, from: &str) {
        self.emu.maps.write_wide_string(to, from);
    }

    /// write a python list of int bytes to the emulator memory.
    pub fn write_buffer(&mut self, to: u64, from: &[u8]) {
        self.emu.maps.write_buffer(to, from);
    }

    /// read a buffer from the emulator memory to a python list of int bytes.
    pub fn read_buffer(&mut self, from: u64, sz: usize) -> PyResult<Vec<u8>> {
        Ok(self.emu.maps.read_buffer(from, sz))
    }

    /// write a python list of int bytes to the emulator memory.
    pub fn write_bytes(&mut self, to: u64, from: &[u8]) {
        self.emu.maps.write_buffer(to, from);
    }

    /// print all the maps that match a substring of the keyword provided.
    pub fn print_maps_by_keyword(&self, kw: &str) {
        self.emu.maps.print_maps_keyword(kw);
    }

    /// print all the memory maps on the process address space.
    pub fn print_maps(&self) {
        self.emu.maps.print_maps();
    }

    /// get the base address of a given address. Will make an exception if it's invalid address.
    pub fn get_addr_base(&self, addr: u64) -> PyResult<u64> {
        match self.emu.maps.get_addr_base(addr) {
            Some(v) => Ok(v),
            None => Err(PyValueError::new_err("provided address is not allocated")),
        }
    }

    /// this method checks if the given address is allocated or not.
    pub fn is_mapped(&self, addr: u64) -> PyResult<bool> {
        Ok(self.emu.maps.is_mapped(addr))
    }

    /// get the memory map name where is the given address.
    /// Will cause an exception if the address is not allocated.
    pub fn get_addr_name(&self, addr: u64) -> PyResult<String> {
        match self.emu.maps.get_addr_name(addr) {
            Some(v) => Ok(v),
            None => Err(PyValueError::new_err(
                "the address doesnt pertain to an allocated block",
            )),
        }
    }

    /// visualize the bytes on the given address.
    pub fn dump(&self, addr: u64) {
        self.emu.maps.dump(addr);
    }

    /// visualize the `amount` of bytes provided on `address`.
    pub fn dump_n(&self, addr: u64, amount: u64) {
        self.emu.maps.dump_n(addr, amount);
    }

    /// visualize a number of qwords on given address.
    pub fn dump_qwords(&self, addr: u64, n: u64) {
        self.emu.maps.dump_qwords(addr, n);
    }

    /// visualize a number of dwords on a given address.
    pub fn dump_dwords(&self, addr: u64, n: u64) {
        self.emu.maps.dump_dwords(addr, n);
    }

    /// read an amount of bytes from an address to a python object.
    pub fn read_bytes(&mut self, addr: u64, sz: usize) -> PyResult<&[u8]> {
        Ok(self.emu.maps.read_bytes(addr, sz))
    }

    /// read an amount of bytes from an address to a string of spaced hexa bytes.
    pub fn read_string_of_bytes(&mut self, addr: u64, sz: usize) -> PyResult<String> {
        Ok(self.emu.maps.read_string_of_bytes(addr, sz))
    }

    /// read an ascii string from a memory address,
    /// if the address point to a non allocated zone string will be empty.    
    pub fn read_string(&self, addr: u64) -> PyResult<String> {
        Ok(self.emu.maps.read_string(addr))
    }

    /// read a wide string from a memory address,
    /// if the address point to a non allocated zone string will be empty.    
    pub fn read_wide_string(&self, addr: u64) -> PyResult<String> {
        Ok(self.emu.maps.read_wide_string(addr))
    }

    /// search a substring on a specific memory map name, it will return a list of matched addresses.
    /// if the string is not found, it will return an empty list.
    pub fn search_string(&self, kw: &str, map_name: &str) -> PyResult<Vec<u64>> {
        match self.emu.maps.search_string(kw, map_name) {
            Some(v) => Ok(v),
            None => Ok(Vec::new()),
        }
    }

    /// write on emulators memory a spaced hexa bytes
    pub fn write_spaced_bytes(&mut self, addr: u64, spaced_hex_bytes: &str) -> PyResult<bool> {
        if self.emu.maps.write_spaced_bytes(addr, spaced_hex_bytes) {
            Ok(true)
        } else {
            Err(PyValueError::new_err(
                "couldnt write the bytes on that address",
            ))
        }
    }

    /// search one occurence of a spaced hex bytes from a specific address, will return zero if it's not found.
    pub fn search_spaced_bytes_from(&self, saddr: u64, sbs: &str) -> PyResult<u64> {
        Ok(self.emu.maps.search_spaced_bytes_from(sbs, saddr))
    }

    /// search one occcurence of a spaced hex bytes from an especific address backward,
    /// will return zero if it's not found.
    pub fn search_spaced_bytes_from_bw(&self, saddr: u64, sbs: &str) -> PyResult<u64> {
        Ok(self.emu.maps.search_spaced_bytes_from_bw(sbs, saddr))
    }

    /// search spaced hex bytes string on specific map using its map name,
    /// will return a list with the addresses found if there are matches,
    /// otherwise the list will be empty.
    pub fn search_spaced_bytes(&self, sbs: &str, map_name: &str) -> PyResult<Vec<u64>> {
        Ok(self.emu.maps.search_spaced_bytes(sbs, map_name))
    }

    /// search spaced hex bytes string on all the memory layout,
    /// will return a list with the addresses found if there are matches,
    /// otherwise the list will be empty.
    pub fn search_spaced_bytes_in_all(&self, sbs: &str) -> PyResult<Vec<u64>> {
        Ok(self.emu.maps.search_spaced_bytes_in_all(sbs))
    }

    /// Search a substring in all the memory layout except on libs, will print the results.
    /// In the future will return a list with results instead of printing.
    pub fn search_string_in_all(&self, kw: String) {
        self.emu.maps.search_string_in_all(kw);
    }

    /// search a bytes object on specific map, will return a list with matched addresses if there are any.
    pub fn search_bytes(&self, bkw: Vec<u8>, map_name: &str) -> PyResult<Vec<u64>> {
        Ok(self.emu.maps.search_bytes(bkw, map_name))
    }

    /// show the total allocated memory.
    pub fn allocated_size(&self) -> PyResult<usize> {
        Ok(self.emu.maps.size())
    }

    /// show if there are memory blocks overlaping eachother.
    pub fn memory_overlaps(&self, addr: u64, sz: u64) -> PyResult<bool> {
        Ok(self.emu.maps.overlaps(addr, sz))
    }

    /// show all the memory blocks allocated during the emulation.
    pub fn show_allocs(&self) {
        self.emu.maps.show_allocs();
    }

    /// free a memory map by its name
    pub fn free(&mut self, name: &str) {
        self.emu.maps.free(name);
    }

    /// basic allocator, it looks for a free block of given size,
    /// it only returns the address if its possible, but dont really allocates,
    /// just find the address, you have to load to that address something.
    /// use alloc() method instead if possible.
    pub fn memory_alloc(&self, sz: u64) -> PyResult<u64> {
        match self.emu.maps.alloc(sz) {
            Some(addr) => Ok(addr),
            None => Err(PyValueError::new_err("couldnt found a space of that size")),
        }
    }

    /// Save all memory blocks allocated during emulation to disk.
    /// Provide a folder where every alloc will be a file.
    pub fn save_all_allocs(&mut self, path: String) {
        self.emu.maps.save_all_allocs(path);
    }

    /// save a chunk of memory to disk.
    pub fn save(&mut self, addr: u64, size: u64, filename: String) {
        self.emu.maps.save(addr, size, filename);
    }

    /// perform a memory test to see overlapps or other possible problems.
    pub fn mem_test(&self) -> PyResult<bool> {
        Ok(self.emu.maps.mem_test())
    }

    /// breakpoints
    /// show breakpoints
    pub fn bp_show(&self) {
        self.emu.bp.show();
    }

    /// clear all the breakpoints
    pub fn bp_clear_all(&mut self) {
        self.emu.bp.clear_bp();
    }

    /// set breakpoint on an address
    pub fn bp_set_addr(&mut self, addr: u64) {
        self.emu.bp.set_bp(addr);
    }

    /// get the current address breakpoint
    pub fn bp_get_addr(&self) -> PyResult<u64> {
        Ok(self.emu.bp.get_bp())
    }

    /// set breakpoint on a instruction counter
    pub fn bp_set_inst(&mut self, ins: u64) {
        self.emu.bp.set_instruction(ins);
    }

    /// get breakpoint on a instrunction counter
    pub fn bp_get_inst(&self) -> PyResult<u64> {
        Ok(self.emu.bp.get_instruction())
    }

    /// set a memory breakpoint on read
    pub fn bp_set_mem_read(&mut self, addr: u64) {
        self.emu.bp.set_mem_read(addr);
    }

    /// get the memory breakpoint on read
    pub fn bp_get_mem_read(&self) -> PyResult<u64> {
        Ok(self.emu.bp.get_mem_read())
    }

    /// set a memory breakpoint on write
    pub fn bp_set_mem_write(&mut self, addr: u64) {
        self.emu.bp.set_mem_write(addr);
    }

    /// get the memory breakpoint on write
    pub fn bp_get_mem_write(&self) -> PyResult<u64> {
        Ok(self.emu.bp.get_mem_write())
    }

    /// handle winapi address
    pub fn handle_winapi(&mut self, addr: u64) {
        self.emu.handle_winapi(addr);
    }

    /// emulate until next winapi call
    pub fn run_until_apicall(&mut self) -> PyResult<(u64, String)> {
        self.emu.skip_apicall = true;
        loop {
            if !self.emu.step() {
                match self.emu.its_apicall {
                    Some(addr) => {
                        self.emu.skip_apicall = false;
                        let name = self.emu.api_addr_to_name(addr);
                        self.emu.regs.rip += self.emu.last_instruction_size as u64;
                        return Ok((addr, name));
                    }
                    None => continue,
                }
            }
        }
    }
}

#[pyfunction]
fn init32() -> PyResult<Emu> {
    let mut emu = Emu { emu: emu32() };
    emu.emu.cfg.is_64bits = false;
    emu.emu.cfg.console_enabled = false;
    emu.emu.cfg.verbose = 0;

    Ok(emu)
}

#[pyfunction]
fn init64() -> PyResult<Emu> {
    let mut emu = Emu { emu: emu64() };
    emu.emu.cfg.is_64bits = true;
    emu.emu.cfg.console_enabled = false;
    emu.emu.cfg.verbose = 0;

    Ok(emu)
}

#[pymodule]
fn pymwemu(_py: Python, m: &PyModule) -> PyResult<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info"))
        .format(|buf, record| writeln!(buf, "{}", record.args()))
        .init();
    m.add_function(wrap_pyfunction!(init32, m)?)?;
    m.add_function(wrap_pyfunction!(init64, m)?)?;
    Ok(())
}
