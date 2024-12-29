use serde::{Serialize, Deserialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct Breakpoint {
    addr: u64,
    instruction: u64,
    mem_read_addr: u64,
    mem_write_addr: u64,
}

impl Default for Breakpoint {
    fn default() -> Self {
        Self::new()
    }
}

impl Breakpoint {
    pub fn new() -> Breakpoint {
        Breakpoint {
            addr: 0,
            instruction: 0,
            mem_read_addr: 0,
            mem_write_addr: 0,
        }
    }

    pub fn set_bp(&mut self, addr: u64) {
        self.addr = addr;
    }

    pub fn clear_bp(&mut self) {
        self.addr = 0;
        self.mem_read_addr = 0;
        self.mem_write_addr = 0;
    }

    pub fn set_mem_read(&mut self, addr: u64) {
        self.mem_read_addr = addr;
    }

    pub fn set_mem_write(&mut self, addr: u64) {
        self.mem_write_addr = addr;
    }

    pub fn set_instruction(&mut self, ins: u64) {
        self.instruction = ins;
    }

    pub fn get_bp(&self) -> u64 {
        self.addr
    }

    pub fn get_mem_read(&self) -> u64 {
        self.mem_read_addr
    }

    pub fn get_mem_write(&self) -> u64 {
        self.mem_write_addr
    }

    pub fn get_instruction(&self) -> u64 {
        self.instruction
    }

    pub fn show(&self) {
        log::info!("break on address: 0x{:x}", self.addr);
        log::info!("break on instruction: {}", self.instruction);
        log::info!("break on memory read: 0x{:x}", self.mem_read_addr);
        log::info!("break on memory write: 0x{:x}", self.mem_write_addr);
    }
}
