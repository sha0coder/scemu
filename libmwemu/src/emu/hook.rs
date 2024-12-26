use crate::emu;
use iced_x86::Instruction;


// return: false will ignore interrupt handling like 0x80 -> linux
type TypeHookOnInterrupt = fn(emu: &mut emu::Emu, ip_addr: u64, interrupt: u64) -> bool;
// return: allow handle exception?
type TypeHookOnException = fn(emu: &mut emu::Emu, ip_addr: u64) -> bool;
// memory read is pre-read you can modify the value that is going to be read.
type TypeHookOnMemoryRead = fn(emu: &mut emu::Emu, ip_addr: u64, mem_addr: u64, sz: u32);
// the memory write is pre but you can change the value is going to be written.
type TypeHookOnMemoryWrite =
    fn(emu: &mut emu::Emu, ip_addr: u64, mem_addr: u64, sz: u32, value: u128) -> u128;
type TypeHookOnPreInstruction = fn(emu: &mut emu::Emu, ip_addr: u64, ins: &Instruction, sz: usize);
type TypeHookOnPostInstruction =
    fn(emu: &mut emu::Emu, ip_addr: u64, ins: &Instruction, sz: usize, emu_ok: bool);
type TypeHookOnWinApiCall = fn(emu: &mut emu::Emu, ip_addr: u64, called_addr: u64) -> bool;



pub struct Hook {
    pub hook_on_interrupt: Option<TypeHookOnInterrupt>,
    pub hook_on_exception: Option<TypeHookOnException>,
    pub hook_on_memory_read: Option<TypeHookOnMemoryRead>,
    pub hook_on_memory_write: Option<TypeHookOnMemoryWrite>,
    pub hook_on_pre_instruction: Option<TypeHookOnPreInstruction>,
    pub hook_on_post_instruction: Option<TypeHookOnPostInstruction>,
    pub hook_on_winapi_call: Option<TypeHookOnWinApiCall>,
}

impl Hook {
    pub fn new() -> Hook {
        Hook {
            hook_on_interrupt: None,
            hook_on_exception: None,
            hook_on_memory_read: None,
            hook_on_memory_write: None,
            hook_on_pre_instruction: None,
            hook_on_post_instruction: None,
            hook_on_winapi_call: None,
        }
    }

    pub fn on_interrupt(&mut self, hook: TypeHookOnInterrupt) {
        self.hook_on_interrupt = Some(hook);
    }

    pub fn disable_interrupt(&mut self) {
        self.hook_on_interrupt = None;
    }

    pub fn on_exception(&mut self, hook: TypeHookOnException) {
        self.hook_on_exception = Some(hook);
    }

    pub fn disable_exception(&mut self) {
        self.hook_on_exception = None;
    }

    pub fn on_memory_read(&mut self, hook: TypeHookOnMemoryRead) {
        self.hook_on_memory_read = Some(hook);
    }

    pub fn disable_memory_read(&mut self) {
        self.hook_on_memory_read = None;
    }

    pub fn on_memory_write(&mut self, hook: TypeHookOnMemoryWrite) {
        self.hook_on_memory_write = Some(hook);
    }

    pub fn disable_memory_write(&mut self) {
        self.hook_on_memory_write = None;
    }

    pub fn on_pre_instruction(&mut self, hook: TypeHookOnPreInstruction) {
        self.hook_on_pre_instruction = Some(hook);
    }

    pub fn disable_pre_instruction(&mut self) {
        self.hook_on_pre_instruction = None;
    }

    pub fn on_post_instruction(&mut self, hook: TypeHookOnPostInstruction) {
        self.hook_on_post_instruction = Some(hook);
    }

    pub fn disable_post_instruction(&mut self) {
        self.hook_on_post_instruction = None;
    }

    pub fn on_winapi_call(&mut self, hook: TypeHookOnWinApiCall) {
        self.hook_on_winapi_call = Some(hook);
    }

    pub fn disable_winapi_call(&mut self) {
        self.hook_on_winapi_call = None;
    }
}
