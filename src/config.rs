
pub struct Config {
    pub trace_mem: bool,    // show memory operations in every step
    pub trace_regs: bool,   // show all the regs in every step
    pub trace_reg: bool,    // show value and content of a reg in every step
    pub reg_name: String,   // which reg to trace
    pub quick_mode: bool,  // dont print the asm, only relevant things
    pub console: bool,      // enable the console on specific moment?
    pub console_num: u64,   // in which moment enable the console
    pub loops: bool,
    pub nocolors: bool,
    pub trace_string: bool,
    pub string_addr: u32,
    pub trace_dword: bool,
    pub dword_addr:u32,
    pub trace_word: bool,
    pub word_addr: u32,
    pub trace_bytes: bool,
    pub bytes_addr: u32,
}


impl Config {
    pub fn new() -> Config {
        Config {
            trace_mem: false,
            trace_regs: false,
            trace_reg: false,
            reg_name: "".to_string(),
            quick_mode: false,
            console: false,
            console_num: 0,
            loops: false,
            nocolors:  false,
            trace_string: false,
            string_addr: 0,
            trace_dword: false,
            dword_addr: 0,
            trace_word: false,
            word_addr: 0,
            trace_bytes: false,
            bytes_addr: 0,
        }
    }
}
