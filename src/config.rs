
pub struct Config {
    pub trace_mem: bool,    // show memory operations in every step
    pub trace_regs: bool,   // show all the regs in every step
    pub trace_reg: bool,    // show value and content of a reg in every step
    pub reg_name: String,   // which reg to trace
    pub verbose: u32,       // 0 only view the api, 1 api + messages, 2 asm code
    pub console: bool,      // enable the console on specific moment?
    pub console_num: u64,   // in which moment enable the console
    pub loops: bool,
    pub nocolors: bool,
    pub trace_string: bool,
    pub string_addr: u32,
    pub inspect: bool,
    pub inspect_seq: String,
}

impl Config {
    pub fn new() -> Config {
        Config {
            trace_mem: false,
            trace_regs: false,
            trace_reg: false,
            reg_name: "".to_string(),
            verbose: 0,
            console: false,
            console_num: 0,
            loops: false,
            nocolors:  false,
            trace_string: false,
            string_addr: 0,
            inspect: false,
            inspect_seq: "".to_string(),
        }
    }
}
