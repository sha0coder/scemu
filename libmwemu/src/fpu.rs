use iced_x86::Register;
use crate::emu;

pub struct FPUState {
    pub fpu_control_word: u16,               // Control Word
    pub fpu_status_word: u16,               // Status Word
    pub fpu_tag_word: u16,                // Tag Word
    pub reserved1: u8,
    pub fpu_opcode: u16,               // Opcode
    pub rip: u64,               // Instruction Pointer
    pub rdp: u64,               // Data Pointer
    pub mxcsr: u32,             // SSE Control and Status
    pub mxcsr_mask: u32,
    pub st: [u128; 8],          // FPU registers (packed in 128 bits each)
    pub xmm: [u128; 16],        // XMM registers
    pub reserved2: [u8; 224],   // Reserved
}

impl FPUState {
    pub fn new() -> Self {
        Self {
            fpu_control_word: 0,
            fpu_status_word: 0,
            fpu_tag_word: 0,
            reserved1: 0,
            fpu_opcode: 0,
            rip: 0,
            rdp: 0,
            mxcsr: 0,
            mxcsr_mask: 0,
            st: [0; 8],
            xmm: [0; 16],
            reserved2: [0; 224],
        }
    }

    pub fn load(addr: u64, emu: &mut emu::Emu) -> FPUState {
        let mut state = FPUState::new();
        state.fpu_control_word = emu.maps.read_word(addr).unwrap();
        state.fpu_status_word = emu.maps.read_word(addr + 2).unwrap();
        state.fpu_tag_word = emu.maps.read_word(addr + 4).unwrap();
        state.fpu_opcode = emu.maps.read_word(addr + 6).unwrap();
        state.rip = emu.maps.read_qword(addr + 8).unwrap();
        state.rdp = emu.maps.read_qword(addr + 16).unwrap();
        state.mxcsr = emu.maps.read_dword(addr + 24).unwrap();
        state.mxcsr_mask = emu.maps.read_dword(addr + 28).unwrap();
        state
    }

    pub fn save(&self, addr: u64, emu: &mut emu::Emu) {
        emu.maps.write_word(addr, self.fpu_control_word);          // FCW (offset 0)
        emu.maps.write_word(addr + 2, self.fpu_status_word);       // FSW (offset 2)
        emu.maps.write_word(addr + 4, self.fpu_tag_word);          // FTW (offset 4)
        emu.maps.write_word(addr + 6, self.fpu_opcode);            // FOP (offset 6)
        emu.maps.write_qword(addr + 8, self.rip);                  // RIP (offset 8)
        emu.maps.write_qword(addr + 16, self.rdp);                 // RDP (offset 16)
        emu.maps.write_dword(addr + 24, self.mxcsr);               // MXCSR (offset 24)
        emu.maps.write_dword(addr + 28, self.mxcsr_mask);          // MXCSR_MASK (offset 28)
    }
}

#[derive(Clone)]
pub struct FPU {
    pub st: Vec<f64>,
    pub st_depth: u8,
    pub tag: u16,
    pub stat: u16,
    pub ctrl: u16,
    pub ip: u64,
    pub err_off: u32,
    pub err_sel: u32,
    pub code_segment: u16,
    pub data_segment: u16,
    pub operand_ptr: u64,
    pub reserved: [u8; 14],
    pub reserved2: [u8; 96],
    pub xmm: [u128; 16],
    pub top: i8,
    pub f_c0: bool, // overflow
    pub f_c1: bool, // underflow
    pub f_c2: bool, // div by zero
    pub f_c3: bool, // precission
    pub f_c4: bool, // stack fault
    pub mxcsr: u32,
    pub fpu_control_word: u16,
    pub opcode: u16,
}

impl Default for FPU {
    fn default() -> Self {
        Self::new()
    }
}

impl FPU {
    pub fn new() -> FPU {
        FPU {
            st: vec![0.0; 8],
            st_depth: 0,
            tag: 0xffff,
            stat: 0,
            ctrl: 0x027f,
            ip: 0,
            err_off: 0,
            err_sel: 0,
            code_segment: 0,
            data_segment: 0,
            operand_ptr: 0,
            reserved: [0; 14],
            reserved2: [0; 96],
            xmm: [0; 16],
            top: 0,
            f_c0: false, // overflow
            f_c1: false, // underflow
            f_c2: false, // div by zero
            f_c3: false, // precision
            f_c4: false, // stack fault
            mxcsr: 0,
            fpu_control_word: 0,
            opcode: 0,
        }
    }

    pub fn clear(&mut self) {
        self.st.clear();
        self.st_depth = 0;
        self.st = vec![0.0; 8];
        self.tag = 0xffff;
        self.stat = 0;
        self.ctrl = 0x037f;
        self.ip = 0;
        self.err_off = 0;
        self.err_sel = 0;
        self.code_segment = 0;
        self.data_segment = 0;
        self.operand_ptr = 0;
        self.reserved = [0; 14];
        self.reserved2 = [0; 96];
        self.xmm = [0; 16];
        self.fpu_control_word = 0;
    }

    pub fn set_ctrl(&mut self, ctrl: u16) {
        self.ctrl = ctrl;
    }

    pub fn get_ctrl(&self) -> u16 {
        self.ctrl
    }

    pub fn set_ip(&mut self, ip: u64) {
        self.ip = ip;
    }

    pub fn inc_top(&mut self) {
        self.top = (self.top + 1) % 8;
    }

    pub fn dec_top(&mut self) {
        if self.top == 0 {
            self.top = 7;
        } else {
            self.top -= 1;
        }
    }

    pub fn get_env32(&self) -> Vec<u32> {
        let mut r: Vec<u32> = Vec::new();
        let mut r1: u32 = self.tag as u32;
        r1 <<= 16;
        r1 += self.ctrl as u32;
        r.push(r1);
        r.push(0xffff0000);
        r.push(0xffffffff);
        r.push(self.ip as u32);
        r
    }

    pub fn get_env64(&self) -> Vec<u64> {
        let mut r: Vec<u64> = Vec::new();
        let mut r1: u64 = self.tag as u64;
        r1 <<= 16;
        r1 += self.ctrl as u64;
        r.push(r1);
        r.push(0xffff0000);
        r.push(0xffffffff);
        r.push(self.ip);
        r
    }

    pub fn print(&self) {
        log::info!("---- fpu ----");
        for i in 0..self.st.len() {
            log::info!("st({}): {}", i, self.st[i]);
        }

        log::info!("stat: 0x{:x}", self.stat);
        log::info!("ctrl: 0x{:x}", self.ctrl);
        log::info!("eip:  0x{:x}", self.ip);

        log::info!("--------");
    }

    pub fn set_st(&mut self, i: usize, value: f64) {
        self.st[i] = value;
    }

    pub fn get_st(&mut self, i: usize) -> f64 {
        self.f_c4 = self.st_depth == 0;
        return self.st[i];
    }

    pub fn xchg_st(&mut self, i: usize) {
        let i = i;
        self.st.swap(0, i);
    }

    pub fn clear_st(&mut self, i: usize) {
        self.st[i] = 0.0;
    }

    pub fn move_to_st0(&mut self, i: usize) {
        self.st[0] = self.st[i];
    }

    pub fn add_to_st0(&mut self, i: usize) {
        self.st[0] += self.st[i];
    }

    pub fn add(&mut self, i: usize, j: usize) {
        self.st[i] += self.st[j];
    }

    pub fn push(&mut self, value: f64) {
        if self.st_depth >= 8 {
            self.f_c0 = true; // overflow
        } else {
            self.st_depth += 1;
            self.f_c0 = false;
        }
        self.st[7] = self.st[6];
        self.st[6] = self.st[5];
        self.st[5] = self.st[4];
        self.st[4] = self.st[3];
        self.st[3] = self.st[2];
        self.st[2] = self.st[1];
        self.st[1] = self.st[0];
        self.st[0] = value;
    }

    pub fn pop(&mut self) -> f64 {
        if self.st_depth == 0 {
            self.f_c1 = true;
        } else {
            self.st_depth -= 1;
            self.f_c1 = false;
        }
        let result = self.st[0];
        self.st[0] = self.st[1];
        self.st[1] = self.st[2];
        self.st[2] = self.st[3];
        self.st[3] = self.st[4];
        self.st[4] = self.st[5];
        self.st[5] = self.st[6];
        self.st[6] = self.st[7];
        self.st[7] = 0.0;
        result
    }

    pub fn fyl2x(&mut self) {
        self.st[1] *= self.st[0].log2();
        self.pop();
    }

    pub fn fyl2xp1(&mut self) {
        self.st[1] *= self.st[0].log2() + 1.0;
        self.pop();
    }

    pub fn check_pending_exceptions(self) {}

    pub fn set_streg(&mut self, reg: Register, value: f64) {
        match reg {
            Register::ST0 => self.st[0] = value,
            Register::ST1 => self.st[1] = value,
            Register::ST2 => self.st[2] = value,
            Register::ST3 => self.st[3] = value,
            Register::ST4 => self.st[4] = value,
            Register::ST5 => self.st[5] = value,
            Register::ST6 => self.st[6] = value,
            Register::ST7 => self.st[7] = value,
            _ => unreachable!(),
        }
    }

    pub fn frexp(&self, value: f64) -> (f64, i32) {
        if value == 0.0 {
            (0.0, 0)
        } else {
            let exponent = value.abs().log2().floor() as i32 + 1;
            let mantissa = value / (2f64.powi(exponent));

            (mantissa, exponent)
        }
    }

    pub fn convert_st(&self, src: Vec<f64>) -> [u128; 8] {
        let mut result = [0u128; 8];
        
        for i in 0..8 {
            let low = if let Some(val) = src.get(i * 2) {
                *val
            } else {
                0.0
            };
            let high = if let Some(val) = src.get(i * 2 + 1) {
                *val
            } else {
                0.0
            };
    
            let low_bits = low.to_bits() as u128;
            let high_bits = high.to_bits() as u128;
            result[i] = low_bits | (high_bits << 64);
        }
    
        result
    }

    pub fn fxsave(&self) -> FPUState {
        let mut state = FPUState::new();
        state.fpu_control_word = self.fpu_control_word;
        state.fpu_status_word = self.stat;
        state.fpu_tag_word = self.tag;
        state.fpu_opcode = self.opcode;
        state.rip = self.ip;
        state.rdp = self.operand_ptr;
        state.mxcsr = self.mxcsr;
        state.mxcsr_mask = self.mxcsr;
        state.st = self.convert_st(self.st.clone());
        state.xmm = self.xmm.clone();
        return state;
    }

    pub fn fxrstor(&mut self, state: FPUState) {
        self.fpu_control_word = state.fpu_control_word;
        self.stat = state.fpu_status_word;
        self.tag = state.fpu_tag_word;
        self.opcode = state.fpu_opcode;
        self.ip = state.rip;
        self.operand_ptr = state.rdp;
        self.mxcsr = state.mxcsr;
        
        // Convert the packed 128-bit ST registers back to f64 values
        for i in 0..8 {
            let low_bits = (state.st[i] & 0xFFFFFFFFFFFFFFFF) as u64;
            self.st[i] = f64::from_bits(low_bits);
        }
        
        self.xmm = state.xmm;
    }
}
