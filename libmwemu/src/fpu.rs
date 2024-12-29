use iced_x86::Register;
use serde::{Serialize, Serializer};
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

impl Serialize for FPU {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serde_json::Map::new();
        value.insert("st".to_string(), serde_json::to_value(&self.st).unwrap());
        value.insert("st_depth".to_string(), serde_json::to_value(&self.st_depth).unwrap());
        value.insert("tag".to_string(), serde_json::to_value(&self.tag).unwrap());
        value.insert("stat".to_string(), serde_json::to_value(&self.stat).unwrap());
        value.insert("ctrl".to_string(), serde_json::to_value(&self.ctrl).unwrap());
        value.insert("ip".to_string(), serde_json::to_value(&self.ip).unwrap());
        value.insert("err_off".to_string(), serde_json::to_value(&self.err_off).unwrap());
        value.insert("err_sel".to_string(), serde_json::to_value(&self.err_sel).unwrap());
        value.insert("code_segment".to_string(), serde_json::to_value(&self.code_segment).unwrap());
        value.insert("data_segment".to_string(), serde_json::to_value(&self.data_segment).unwrap());
        value.insert("operand_ptr".to_string(), serde_json::to_value(&self.operand_ptr).unwrap());
        value.insert("reserved".to_string(), serde_json::to_value(&self.reserved.to_vec()).unwrap());
        value.insert("reserved2".to_string(), serde_json::to_value(&self.reserved2.to_vec()).unwrap());
        value.insert("xmm".to_string(), serde_json::to_value(&self.xmm).unwrap());
        value.insert("top".to_string(), serde_json::to_value(&self.top).unwrap());
        value.insert("f_c0".to_string(), serde_json::to_value(&self.f_c0).unwrap());
        value.insert("f_c1".to_string(), serde_json::to_value(&self.f_c1).unwrap());
        value.insert("f_c2".to_string(), serde_json::to_value(&self.f_c2).unwrap());
        value.insert("f_c3".to_string(), serde_json::to_value(&self.f_c3).unwrap());
        value.insert("f_c4".to_string(), serde_json::to_value(&self.f_c4).unwrap());
        value.insert("mxcsr".to_string(), serde_json::to_value(&self.mxcsr).unwrap());
        value.insert("fpu_control_word".to_string(), serde_json::to_value(&self.fpu_control_word).unwrap());
        value.insert("opcode".to_string(), serde_json::to_value(&self.opcode).unwrap());
        serializer.serialize_str(&serde_json::to_string(&value).unwrap())
    }
}

#[derive(Clone)]
pub struct FPU {
    st: Vec<f64>,
    st_depth: u8,
    tag: u16,
    pub stat: u16,
    ctrl: u16,
    ip: u64,
    err_off: u32,
    err_sel: u32,
    code_segment: u16,
    data_segment: u16,
    operand_ptr: u64,
    reserved: [u8; 14],
    reserved2: [u8; 96],
    xmm: [u128; 16],
    top: i8,
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
}
