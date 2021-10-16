
pub struct Regs32 {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub esi: u32,
    pub edi: u32,
    pub ebp: u32,
    pub esp: u32,
    pub eip: u32
}

impl Regs32 {
    pub fn new() -> Regs32 {
        Regs32{
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
            esi: 0,
            edi: 0,
            ebp: 0,
            esp: 0,
            eip: 0
        }
    }

    pub fn clear(&mut self) {
        self.eax = 0;
        self.ebx = 0;
        self.ecx = 0;
        self.edx = 0;
        self.esi = 0;
        self.edi = 0;
        self.ebp = 0;
        self.esp = 0;
        self.eip = 0;
    }

    pub fn get_ax(&self) -> u32 {
        return self.eax & 0xffff;
    }

    pub fn get_bx(&self) -> u32 {
        return self.ebx & 0xffff;
    }

    pub fn get_cx(&self) -> u32 {
        return self.ecx & 0xffff;
    }

    pub fn get_dx(&self) -> u32 {
        return self.edx & 0xffff;
    }

    pub fn get_si(&self) -> u32 {
        return self.esi & 0xffff;
    }

    pub fn get_di(&self) -> u32 {
        return self.edi & 0xffff;
    }

    pub fn get_ah(&self) -> u32 {
        return self.eax & 0xff00;
    }

    pub fn get_al(&self) -> u32 {
        return self.eax & 0xff;
    }

    pub fn get_bh(&self) -> u32 {
        return self.ebx & 0xff00;
    }

    pub fn get_bl(&self) -> u32 {
        return self.ebx & 0xff;
    }

    pub fn get_ch(&self) -> u32 {
        return self.ecx & 0xff00;
    }

    pub fn get_cl(&self) -> u32 {
        return self.ecx & 0xff;
    }

    pub fn get_dh(&self) -> u32 {
        return self.edx & 0xff00;
    }

    pub fn get_dl(&self) -> u32 {
        return self.edx & 0xff;
    }


}


