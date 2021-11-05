/*
    TODO:
        - code no deberia estar en posicion 0 y si cae en 0 un set_eip finalizar.
        - ante un pop mirar si ha recogido un puntero a un string y printar el string.
        - pop popea una direccion de codigo?
        - modo de ver codigo o de no verlo
        - modo de ver solo los saltos/branches/calls/rets
        - en cada set_eip() dumpear pila a fichero
        - detectar si lleva mucho tiempo loopeado
        - poner comentarios en las instruciones
        - implementar instrucciones scas y rep
        - back step?

        punto strategico con guloader:
            10004 0xc8b6: jne 0xc7c3
            en la posicion 0x54f tiene que estar la API LoadLibraryA
                ecx: contador
                esi: 0x54f valor al que tiene que llegar ecx (LoadLibraryA)
                edx: export table

        xloader lee en 0x3277003c

*/

extern crate capstone;

mod flags; 
mod eflags;
mod maps;
mod regs32;
mod console;

use flags::Flags;
use eflags::Eflags;
use maps::Maps;
use regs32::Regs32;
use console::Console;

use capstone::prelude::*;


pub struct Emu32 {
    regs: Regs32,
    flags: Flags,
    eflags: Eflags,
    maps: Maps,
    exp: i32
}

impl Emu32 {
    pub fn new() -> Emu32 {
        Emu32{
            regs: Regs32::new(),
            flags: Flags::new(),
            eflags: Eflags::new(),
            maps: Maps::new(),
            exp: -1
        }
    }

    pub fn init_stack(&mut self) {
        let stack = self.maps.get_mem("stack");
        let q = (stack.size() as u32) / 4;
        stack.set_base(self.regs.esp - (q*3));
    }

    pub fn init_peb(&mut self) {
        let peb = self.maps.get_mem("peb");

         /* fake PEB
                8392 0xce4f: mov eax, dword ptr fs:[0x30]    eax -> 0x200004
                8393 0xce55: mov eax, dword ptr [eax + 0xc]  eax -> 0x200008
                8394 0xce58: mov eax, dword ptr [eax + 0x14] eax -> 0x20000c
                8395 0xce5b: mov ecx, dword ptr [eax]        ecx -> 0x210000
                8396 0xce5d: mov eax, ecx                    eax -> 0x210000
                8399 0xce7d: mov ebx, dword ptr [eax + 0x28] --> list of library name strings

        */
        
        //TODO: replicate full PEB structure
        println!("initializing PEB");
        peb.set_base(0x00200000);   

        // 0x02 must be 0   (is being debugged)

        peb.write_dword(0x00200000, 0x00200004);   // PEB addr                 mov eax, dword ptr [eax + 0xc]
        peb.write_dword(0x00200010, 0x00200008);   // PEB->Ldr                 mov eax, dword ptr [eax + 0x14]
        peb.write_dword(0x0020001c, 0x0020000c);   // PEB->Ldr.InMemOrder      mov ecx, dword ptr [eax]
        peb.write_dword(0x0020000c, 0x00210000);
        peb.write_dword(0x00210028, 0x00210040); // 4e00    ptr to ntdll.dll
        peb.write_dword(0x00210040, 0x0074006e);
        peb.write_dword(0x00210044, 0x006c0064); // "ntdll.dll" wide string
        peb.write_dword(0x00210048, 0x002e006c);
        peb.write_dword(0x0021004c, 0x006c0064);
        peb.write_dword(0x00210050, 0x0000006c);
        peb.write_dword(0x00210128, 0x00210130);

        peb.write_dword(0x00210000, 0x00210120-0x28);  // ptr
        peb.write_dword(0x00210120, 0x00210130);
        peb.write_dword(0x00210130, 0x0065006b);       // "kernel32.dll" wide string
        peb.write_dword(0x00210134, 0x006c0072);
        peb.write_dword(0x00210138, 0x006c0075);
        peb.write_dword(0x0021013c, 0x00320033);
        peb.write_dword(0x00210140, 0x0064002e);
        peb.write_dword(0x00210144, 0x006c006c);
        peb.write_dword(0x00210148, 0x00000000);

        peb.write_dword(0x00210108, 0x00210130-0x28);
        peb.write_dword(0x00210130, 0x00210134);
        peb.write_dword(0x00210134, 0x0045004b);       // KERNELBASE.dll
        peb.write_dword(0x00210138, 0x004e0052);
        peb.write_dword(0x0021013c, 0x00000000);

        peb.write_dword(0x002100f8, 0x00210140-0x28);
        peb.write_dword(0x00210140, 0x00210144);
        peb.write_dword(0x00210144, 0x0073006d);       // msvcrt.dll
        peb.write_dword(0x00210148, 0x00630076);       
        peb.write_dword(0x0021014c, 0x00740072);       
        peb.write_dword(0x00210150, 0x00740072);

        peb.write_dword(0x210118, 0x00210154-0x28);
        peb.write_dword(0x00210154, 0x00210158);
        peb.write_dword(0x00210158, 0x006c0064);   // ntdll.dll
        peb.write_dword(0x0021005c, 0x002e006c);
        peb.write_dword(0x00210060, 0x006c0064);
        peb.write_dword(0x00210064, 0x0000006c);

        peb.write_dword(0x0021012c, 0x00210070);
        peb.write_dword(0x00210070, 0x00000000);   // trigger 
    }


    pub fn init(&mut self) {
        println!("initializing regs");
        self.regs.clear();
        self.regs.esp = 0x00100000;
        self.regs.ebp = 0x00100f00;
        self.regs.eip = 0;

        println!("initializing code and stack");

        self.maps.create_map("stack");
        self.maps.create_map("code");
        self.maps.create_map("peb");
        self.maps.create_map("ntdll");
        self.maps.create_map("kernel32");
        self.maps.create_map("kernel32_xloader");

        self.init_stack();
        self.maps.get_mem("code").set_base(self.regs.eip);
        let kernel32 = self.maps.get_mem("kernel32");
        kernel32.set_base(0x850aa1);
        kernel32.load("maps/kernel32.dll");
        kernel32.write_dword(0x905a4d+0x18, 0x54f);
        self.init_peb();
        
        let ntdll = self.maps.get_mem("ntdll");
        ntdll.set_base(0x8f44ca6a);
        ntdll.load("maps/ntdll.dll");

        // xloader initial state hack
        self.memory_write("dword ptr [esp + 4]", 0x22a00);
        self.maps.get_mem("kernel32_xloader").set_base(0x75e40000);
    }

    pub fn explain(&mut self, line: &String) {
        self.exp = i32::from_str_radix(line, 10).expect("bad num conversion");
        println!("explaining line {}", self.exp);
    }

    pub fn load_code(&mut self, filename: &String) {
        self.maps.get_mem("code").load(filename);
    }

    pub fn stack_push(&mut self, value:u32) {
        self.regs.esp -= 4;
        self.maps.get_mem("stack").write_dword(self.regs.esp, value);
    }

    pub fn stack_pop(&mut self) -> u32 {
        let value = self.maps.get_mem("stack").read_dword(self.regs.esp);
        if self.maps.get_mem("code").inside(value) {
            println!("/!\\ poping a code address 0x{:x}", value);
        }
        self.regs.esp += 4;
        return value;
    }

    pub fn memory_operand_to_address(&mut self, operand:&str) -> u32 {
        //[esi] --> da 0x3 la address BUG!!!

        let spl:Vec<&str> = operand.split("[").collect::<Vec<&str>>()[1].split("]").collect::<Vec<&str>>()[0].split(" ").collect();

        if operand.contains("fs:[") {
            let mem = operand.split(":").collect::<Vec<&str>>()[1];
            let value = self.memory_operand_to_address(mem);

            /*
                fs:[0x30]
                fs:[ecx + 0x30]  ecx:0  <-- TODO: implement this


                FS:[0x00] : Current SEH Frame
                FS:[0x18] : TEB (Thread Environment Block)
                FS:[0x20] : PID
                FS:[0x24] : TID
                FS:[0x30] : PEB (Process Environment Block)
                FS:[0x34] : Last Error Value
            */

            //let inm = self.get_inmediate(spl[0]);
            println!("FS ACCESS TO 0x{:x}", value);

            if value == 0x30 { // PEB
                println!("ACCESS TO PEB");
                let peb = self.maps.get_mem("peb");
                return peb.get_base();
            }

            panic!("not implemented: {}", operand);
        }

        if spl.len() == 3 { //ie eax + 0xc
            let sign = spl[1];

            // weird case: [esi + eax*4]
            if spl[2].contains("*") {
                let spl2:Vec<&str> = spl[2].split("*").collect();
                if spl2.len() != 2 {
                    panic!("case ie [esi + eax*4] bad parsed the *  operand:{}", operand);
                }
                
                
                let reg1_val = self.regs.get_by_name(spl[0]);
                let reg2_val = self.regs.get_by_name(spl2[0]);
                let num = u32::from_str_radix(spl2[1].trim_start_matches("0x"),16).expect("bad num conversion");

                if sign != "+" && sign != "-" {
                    panic!("weird sign2 {}", sign);
                }

                if sign == "+" {
                    return reg1_val + (reg2_val * num);
                }

                if sign == "-" {
                    return reg1_val - (reg2_val * num);
                }

                panic!("weird situation");
                
            }
    
            let reg = spl[0];
            let sign = spl[1];
            //println!("disp --> {}  operand:{}", spl[2], operand);
            let disp:u32 = u32::from_str_radix(spl[2].trim_start_matches("0x"),16).expect("bad disp");
            
            if sign != "+" && sign != "-" {
                panic!("weird sign {}", sign);
            }

            if sign == "+" {
                return self.regs.get_by_name(reg) + disp;
            } else {
                return self.regs.get_by_name(reg) - disp;
            }

        }
        
        if spl.len() == 1 { //ie [eax]
            let reg = spl[0];

            if reg.contains("0x") {
                let addr:u32 = usize::from_str_radix(reg.trim_start_matches("0x"),16).expect("bad disp2") as u32;
                return addr;
                // weird but could be a hardcoded address [0x11223344]
            }

            let reg_val = self.regs.get_by_name(reg);
            return reg_val;

        }

        return 0
    }
    
    pub fn memory_read(&mut self, operand:&str) -> u32 {
        //TODO: access to operand .disp instead parsing the string
        //ie [ebp + 0x44]
        let addr:u32 = self.memory_operand_to_address(operand);
        let bits = self.get_size(operand);
        // check integrity of eip, esp and ebp registers

        let stack = self.maps.get_mem("stack");

        // could be normal using part of code as stack
        if !stack.inside(self.regs.esp) {
            //hack: redirect stack
            self.regs.esp = stack.get_base() + 0x1ff;

            //panic!("esp outside stack");
        }

        let value = match bits {
            32 => self.maps.read_dword(addr),
            16 => (self.maps.read_word(addr) as u32) & 0x0000ffff,
             8 => (self.maps.read_byte(addr) as u32) & 0x000000ff,
             _ => panic!("weird precision: {}", operand),
        };

        return value;
    }

    pub fn memory_write(&mut self, operand:&str, value:u32) {
        let addr:u32 = self.memory_operand_to_address(operand);
        let peb = self.maps.get_mem("peb");
        
        if peb.inside(addr) {
            panic!("modifying peb!!");
        }

        let bits = self.get_size(operand);
        match bits {
            32 => self.maps.write_dword(addr, value),
            16 => self.maps.write_word(addr, (value & 0x0000ffff) as u16),
             8 => self.maps.write_byte(addr, (value & 0x000000ff) as u8),
             _ => panic!("weird precision: {}", operand)
        }
    }

    pub fn set_eip(&mut self, addr:u32, is_branch:bool) {
        if self.maps.get_mem("code").inside(addr) {
           self.regs.eip = addr; 
        } else if self.maps.get_mem("stack").inside(addr) {
            println!("/!\\ weird, changing eip to stack.");
            self.regs.eip = addr;
        } else {
            panic!("cannot redirect  eip to 0x{:x} is outisde maps", addr);
        }

        //TODO: lanzar memory scan code.scan() y stack.scan()
        // escanear en cambios de eip pero no en bucles, evitar escanear en bucles!
    }

    pub fn is_reg(&self, operand:&str) -> bool {
        match operand {
            "eax"|"ebx"|"ecx"|"edx"|"esi"|"edi"|"esp"|"ebp"|"eip"|"ax"|"bx"|"cx"|"dx"|"si"|"di"|"al"|"ah"|"bl"|"bh"|"cl"|"ch"|"dl"|"dh" => return true,
            &_ => return false,
        }
    }

    pub fn get_inmediate(&self, operand:&str) -> u32 {
        if operand.contains("0x") {
            return u32::from_str_radix(operand.get(2..).unwrap(), 16).unwrap();
        } else {
            return u32::from_str_radix(operand, 16).unwrap();
        }
    }

    pub fn get_size(&self, operand:&str) -> u8 {
        if operand.contains("byte ptr") {
            return 8;
           
        } else if operand.contains("dword ptr") {
            return 32;

        } else if operand.contains("word ptr") {
            return 16;
        } 

        let c:Vec<char> = operand.chars().collect();
        
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

            if c[1]  == 'i' {
                return 16;
            }
        }

        panic!("weird precision: {}", operand);
    }


    /// FLAGS ///
    /// 
    /// overflow 0xffffffff + 1     
    /// carry    0x7fffffff + 1     o  0x80000000 - 1       o    0 - 1
    

    pub fn flags_add32(&mut self, value1:u32, value2:u32) -> u32 {
        let unsigned:u64 = value1 as u64 + value2 as u64;

        self.flags.f_sf = (unsigned as i32) < 0;
        self.flags.f_zf = unsigned == 0;
        self.flags.f_pf = (unsigned & 0xff) % 2 == 0;
        self.flags.f_of = (value1 as i32) > 0 && (unsigned as i32) < 0;
        self.flags.f_cf = unsigned > 0xffffffff;

        return (unsigned & 0xffffffff) as u32;
    }

    pub fn flags_add16(&mut self, value1:u32, value2:u32) -> u32 {
        if value1 > 0xffff || value2 > 0xffff {
            panic!("flags_add16 with a bigger precision");
        }

        let unsigned:u32 = value1 as u32 + value2 as u32;

        self.flags.f_sf = (unsigned as i16) < 0;
        self.flags.f_zf = unsigned == 0;
        self.flags.f_pf = (unsigned & 0xff) % 2 == 0;
        self.flags.f_of = (value1 as i16) > 0 && (unsigned as i16) < 0;
        self.flags.f_cf = unsigned > 0xffff;

        return (unsigned & 0xffff) as u32;
    }

    pub fn flags_add8(&mut self, value1:u32, value2:u32) -> u32 {
        if value1 > 0xff || value2 > 0xff {
            panic!("flags_add8 with a bigger precision");
        }

        let unsigned:u16 = value1 as u16 + value2 as u16;

        self.flags.f_sf = (unsigned as i8) < 0;
        self.flags.f_zf = unsigned == 0;
        self.flags.f_pf = unsigned % 2 == 0;
        self.flags.f_of = (value1 as i8) > 0 && (unsigned as i8) < 0;
        self.flags.f_cf = unsigned > 0xff;

        return (unsigned & 0xff) as u32;
    }

    pub fn flags_sub32(&mut self, value1:u32, value2:u32) -> u32 {
        let sr:i32 = value1 as i32 - value2 as i32;

        self.flags.f_zf = sr == 0;
        self.flags.f_sf = sr < 0;
        self.flags.f_pf = (sr & 0xff) % 2 == 0;
        self.flags.f_of = (value1 as i32) < 0 && sr >= 0;
        self.flags.f_cf = (value1 as i32) >= 0 && sr < 0;

        return sr as u32;
    }

    pub fn flags_sub16(&mut self, value1:u32, value2:u32) -> u32 {
        let sr:i16 = value1 as i16 - value2 as i16;

        self.flags.f_zf = sr == 0;
        self.flags.f_sf = sr < 0;
        self.flags.f_pf = (sr & 0xff) % 2 == 0;
        self.flags.f_of = (value1 as i16) < 0 && sr >= 0;
        self.flags.f_cf = (value1 as i16) >= 0 && sr < 0;

        return sr as u32;
    }

    pub fn flags_sub8(&mut self, value1:u32, value2:u32) -> u32 {
        let sr:i8 = value1 as i8 - value2 as i8;

        self.flags.f_zf = sr == 0;
        self.flags.f_sf = sr < 0;
        self.flags.f_pf = sr % 2 == 0;
        self.flags.f_of = (value1 as i8) < 0 && sr >= 0;
        self.flags.f_cf = (value1 as i8) >= 0 && sr < 0;

        return sr as u32;
    }

    pub fn flags_inc32(&mut self, value:u32) -> u32 { 
        if value == 0xffffffff {
            self.flags.f_zf = true;
            self.flags.f_pf = true;
            self.flags.f_af = true;
            return 0;
        }
        self.flags.f_of = value == 0x7fffffff;
        self.flags.f_sf = value > 0x7fffffff;
        self.flags.f_pf = (((value as i32) +1) & 0xff) % 2 == 0;
        self.flags.f_zf = false;
        return value + 1;
    }

    pub fn flags_inc16(&mut self, value:u32) -> u32 {
        if value == 0xffff {
            self.flags.f_zf = true;
            self.flags.f_pf = true;
            self.flags.f_af = true;
            return 0;
        }
        self.flags.f_of = value == 0x7fff;
        self.flags.f_sf = value > 0x7fff;
        self.flags.f_pf = (((value as i32) +1) & 0xff) % 2 == 0;
        self.flags.f_zf = false;
        return value + 1;
    }

    pub fn flags_inc8(&mut self, value:u32) -> u32 {
        if value == 0xff {
            self.flags.f_zf = true;
            self.flags.f_pf = true;
            self.flags.f_af = true;
            return 0;
        }
        self.flags.f_of = value == 0x7f;
        self.flags.f_sf = value > 0x7f;
        self.flags.f_pf = (((value as i32) +1) & 0xff) % 2 == 0;
        self.flags.f_zf = false;
        return value + 1;
    }

    pub fn flags_dec32(&mut self, value:u32) -> u32 { 
        if value == 0 {
            self.flags.f_pf = true;
            self.flags.f_af = true;
            self.flags.f_sf = true;
            return 0xffffffff;
        }
        self.flags.f_of = value == 0x80000000;
        self.flags.f_pf = (((value as i32) -1) & 0xff) % 2 == 0;
        self.flags.f_af = false;
        self.flags.f_sf = false;

        self.flags.f_zf = value == 0;

        return value - 1;
    }

    pub fn flags_dec16(&mut self, value:u32) -> u32 { 
        if value == 0 {
            self.flags.f_pf = true;
            self.flags.f_af = true;
            self.flags.f_sf = true;
            return 0xffff;
        }
        self.flags.f_of = value == 0x8000;
        self.flags.f_pf = (((value as i32) -1) & 0xff) % 2 == 0;
        self.flags.f_af = false;
        self.flags.f_sf = false;

        self.flags.f_zf = value == 0;

        return value - 1;
    }

    pub fn flags_dec8(&mut self, value:u32) -> u32 { 
        if value == 0 {
            self.flags.f_pf = true;
            self.flags.f_af = true;
            self.flags.f_sf = true;
            return 0xff;
        }
        self.flags.f_of = value == 0x80;
        self.flags.f_pf = (((value as i32) -1) & 0xff) % 2 == 0;
        self.flags.f_af = false;
        self.flags.f_sf = false;

        self.flags.f_zf = value == 0;

        return value - 1;
    }

    pub fn calc_flags(&mut self, final_value:u32, bits:u8) {
        
        match bits {
            32 => self.flags.f_sf = (final_value as i32) < 0,
            16 => self.flags.f_sf = (final_value as i16) < 0,
            8  => self.flags.f_sf = (final_value as i8) < 0,
            _ => panic!("weird precision")
        }
        
        self.flags.f_zf = final_value == 0;
        self.flags.f_pf = (final_value & 0xff) % 2 == 0;
        self.flags.f_tf = false;        
    }

    pub fn rotate_left(&self, val:u32, rot:u32, bits:u32) -> u32 {
        return (val << rot%bits) & (2_u32.pow(bits-1)) |
               ((val & (2_u32.pow(bits-1))) >> (bits-(rot%bits)));
    }

    pub fn rotate_right(&self, val:u32, rot:u32, bits:u32) -> u32 {
        return ((val & (2_u32.pow(bits-1))) >> rot%bits) |
               (val << (bits-(rot%bits)) & (2_u32.pow(bits-1)));
    }

    pub fn spawn_console(&mut self) {
        let con = Console::new();
        loop {
            let cmd = con.cmd();
            match cmd.as_str() {
                "q" => std::process::exit(1),
                "h" => con.help(),
                "r" => self.regs.print(),
                "rc" => {
                    con.print("register name");
                    let reg = con.cmd();
                    con.print("value");
                    let svalue = con.cmd();
                    let value = u32::from_str_radix(svalue.as_str().trim_start_matches("0x"), 16).expect("bad num conversion");
                    self.regs.set_by_name(reg.as_str(), value);
                },
                "mr"|"rm" => {
                    con.print("memory argument");
                    let operand = con.cmd();
                    let addr:u32 = self.memory_operand_to_address(operand.as_str());
                    let value = self.memory_read(operand.as_str());
                    println!("0x{:x}: 0x{:x}", addr, value);
                },
                "mw"|"wm" => {
                    con.print("memory argument");
                    let operand = con.cmd();
                    let value = u32::from_str_radix(con.cmd().as_str(), 16).expect("bad num conversion");
                    self.memory_write(operand.as_str(), value);
                    println!("done.");
                },
                "s" => self.maps.get_mem("stack").print_dwords_from_to(self.regs.esp, self.regs.ebp),
                "v" => self.maps.get_mem("stack").print_dwords_from_to(self.regs.ebp, self.regs.ebp+0x100),
                "c" => return,
                "f" => self.flags.print(),
                "cf" => self.flags.clear(),
                "mc" => {
                    con.print("name ");
                    let name = con.cmd();
                    con.print("base address ");
                    let saddr = con.cmd();
                    let addr = u32::from_str_radix(saddr.as_str().trim_start_matches("0x"), 16).expect("bad num conversion");
                    self.maps.create_map(name.as_str());
                    self.maps.get_mem(name.as_str()).set_base(addr);
                },
                "ml" => {
                    con.print("map name");
                    let name = con.cmd();
                    con.print("filename");
                    let filename = con.cmd();
                    self.maps.get_mem(name.as_str()).load(filename.as_str());
                },
                "eip" => {
                    con.print("=");
                    let saddr = con.cmd();
                    let addr = u32::from_str_radix(saddr.as_str(), 16).expect("bad num conversion");
                    self.regs.eip = addr;
                },
                "n" => {
                    self.exp += 1;
                    return;
                },
                "m" => self.maps.print_maps(),
                "" => {
                    self.exp += 1;
                    return;
                },
                _ => println!("command not found, type h"),
            }
        }
    }


    ///  RUN ENGINE ///

    pub fn run(&mut self) {
        println!(" ----- emulation -----");
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode32)
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build()
            .expect("Failed to create Capstone object");

        let mut pos = 1;
        

        loop {

            let eip = self.regs.eip.clone();
            let code = self.maps.get_mem("code");
            let block = code.read_from(eip);
            let insns = cs.disasm_all(block, eip as u64).expect("Failed to disassemble");
            

            for ins in insns.as_ref() {
                //TODO: use InsnDetail https://docs.rs/capstone/0.4.0/capstone/struct.InsnDetail.html
                //let detail: InsnDetail = cs.insn_detail(&ins).expect("Failed to get insn detail");
                //let arch_detail: ArchDetail = detail.arch_detail();
                //let ops = arch_detail.operands();

                let sz = ins.bytes().len();

                if self.exp == pos {
                    let op = ins.op_str().unwrap();
                    let parts:Vec<&str> = op.split(", ").collect();
                    println!("-------");
                    println!("{} {}", pos, ins);
                    println!("\tesp: 0x{:x}", self.regs.esp);
                    println!("\tebp: 0x{:x}", self.regs.ebp);
                    for i in 0..parts.len() {
                        if self.is_reg(parts[i]) {
                            println!("\t{}: 0x{:x}", parts[i], self.regs.get_by_name(parts[i]));
                        } else if parts[i].contains("[") {
                            let addr = self.memory_operand_to_address(parts[i]);
                            let value = self.memory_read(parts[i]);
                            println!("\t0x{:x}: 0x{:x}", addr, value);
                        }
                    }
  
                    self.spawn_console();

                } else {
                    println!("{} {}", pos, ins);
                    //stack.print_dwords_from_to(self.regs.esp, self.regs.esp+4*4);
                }
                pos += 1;
                

                match ins.mnemonic() {
                    Some("jmp") => {
                        let addr = self.get_inmediate(ins.op_str().unwrap());       
                        self.set_eip(addr, false);
                        break;
                    },

                    Some("call") => {

                        if sz == 3 {
                            let addr = self.memory_read(ins.op_str().unwrap());
                            self.stack_push(self.regs.eip + sz as u32); // push return address
                            println!("\tcall return addres: 0x{:x}", self.regs.eip + sz as u32);
                            self.set_eip(addr, false);
                            break; 
                        }

                        if sz == 5 {
                            let addr = self.get_inmediate(ins.op_str().unwrap());
                            self.stack_push(self.regs.eip + sz as u32); // push return address
                            println!("\tcall return addres: 0x{:x}", self.regs.eip + sz as u32);
                            self.set_eip(addr, false);
                            break;
                        }

                        println!("weird call");
                        return;
                    },

                    Some("push") => {
                        let opcode:u8 = ins.bytes()[0];

                        match opcode {
                            // push + regs
                            0x50 => self.stack_push(self.regs.eax),
                            0x51 => self.stack_push(self.regs.ecx),
                            0x52 => self.stack_push(self.regs.edx),
                            0x53 => self.stack_push(self.regs.ebx),
                            0x54 => self.stack_push(self.regs.esp),
                            0x55 => self.stack_push(self.regs.ebp),
                            0x56 => self.stack_push(self.regs.esi),
                            0x57 => self.stack_push(self.regs.edi),

                            // push + inmediate
                            0x68 => {
                                let addr = self.get_inmediate(ins.op_str().unwrap());
                                self.stack_push(addr as u32);
                            },

                            // push + mem operation
                            _ => {
                                let value = self.memory_read(ins.op_str().unwrap());
                                self.stack_push(value);
                            }
                        }
                        println!("\tpushing 0x{:x}",self.memory_read("dword ptr [esp]"));
                    },

                    Some("pop") => {
                        let opcode:u8 = ins.bytes()[0];

                        match opcode {
                            // pop + regs
                            0x58 => self.regs.eax = self.stack_pop(),
                            0x59 => self.regs.ecx = self.stack_pop(),
                            0x5a => self.regs.edx = self.stack_pop(),
                            0x5b => self.regs.ebx = self.stack_pop(),
                            0x5c => self.regs.esp = self.stack_pop(),
                            0x5d => self.regs.ebp = self.stack_pop(),
                            0x5e => self.regs.esi = self.stack_pop(),
                            0x5f => self.regs.edi = self.stack_pop(),

                            // pop + mem operation
                            _ => {
                                //let value = self.memory_read(ins.op_str().unwrap());
                                let value = self.stack_pop();
                                self.memory_write(ins.op_str().unwrap(), value);
                            },
                        }

                    },

                    Some("pushal") => {
                        let tmp_esp = self.regs.esp;
                        self.stack_push(self.regs.eax);
                        self.stack_push(self.regs.ecx);
                        self.stack_push(self.regs.edx);
                        self.stack_push(self.regs.ebx);
                        self.stack_push(tmp_esp);
                        self.stack_push(self.regs.ebp);
                        self.stack_push(self.regs.esi);
                        self.stack_push(self.regs.edi);
                    },

                    Some("popal") => {
                        self.regs.edi = self.stack_pop();
                        self.regs.esi = self.stack_pop();
                        self.regs.ebp = self.stack_pop();
                        self.regs.esp += 4; // skip esp
                        self.regs.ebx = self.stack_pop();
                        self.regs.edx = self.stack_pop();
                        self.regs.ecx = self.stack_pop();
                        self.regs.eax = self.stack_pop();
                    },

                    Some("ret") => {
                        let ret_addr = self.stack_pop(); // return address
                        let op = ins.op_str().unwrap();
                        println!("\tret return addres: 0x{:x}  return value: 0x{:x}", ret_addr, self.regs.eax);

                        
                        if op.len() > 0 {
                            let mut arg = self.get_inmediate(op);

                            // apply stack compensation of ret operand

                            if arg % 4 != 0 {
                                panic!("weird ret argument!");
                            }

                            arg = arg / 4;

                            for _ in 0..arg {
                                self.stack_pop();
                            }
                        }
                        
                        self.set_eip(ret_addr, false);
                        break;
                    },

                    Some("mov") => {
                        let parts:Vec<&str> = ins.op_str().unwrap().split(", ").collect();
                        
                        if parts[0].contains("[") {
                            if self.is_reg(parts[1]) {
                                // mov mem, reg
                                let value = self.regs.get_by_name(parts[1]);
                                self.memory_write(parts[0], value);
                                
                            } else {
                                // mov mem, inm
                                let inm = self.get_inmediate(parts[1]);
                                self.memory_write(parts[0], inm);
                            }

                        } else {

                            if parts[1].contains("[") {
                                // mov reg, mem 
                                let value = self.memory_read(parts[1]);
                                self.regs.set_by_name(parts[0], value);
                                //println!("reg '{}' '{}' new value: 0x{:x}", parts[0], parts[1], value);

                            } else if self.is_reg(parts[1]) {
                                // mov reg, reg
                                self.regs.set_by_name(parts[0], self.regs.get_by_name(parts[1]));
                                
                            } else {
                                // mov reg, inm
                                let inm = self.get_inmediate(parts[1]);
                                self.regs.set_by_name(parts[0], inm);
                            }
                        }
                    
                    },

                    Some("xor") => {
                        let parts:Vec<&str> = ins.op_str().unwrap().split(", ").collect();

                        if parts[0].contains("[") {
                            if self.is_reg(parts[1]) {
                                // mov mem, reg
                                let value1 = self.regs.get_by_name(parts[1]);
                                let value0 = self.memory_read(parts[0]);

                                self.memory_write(parts[0], value0 ^ value1);
                                
                            } else {
                                // mov mem, inm
                                let inm = self.get_inmediate(parts[1]);
                                let value0 = self.memory_read(parts[0]);
                                self.memory_write(parts[0], value0 ^ inm);
                            }

                        } else {

                            if parts[1].contains("[") {
                                // mov reg, mem 
                                let value1 = self.memory_read(parts[1]);
                                let value0 = self.regs.get_by_name(parts[0]);
                                self.regs.set_by_name(parts[0], value0 ^ value1);

                            } else if self.is_reg(parts[1]) {
                                // mov reg, reg
                                let value1 = self.regs.get_by_name(parts[1]);
                                let value0 = self.regs.get_by_name(parts[0]);
                                self.regs.set_by_name(parts[0], value0 ^ value1);
                                
                            } else {
                                // mov reg, inm
                                let inm = self.get_inmediate(parts[1]);
                                let value0 = self.regs.get_by_name(parts[0]);
                                self.regs.set_by_name(parts[0], value0 ^ inm);
                            }
                        }
                    },

                    Some("add") => { // https://c9x.me/x86/html/file_module_x86_id_5.html
                        let ops = ins.op_str().unwrap();
                        let parts:Vec<&str> = ops.split(", ").collect();

                        if parts[0].contains("[") {
                            if self.is_reg(parts[1]) {
                                // mov mem, reg
                                let value1:u32 = self.regs.get_by_name(parts[1]);
                                let value0:u32 = self.memory_read(parts[0]);
                                let res:u32;
                                match self.get_size(parts[1]) {
                                    32 => res = self.flags_add32(value0, value1),
                                    16 => res = self.flags_add16(value0, value1),
                                    8  => res = self.flags_add8(value0, value1),
                                    _  => panic!("weird precision")
                                }
                                self.memory_write(parts[0], res); 
                                
                            } else {
                                // mov mem, inm
                                let inm = self.get_inmediate(parts[1]);
                                let value0 = self.memory_read(parts[0]);
                                let res:u32;
                                match self.get_size(parts[0]) {
                                    32 => res = self.flags_add32(value0, inm),
                                    16 => res = self.flags_add16(value0, inm),
                                    8  => res = self.flags_add8(value0, inm),
                                    _  => panic!("weird precision")
                                }
                                self.memory_write(parts[0], res);
                            }

                        } else {

                            if parts[1].contains("[") {
                                // mov reg, mem 
                                let value1 = self.memory_read(parts[1]);
                                let value0 = self.regs.get_by_name(parts[0]);
                                let res:u32;
                                match self.get_size(parts[1]) {
                                    32 => res = self.flags_add32(value0, value1),
                                    16 => res = self.flags_add16(value0, value1),
                                    8  => res = self.flags_add8(value0, value1),
                                    _  => panic!("weird precision")
                                }
                                self.regs.set_by_name(parts[0], res);


                            } else if self.is_reg(parts[1]) {
                                // mov reg, reg
                                let value1 = self.regs.get_by_name(parts[1]);
                                let value0 = self.regs.get_by_name(parts[0]);
                                let res:u32;
                                match self.get_size(parts[1]) {
                                    32 => res = self.flags_add32(value0, value1),
                                    16 => res = self.flags_add16(value0, value1),
                                    8  => res = self.flags_add8(value0, value1),
                                    _  => panic!("weird precision")
                                }
                                self.regs.set_by_name(parts[0], res);
                                
                            } else {
                                // mov reg, inm
                                let inm = self.get_inmediate(parts[1]);
                                let value0 = self.regs.get_by_name(parts[0]);
                                let res:u32;
                                match self.get_size(parts[0]) {
                                    32 => res = self.flags_add32(value0, inm),
                                    16 => res = self.flags_add16(value0, inm),
                                    8  => res = self.flags_add8(value0, inm),
                                    _  => panic!("weird precision")
                                }
                                self.regs.set_by_name(parts[0], res);
                            }
                        } 
                    },
                    
                    
                    Some("sub") => {
                        let op = ins.op_str().unwrap();
                        let parts:Vec<&str> = op.split(", ").collect();

                        if parts[0].contains("[") {
                            if self.is_reg(parts[1]) {
                                // mov mem, reg
                                let value1 = self.regs.get_by_name(parts[1]);
                                let value0 = self.memory_read(parts[0]);
                                let res:u32;
                                match self.get_size(op) {
                                    32 => res = self.flags_sub32(value0, value1),
                                    16 => res = self.flags_sub16(value0, value1),
                                    8  => res = self.flags_sub8(value0, value1),
                                    _  => panic!("weird precision")
                                }
                                self.memory_write(parts[0], res);
                                
                            } else {
                                // mov mem, inm
                                let inm = self.get_inmediate(parts[1]);
                                let value0 = self.memory_read(parts[0]);
                                let res:u32;
                                match self.get_size(op) {
                                    32 => res = self.flags_sub32(value0, inm),
                                    16 => res = self.flags_sub16(value0, inm),
                                    8  => res = self.flags_sub8(value0, inm),
                                    _  => panic!("weird precision")
                                }
                                self.memory_write(parts[0], res);
                            }

                        } else {

                            if parts[1].contains("[") {
                                // mov reg, mem 
                                let value1 = self.memory_read(parts[1]);
                                let value0 = self.regs.get_by_name(parts[0]);
                                let res:u32;
                                match self.get_size(parts[1]) {
                                    32 => res = self.flags_sub32(value0, value1),
                                    16 => res = self.flags_sub16(value0, value1),
                                    8  => res = self.flags_sub8(value0, value1),
                                    _  => panic!("weird precision")
                                }
                                self.regs.set_by_name(parts[0], res);

                            } else if self.is_reg(parts[1]) {
                                // mov reg, reg
                                let value1 = self.regs.get_by_name(parts[1]);
                                let value0 = self.regs.get_by_name(parts[0]);
                                let res:u32;
                                match self.get_size(parts[1]) {
                                    32 => res = self.flags_sub32(value0, value1),
                                    16 => res = self.flags_sub16(value0, value1),
                                    8  => res = self.flags_sub8(value0, value1),
                                    _  => panic!("weird precision")
                                }
                                self.regs.set_by_name(parts[0], res);
                                
                            } else {
                                // mov reg, inm
                                let inm = self.get_inmediate(parts[1]);
                                let value0 = self.regs.get_by_name(parts[0]);
                                let res:u32;
                                match self.get_size(parts[0]) {
                                    32 => res = self.flags_sub32(value0, inm),
                                    16 => res = self.flags_sub16(value0, inm),
                                    8  => res = self.flags_sub8(value0, inm),
                                    _  => panic!("weird precision")
                                }
                                self.regs.set_by_name(parts[0], res);
                            }
                        }
                    },

                    Some("inc") => {
                        let op = ins.op_str().unwrap();
                        if self.is_reg(op) {
                            let value = self.regs.get_by_name(op);
                            let res:u32;

                            match self.get_size(op) {
                                32 => res = self.flags_inc32(value),
                                16 => res = self.flags_inc16(value),
                                8 =>  res = self.flags_inc8(value),
                                _ => res = 0,
                            }

                            self.regs.set_by_name(op, res);
                            
                        } else {
                            let value = self.memory_read(op);
                            let res:u32;

                            match self.get_size(op) {
                                32 => res = self.flags_inc32(value),
                                16 => res = self.flags_inc16(value),
                                8 =>  res = self.flags_inc8(value),
                                _ => res = 0,
                            }

                            self.memory_write(op, res);
                        }
                    },

                    Some("dec") => {
                        let op = ins.op_str().unwrap();
                        if self.is_reg(op) {
                            // dec reg
                            let value = self.regs.get_by_name(op);
                            let res:u32;

                            match self.get_size(op) {
                                32 => res = self.flags_dec32(value),
                                16 => res = self.flags_dec16(value),
                                8 =>  res = self.flags_dec8(value),
                                _ => res = 0,
                            }

                            self.regs.set_by_name(op, res);
                        } else {
                            // dec  mem
                            let value = self.memory_read(op);
                            let res:u32;

                            match self.get_size(op) {
                                32 => res = self.flags_dec32(value),
                                16 => res = self.flags_dec16(value),
                                8 =>  res = self.flags_dec8(value),
                                _ => res = 0,
                            }

                            self.memory_write(op, res);
                        }
                    },

                    // neg not and or ror rol  sar sal shr shl 
                    Some("neg") => {
                        let op = ins.op_str().unwrap();
                        if self.is_reg(op) {
                            let mut value = self.regs.get_by_name(op);
                            let mut signed:i32 = value as i32;
                            let bits = self.get_size(op);
                            match bits {
                                32 => self.flags.f_of = value == 0x80000000,
                                16 => self.flags.f_of = value == 0x8000,
                                8 =>  self.flags.f_of = value == 0x80,
                                _ => panic!("weird precision")
                            }
                            signed = signed * -1;
                            value = signed as u32;
                            self.calc_flags(value, bits);
                            self.flags.f_cf = true;
                            self.regs.set_by_name(op, value);
                            
                        } else {
                            let mut value = self.memory_read(op);
                            let mut signed:i32 = value as i32;
                            let bits = self.get_size(op);
                            match  bits {
                                32 => self.flags.f_of = value == 0x80000000,
                                16 => self.flags.f_of = value == 0x8000,
                                8 =>  self.flags.f_of = value == 0x80,
                                _ => panic!("weird precision")
                            }
                            signed = signed * -1;
                            value = signed as u32;
                            self.calc_flags(value, bits);
                            self.flags.f_cf = true;
                            
                            self.memory_write(op, value);
                        }
                    },

                    Some("not") => { // dont alter flags
                        let op = ins.op_str().unwrap();
                        if self.is_reg(op) {
                            let mut value = self.regs.get_by_name(op);
                            let mut signed:i32 = value as i32;
                            signed = !signed;
                            value = signed as u32;
                            self.regs.set_by_name(op, value);
                        } else {
                            let mut value = self.memory_read(op);
                            let mut signed:i32 = value as i32;
                            signed = !signed;
                            value = signed as u32;
                            self.memory_write(op, value);
                        }
                    },

                    Some("and") => { // TODO: how to trigger overflow and carry with and
                        let parts:Vec<&str> = ins.op_str().unwrap().split(", ").collect();

                        if parts[0].contains("[") {
                            if self.is_reg(parts[1]) {
                                // and mem, reg
                                let value1 = self.regs.get_by_name(parts[1]);
                                let value0 = self.memory_read(parts[0]);
                                let res = value0 & value1;
                                self.calc_flags(res, self.get_size(parts[1]));
                                self.memory_write(parts[0], res);
                                
                            } else {
                                // and mem, inm
                                let inm = self.get_inmediate(parts[1]);
                                let value0 = self.memory_read(parts[0]);
                                let res = value0 & inm;
                                self.calc_flags(res, self.get_size(parts[0]));
                                self.memory_write(parts[0], res);
                            }

                        } else {

                            if parts[1].contains("[") {
                                // and reg, mem 
                                let value1 = self.memory_read(parts[1]);
                                let value0 = self.regs.get_by_name(parts[0]);
                                let res = value0 & value1;
                                self.calc_flags(res, self.get_size(parts[1]));
                                self.regs.set_by_name(parts[0], res);

                            } else if self.is_reg(parts[1]) {
                                // and reg, reg
                                let value1 = self.regs.get_by_name(parts[1]);
                                let value0 = self.regs.get_by_name(parts[0]);
                                let res = value0 & value1;
                                self.calc_flags(res, self.get_size(parts[1]));
                                self.regs.set_by_name(parts[0], res);
                                
                            } else {
                                // and reg, inm
                                let inm = self.get_inmediate(parts[1]);
                                let value0 = self.regs.get_by_name(parts[0]);
                                let res = value0 & inm;
                                self.calc_flags(res, self.get_size(parts[0]));
                                self.regs.set_by_name(parts[0], res);
                            }
                        }

                    },

                    Some("or") => {
                        let parts:Vec<&str> = ins.op_str().unwrap().split(", ").collect();

                        if parts[0].contains("[") {
                            if self.is_reg(parts[1]) {
                                // or mem, reg
                                let value1 = self.regs.get_by_name(parts[1]);
                                let value0 = self.memory_read(parts[0]);
                                let res = value0 | value1;
                                self.calc_flags(res, self.get_size(parts[1]));
                                self.memory_write(parts[0], res);
                                
                            } else {
                                // or mem, inm
                                let inm = self.get_inmediate(parts[1]);
                                let value0 = self.memory_read(parts[0]);
                                let res = value0 | inm;
                                self.calc_flags(res, self.get_size(parts[0]));
                                self.memory_write(parts[0], res);
                            }

                        } else {

                            if parts[1].contains("[") {
                                // or reg, mem 
                                let value1 = self.memory_read(parts[1]);
                                let value0 = self.regs.get_by_name(parts[0]);
                                let res = value0 | value1;
                                self.calc_flags(res, self.get_size(parts[0]));
                                self.regs.set_by_name(parts[0], res);

                            } else if self.is_reg(parts[1]) {
                                // or reg, reg
                                let value1 = self.regs.get_by_name(parts[1]);
                                let value0 = self.regs.get_by_name(parts[0]);
                                let res = value0 | value1;
                                self.calc_flags(res, self.get_size(parts[0]));
                                self.regs.set_by_name(parts[0], res);
                                
                            } else {
                                // or reg, inm
                                let inm = self.get_inmediate(parts[1]);
                                let value0 = self.regs.get_by_name(parts[0]);
                                let res = value0 | inm;
                                self.calc_flags(res, self.get_size(parts[0]));
                                self.regs.set_by_name(parts[0], res);
                            }
                        }
                    },

                    Some("sal") => {
                        let op = ins.op_str().unwrap();
                        let parts:Vec<&str> = op.split(", ").collect();
                        let twoparams = parts.len() == 1;

                        if twoparams {
                            if self.is_reg(parts[0]) {
                                // reg
                                if self.is_reg(parts[1]) {
                                    // sal reg, reg
                                    let value0:u32 = self.regs.get_by_name(parts[0]);
                                    let value1:u32 = self.regs.get_by_name(parts[1]);
                                    let mut unsigned64:u64 = value0 as u64;
                                    let res:u32;
                                    let bits = self.get_size(parts[0]);
                                
                                    for _ in 0..value1 {
                                        unsigned64 *= 2;
                                    }

                                    match bits {
                                        32 => {
                                            self.flags.f_cf = unsigned64 > 0xffffffff;
                                            res = (unsigned64 & 0xffffffff) as u32
                                        },
                                        16 => {
                                            self.flags.f_cf = unsigned64 > 0xffff;
                                            res = (unsigned64 & 0xffff) as u32
                                        },
                                        8  => {
                                            self.flags.f_cf = unsigned64 > 0xff;
                                            res = (unsigned64 & 0xff) as u32;
                                        },
                                        _  => panic!("weird precision")
                                    }

                                    self.calc_flags(res, bits);
                                    self.regs.set_by_name(parts[0], res);


                                } else  {
                                    // sal reg, imm
                                    let value0:u32 = self.regs.get_by_name(parts[0]);
                                    let value1:u32 = self.get_inmediate(parts[1]);
                                    let mut unsigned64:u64 = value0 as u64;
                                    let res:u32;
                                    let bits = self.get_size(parts[0]);
                                
                                    for _ in 0..value1 {
                                        unsigned64 *= 2;
                                    }

                                    match bits {
                                        32 => {
                                            self.flags.f_cf = unsigned64 > 0xffffffff;
                                            res = (unsigned64 & 0xffffffff) as u32
                                        },
                                        16 => {
                                            self.flags.f_cf = unsigned64 > 0xffff;
                                            res = (unsigned64 & 0xffff) as u32
                                        },
                                        8  => {
                                            self.flags.f_cf = unsigned64 > 0xff;
                                            res = (unsigned64 & 0xff) as u32;
                                        },
                                        _  => panic!("weird precision")
                                    }

                                    self.calc_flags(res, bits);
                                    self.regs.set_by_name(parts[0], res);
                                }


                            } else {
                                // mem
                                if self.is_reg(parts[1]) {
                                    // sal mem, reg
                                    let value0:u32 = self.memory_read(parts[0]);
                                    let value1:u32 = self.regs.get_by_name(parts[1]);

                                    let mut unsigned64:u64 = value0 as u64;
                                    let res:u32;
                                    let bits = self.get_size(parts[0]);
                                
                                    for _ in 0..value1 {
                                        unsigned64 *= 2;
                                    }

                                    match bits {
                                        32 => {
                                            self.flags.f_cf = unsigned64 > 0xffffffff;
                                            res = (unsigned64 & 0xffffffff) as u32
                                        },
                                        16 => {
                                            self.flags.f_cf = unsigned64 > 0xffff;
                                            res = (unsigned64 & 0xffff) as u32
                                        },
                                        8  => {
                                            self.flags.f_cf = unsigned64 > 0xff;
                                            res = (unsigned64 & 0xff) as u32;
                                        },
                                        _  => panic!("weird precision")
                                    }

                                    self.calc_flags(res, bits);
                                    self.memory_write(parts[0], res);

                                } else {
                                    // sal mem, imm
                                    let value0:u32 = self.memory_read(parts[0]);
                                    let value1:u32 = self.get_inmediate(parts[1]);
                                    let mut unsigned64:u64 = value0 as u64;
                                    let res:u32;
                                    let bits = self.get_size(parts[0]);
                                
                                    for _ in 0..value1 {
                                        unsigned64 *= 2;
                                    }

                                    match bits {
                                        32 => {
                                            self.flags.f_cf = unsigned64 > 0xffffffff;
                                            res = (unsigned64 & 0xffffffff) as u32
                                        },
                                        16 => {
                                            self.flags.f_cf = unsigned64 > 0xffff;
                                            res = (unsigned64 & 0xffff) as u32
                                        },
                                        8  => {
                                            self.flags.f_cf = unsigned64 > 0xff;
                                            res = (unsigned64 & 0xff) as u32;
                                        },
                                        _  => panic!("weird precision")
                                    }

                                    self.calc_flags(res, bits);
                                    self.memory_write(parts[0], res);
                                }

                            }


                        } else { // one param
                            if self.is_reg(op) { // reg
                                let value:i32 = self.regs.get_by_name(op) as i32;
                                let unsigned64:u64;
                                let res:u32;
                                let bits = self.get_size(op);

                                unsigned64 = (value as u64) * 2;

                                match bits {
                                    32 => {
                                        self.flags.f_cf = unsigned64 > 0xffffffff;
                                        res = (unsigned64 & 0xffffffff) as u32
                                    },
                                    16 => {
                                        self.flags.f_cf = unsigned64 > 0xffff;
                                        res = (unsigned64 & 0xffff) as u32
                                    },
                                    8  => {
                                        self.flags.f_cf = unsigned64 > 0xff;
                                        res = (unsigned64 & 0xff) as u32;
                                    },
                                    _  => panic!("weird precision")
                                }

                                self.calc_flags(res, bits);
                                self.regs.set_by_name(op, res);


                            } else { // mem 
                                let value:i32 = self.memory_read(op) as i32;
                                let unsigned64:u64;
                                let res:u32;
                                let bits = self.get_size(op);

                                unsigned64 = (value as u64) * 2;

                                match bits {
                                    32 => {
                                        self.flags.f_cf = unsigned64 > 0xffffffff;
                                        res = (unsigned64 & 0xffffffff) as u32
                                    },
                                    16 => {
                                        self.flags.f_cf = unsigned64 > 0xffff;
                                        res = (unsigned64 & 0xffff) as u32
                                    },
                                    8  => {
                                        self.flags.f_cf = unsigned64 > 0xff;
                                        res = (unsigned64 & 0xff) as u32;
                                    },
                                    _  => panic!("weird precision")
                                }

                                self.calc_flags(res, bits);
                                self.memory_write(op, res);
                            }
                        }
                    },

                    Some("sar") => {
                        let op = ins.op_str().unwrap();
                        let parts:Vec<&str> = op.split(", ").collect();
                        let twoparams = parts.len() == 1;

                        if twoparams {
                            if self.is_reg(parts[0]) {
                                // reg
                                if self.is_reg(parts[1]) {
                                    // shl reg, reg
                                    let value0:u32 = self.regs.get_by_name(parts[0]);
                                    let value1:u32 = self.regs.get_by_name(parts[1]);
                                    let mut unsigned64:u64 = value0 as u64;
                                    let res:u32;
                                    let bits = self.get_size(parts[0]);
                                
                                    for _ in 0..value1 {
                                        unsigned64 /= 2;
                                    }

                                    match bits {
                                        32 => {
                                            self.flags.f_cf = unsigned64 > 0xffffffff;
                                            res = (unsigned64 & 0xffffffff) as u32
                                        },
                                        16 => {
                                            self.flags.f_cf = unsigned64 > 0xffff;
                                            res = (unsigned64 & 0xffff) as u32
                                        },
                                        8  => {
                                            self.flags.f_cf = unsigned64 > 0xff;
                                            res = (unsigned64 & 0xff) as u32;
                                        },
                                        _  => panic!("weird precision")
                                    }

                                    self.calc_flags(res, bits);
                                    self.regs.set_by_name(parts[0], res);

                                } else  {
                                    // shl reg, imm
                                    let value0:u32 = self.regs.get_by_name(parts[0]);
                                    let value1:u32 = self.get_inmediate(parts[1]);
                                    let mut unsigned64:u64 = value0 as u64;
                                    let res:u32;
                                    let bits = self.get_size(parts[0]);
                                
                                    for _ in 0..value1 {
                                        unsigned64 /= 2;
                                    }

                                    match bits {
                                        32 => {
                                            self.flags.f_cf = unsigned64 > 0xffffffff;
                                            res = (unsigned64 & 0xffffffff) as u32
                                        },
                                        16 => {
                                            self.flags.f_cf = unsigned64 > 0xffff;
                                            res = (unsigned64 & 0xffff) as u32
                                        },
                                        8  => {
                                            self.flags.f_cf = unsigned64 > 0xff;
                                            res = (unsigned64 & 0xff) as u32;
                                        },
                                        _  => panic!("weird precision")
                                    }

                                    self.calc_flags(res, bits);
                                    self.regs.set_by_name(parts[0], res);
                                }


                            } else {
                                // mem
                                if self.is_reg(parts[1]) {
                                    // shl mem, reg
                                    let value0:u32 = self.memory_read(parts[0]);
                                    let value1:u32 = self.regs.get_by_name(parts[1]);

                                    let mut unsigned64:u64 = value0 as u64;
                                    let res:u32;
                                    let bits = self.get_size(parts[0]);
                                
                                    for _ in 0..value1 {
                                        unsigned64 /= 2;
                                    }

                                    match bits {
                                        32 => {
                                            self.flags.f_cf = unsigned64 > 0xffffffff;
                                            res = (unsigned64 & 0xffffffff) as u32
                                        },
                                        16 => {
                                            self.flags.f_cf = unsigned64 > 0xffff;
                                            res = (unsigned64 & 0xffff) as u32
                                        },
                                        8  => {
                                            self.flags.f_cf = unsigned64 > 0xff;
                                            res = (unsigned64 & 0xff) as u32;
                                        },
                                        _  => panic!("weird precision")
                                    }

                                    self.calc_flags(res, bits);
                                    self.memory_write(parts[0], res);

                                } else {
                                    // shl mem, imm
                                    let value0:u32 = self.memory_read(parts[0]);
                                    let value1:u32 = self.get_inmediate(parts[1]);
                                    let mut unsigned64:u64 = value0 as u64;
                                    let res:u32;
                                    let bits = self.get_size(parts[0]);
                                
                                    for _ in 0..value1 {
                                        unsigned64 /= 2;
                                    }

                                    match bits {
                                        32 => {
                                            self.flags.f_cf = unsigned64 > 0xffffffff;
                                            res = (unsigned64 & 0xffffffff) as u32
                                        },
                                        16 => {
                                            self.flags.f_cf = unsigned64 > 0xffff;
                                            res = (unsigned64 & 0xffff) as u32
                                        },
                                        8  => {
                                            self.flags.f_cf = unsigned64 > 0xff;
                                            res = (unsigned64 & 0xff) as u32;
                                        },
                                        _  => panic!("weird precision")
                                    }

                                    self.calc_flags(res, bits);
                                    self.memory_write(parts[0], res);
                                }

                            }

                        } else { // one param
                            if self.is_reg(op) { // reg
                                let value:i32 = self.regs.get_by_name(op) as i32;
                                let unsigned64:u64;
                                let res:u32;
                                let bits = self.get_size(op);

                                unsigned64 = (value as u64) / 2;

                                match bits {
                                    32 => {
                                        self.flags.f_cf = unsigned64 > 0xffffffff;
                                        res = (unsigned64 & 0xffffffff) as u32
                                    },
                                    16 => {
                                        self.flags.f_cf = unsigned64 > 0xffff;
                                        res = (unsigned64 & 0xffff) as u32
                                    },
                                    8  => {
                                        self.flags.f_cf = unsigned64 > 0xff;
                                        res = (unsigned64 & 0xff) as u32;
                                    },
                                    _  => panic!("weird precision")
                                }

                                self.calc_flags(res, bits);
                                self.regs.set_by_name(op, res);


                            } else { // mem 
                                let value:i32 = self.memory_read(op) as i32;
                                let unsigned64:u64;
                                let res:u32;
                                let bits = self.get_size(op);

                                unsigned64 = (value as u64) / 2;

                                match bits {
                                    32 => {
                                        self.flags.f_cf = unsigned64 > 0xffffffff;
                                        res = (unsigned64 & 0xffffffff) as u32
                                    },
                                    16 => {
                                        self.flags.f_cf = unsigned64 > 0xffff;
                                        res = (unsigned64 & 0xffff) as u32
                                    },
                                    8  => {
                                        self.flags.f_cf = unsigned64 > 0xff;
                                        res = (unsigned64 & 0xff) as u32;
                                    },
                                    _  => panic!("weird precision")
                                }

                                self.calc_flags(res, bits);
                                self.memory_write(op, res);
                            }
                        }
                    },

                    Some("shr") => {
                        let op = ins.op_str().unwrap();
                        let parts:Vec<&str> = op.split(", ").collect();
                        let twoparams = parts.len() == 1;

                        if twoparams {
                            if self.is_reg(parts[0]) {
                                // reg
                                if self.is_reg(parts[1]) {
                                    // shr reg, reg
                                    let value0:u32 = self.regs.get_by_name(parts[0]);
                                    let value1:u32 = self.regs.get_by_name(parts[1]);
                                    let mut unsigned64:u64 = value0 as u64;
                                    let res:u32;
                                    let bits = self.get_size(parts[0]);
                                
                                    for _ in 0..value1 {
                                        unsigned64 /= 2;
                                    }

                                    match bits {
                                        32 => {
                                            self.flags.f_cf = unsigned64 > 0xffffffff;
                                            res = (unsigned64 & 0xffffffff) as u32
                                        },
                                        16 => {
                                            self.flags.f_cf = unsigned64 > 0xffff;
                                            res = (unsigned64 & 0xffff) as u32
                                        },
                                        8  => {
                                            self.flags.f_cf = unsigned64 > 0xff;
                                            res = (unsigned64 & 0xff) as u32;
                                        },
                                        _  => panic!("weird precision")
                                    }

                                    self.calc_flags(res, bits);
                                    self.regs.set_by_name(parts[0], res);


                                } else  {
                                    // shr reg, imm
                                    let value0:u32 = self.regs.get_by_name(parts[0]);
                                    let value1:u32 = self.get_inmediate(parts[1]);
                                    let mut unsigned64:u64 = value0 as u64;
                                    let res:u32;
                                    let bits = self.get_size(parts[0]);
                                
                                    for _ in 0..value1 {
                                        unsigned64 /= 2;
                                    }

                                    match bits {
                                        32 => {
                                            self.flags.f_cf = unsigned64 > 0xffffffff;
                                            res = (unsigned64 & 0xffffffff) as u32
                                        },
                                        16 => {
                                            self.flags.f_cf = unsigned64 > 0xffff;
                                            res = (unsigned64 & 0xffff) as u32
                                        },
                                        8  => {
                                            self.flags.f_cf = unsigned64 > 0xff;
                                            res = (unsigned64 & 0xff) as u32;
                                        },
                                        _  => panic!("weird precision")
                                    }

                                    self.calc_flags(res, bits);
                                    self.regs.set_by_name(parts[0], res);
                                }


                            } else {
                                // mem
                                if self.is_reg(parts[1]) {
                                    // shr mem, reg
                                    let value0:u32 = self.memory_read(parts[0]);
                                    let value1:u32 = self.regs.get_by_name(parts[1]);
                                    let mut unsigned64:u64 = value0 as u64;
                                    let res:u32;
                                    let bits = self.get_size(parts[0]);
                                    

                                    for _ in 0..value1 {
                                        unsigned64 /= 2;
                                    }

                                    match bits {
                                        32 => {
                                            self.flags.f_cf = unsigned64 > 0xffffffff;
                                            res = (unsigned64 & 0xffffffff) as u32
                                        },
                                        16 => {
                                            self.flags.f_cf = unsigned64 > 0xffff;
                                            res = (unsigned64 & 0xffff) as u32
                                        },
                                        8  => {
                                            self.flags.f_cf = unsigned64 > 0xff;
                                            res = (unsigned64 & 0xff) as u32;
                                        },
                                        _  => panic!("weird precision")
                                    }

                                    self.calc_flags(res, bits);
                                    self.memory_write(parts[0], res);

                                } else {
                                    // shr mem, imm
                                    let value0:u32 = self.memory_read(parts[0]);
                                    let value1:u32 = self.get_inmediate(parts[1]);
                                    let mut unsigned64:u64 = value0 as u64;
                                    let res:u32;
                                    let bits = self.get_size(parts[0]);
                                
                                    for _ in 0..value1 {
                                        unsigned64 /= 2;
                                    }

                                    match bits {
                                        32 => {
                                            self.flags.f_cf = unsigned64 > 0xffffffff;
                                            res = (unsigned64 & 0xffffffff) as u32
                                        },
                                        16 => {
                                            self.flags.f_cf = unsigned64 > 0xffff;
                                            res = (unsigned64 & 0xffff) as u32
                                        },
                                        8  => {
                                            self.flags.f_cf = unsigned64 > 0xff;
                                            res = (unsigned64 & 0xff) as u32;
                                        },
                                        _  => panic!("weird precision")
                                    }

                                    self.calc_flags(res, bits);
                                    self.memory_write(parts[0], res);
                                }

                            }


                        } else { // one param
                            if self.is_reg(op) { // reg
                                let value:i32 = self.regs.get_by_name(op) as i32;
                                let unsigned64:u64;
                                let res:u32;
                                let bits = self.get_size(op);

                                unsigned64 = (value as u64) / 2;

                                match bits {
                                    32 => {
                                        self.flags.f_cf = unsigned64 > 0xffffffff;
                                        res = (unsigned64 & 0xffffffff) as u32
                                    },
                                    16 => {
                                        self.flags.f_cf = unsigned64 > 0xffff;
                                        res = (unsigned64 & 0xffff) as u32
                                    },
                                    8  => {
                                        self.flags.f_cf = unsigned64 > 0xff;
                                        res = (unsigned64 & 0xff) as u32;
                                    },
                                    _  => panic!("weird precision")
                                }

                                self.calc_flags(res, bits);
                                self.regs.set_by_name(op, res);


                            } else { // mem 
                                let value:i32 = self.memory_read(op) as i32;
                                let unsigned64:u64;
                                let res:u32;
                                let bits = self.get_size(op);

                                unsigned64 = (value as u64) / 2;

                                match bits {
                                    32 => {
                                        self.flags.f_cf = unsigned64 > 0xffffffff;
                                        res = (unsigned64 & 0xffffffff) as u32
                                    },
                                    16 => {
                                        self.flags.f_cf = unsigned64 > 0xffff;
                                        res = (unsigned64 & 0xffff) as u32
                                    },
                                    8  => {
                                        self.flags.f_cf = unsigned64 > 0xff;
                                        res = (unsigned64 & 0xff) as u32;
                                    },
                                    _  => panic!("weird precision")
                                }

                                self.calc_flags(res, bits);
                                self.memory_write(op, res);
                            }
                        }

                    },

                    Some("shl") => {
                        let op = ins.op_str().unwrap();
                        let parts:Vec<&str> = op.split(", ").collect();
                        let twoparams = parts.len() == 2;

                        if twoparams {
                            if self.is_reg(parts[0]) {
                                // reg
                                if self.is_reg(parts[1]) {
                                    // shl reg, reg
                                    let value0:u32 = self.regs.get_by_name(parts[0]);
                                    let value1:u32 = self.regs.get_by_name(parts[1]);
                                    let mut unsigned64:u64 = value0 as u64;
                                    let res:u32;
                                    let bits = self.get_size(parts[0]);
                                
                                    for _ in 0..value1 {
                                        unsigned64 *= 2;
                                    }

                                    match bits {
                                        32 => {
                                            self.flags.f_cf = unsigned64 > 0xffffffff;
                                            res = (unsigned64 & 0xffffffff) as u32
                                        },
                                        16 => {
                                            self.flags.f_cf = unsigned64 > 0xffff;
                                            res = (unsigned64 & 0xffff) as u32
                                        },
                                        8  => {
                                            self.flags.f_cf = unsigned64 > 0xff;
                                            res = (unsigned64 & 0xff) as u32;
                                        },
                                        _  => panic!("weird precision")
                                    }

                                    self.calc_flags(res, bits);
                                    self.regs.set_by_name(parts[0], res);


                                } else  {
                                    // shl reg, imm
                                    let value0:u32 = self.regs.get_by_name(parts[0]);
                                    let value1:u32 = self.get_inmediate(parts[1]);
                                    let mut unsigned64:u64 = value0 as u64;
                                    let res:u32;
                                    let bits = self.get_size(parts[0]);
                                
                                    for _ in 0..value1 {
                                        unsigned64 *= 2;
                                    }

                                    match bits {
                                        32 => {
                                            self.flags.f_cf = unsigned64 > 0xffffffff;
                                            res = (unsigned64 & 0xffffffff) as u32
                                        },
                                        16 => {
                                            self.flags.f_cf = unsigned64 > 0xffff;
                                            res = (unsigned64 & 0xffff) as u32
                                        },
                                        8  => {
                                            self.flags.f_cf = unsigned64 > 0xff;
                                            res = (unsigned64 & 0xff) as u32;
                                        },
                                        _  => panic!("weird precision")
                                    }

                                    self.calc_flags(res, bits);
                                    self.regs.set_by_name(parts[0], res);
                                }

                            } else {
                                // mem
                                if self.is_reg(parts[1]) {
                                    // shl mem, reg
                                    let value0:u32 = self.memory_read(parts[0]);
                                    let value1:u32 = self.regs.get_by_name(parts[1]);
                                    let mut unsigned64:u64 = value0 as u64;
                                    let res:u32;
                                    let bits = self.get_size(parts[0]);
                                
                                    for _ in 0..value1 {
                                        unsigned64 *= 2;
                                    }

                                    match bits {
                                        32 => {
                                            self.flags.f_cf = unsigned64 > 0xffffffff;
                                            res = (unsigned64 & 0xffffffff) as u32
                                        },
                                        16 => {
                                            self.flags.f_cf = unsigned64 > 0xffff;
                                            res = (unsigned64 & 0xffff) as u32
                                        },
                                        8  => {
                                            self.flags.f_cf = unsigned64 > 0xff;
                                            res = (unsigned64 & 0xff) as u32;
                                        },
                                        _  => panic!("weird precision")
                                    }

                                    self.calc_flags(res, bits);
                                    self.memory_write(parts[0], res);

                                } else {
                                    // shl mem, imm
                                    let value0:u32 = self.memory_read(parts[0]);
                                    let value1:u32 = self.get_inmediate(parts[1]);
                                    let mut unsigned64:u64 = value0 as u64;
                                    let res:u32;
                                    let bits = self.get_size(parts[0]);
                                
                                    for _ in 0..value1 {
                                        unsigned64 *= 2;
                                    }

                                    match bits {
                                        32 => {
                                            self.flags.f_cf = unsigned64 > 0xffffffff;
                                            res = (unsigned64 & 0xffffffff) as u32
                                        },
                                        16 => {
                                            self.flags.f_cf = unsigned64 > 0xffff;
                                            res = (unsigned64 & 0xffff) as u32
                                        },
                                        8  => {
                                            self.flags.f_cf = unsigned64 > 0xff;
                                            res = (unsigned64 & 0xff) as u32;
                                        },
                                        _  => panic!("weird precision")
                                    }

                                    self.calc_flags(res, bits);
                                    self.memory_write(parts[0], res);
                                }

                            }


                        } else { // one param
                            if self.is_reg(op) { // reg
                                let value:i32 = self.regs.get_by_name(op) as i32;
                                let unsigned64:u64;
                                let res:u32;
                                let bits = self.get_size(op);

                                unsigned64 = (value as u64) * 2;

                                match bits {
                                    32 => {
                                        self.flags.f_cf = unsigned64 > 0xffffffff;
                                        res = (unsigned64 & 0xffffffff) as u32
                                    },
                                    16 => {
                                        self.flags.f_cf = unsigned64 > 0xffff;
                                        res = (unsigned64 & 0xffff) as u32
                                    },
                                    8  => {
                                        self.flags.f_cf = unsigned64 > 0xff;
                                        res = (unsigned64 & 0xff) as u32;
                                    },
                                    _  => panic!("weird precision")
                                }

                                self.calc_flags(res, bits);
                                self.regs.set_by_name(op, res);


                            } else { // mem 
                                let value:i32 = self.memory_read(op) as i32;
                                let unsigned64:u64;
                                let res:u32;
                                let bits = self.get_size(op);

                                unsigned64 = (value as u64) * 2;

                                match bits {
                                    32 => {
                                        self.flags.f_cf = unsigned64 > 0xffffffff;
                                        res = (unsigned64 & 0xffffffff) as u32
                                    },
                                    16 => {
                                        self.flags.f_cf = unsigned64 > 0xffff;
                                        res = (unsigned64 & 0xffff) as u32
                                    },
                                    8  => {
                                        self.flags.f_cf = unsigned64 > 0xff;
                                        res = (unsigned64 & 0xff) as u32;
                                    },
                                    _  => panic!("weird precision")
                                }

                                self.calc_flags(res, bits);
                                self.memory_write(op, res);
                            }
                        }
                    },



                    Some("ror") => {
                        let op = ins.op_str().unwrap();
                        let parts:Vec<&str> = op.split(", ").collect();
                        let twoparams = parts.len() == 1;

                        if twoparams {
                            if self.is_reg(parts[0]) {
                                // reg
                                if self.is_reg(parts[1]) {
                                    // ror reg, reg
                                    let value0:u32 = self.regs.get_by_name(parts[0]);
                                    let value1:u32 = self.regs.get_by_name(parts[1]);
                                    let res:u32;
                                    let bits:u8 = self.get_size(op);
                                
                                    res = self.rotate_right(value0, value1, bits as u32);
                            
                                    self.calc_flags(res, bits);
                                    self.regs.set_by_name(parts[0], res);


                                } else  {
                                    // ror reg, imm
                                    let value0:u32 = self.regs.get_by_name(parts[0]);
                                    let value1:u32 = self.get_inmediate(parts[1]);
                                    let res:u32;
                                    let bits:u8 = self.get_size(op);
                                    
                                    res = self.rotate_right(value0, value1, bits as u32);

                                    self.calc_flags(res, bits);
                                    self.regs.set_by_name(parts[0], res);
                                }


                            } else {
                                // mem
                                if self.is_reg(parts[1]) {
                                    // ror mem, reg
                                    let value0:u32 = self.memory_read(parts[0]);
                                    let value1:u32 = self.regs.get_by_name(parts[1]);

                                    let res:u32;
                                    let bits:u8 = self.get_size(op);

                                    res = self.rotate_right(value0, value1, bits as u32);
                              
                                    self.calc_flags(res, bits);
                                    self.memory_write(parts[0], res);

                                } else {
                                    // ror mem, imm
                                    let value0:u32 = self.memory_read(parts[0]);
                                    let value1:u32 = self.get_inmediate(parts[1]);
                                    let res:u32;
                                    let bits:u8 = self.get_size(op);

                                    res = self.rotate_right(value0, value1, bits as u32);

                                    self.calc_flags(res, bits);
                                    self.memory_write(parts[0], res);
                                }
                            }


                        } else { // one param
                            if self.is_reg(op) { 
                                // ror reg
                                let value:u32 = self.regs.get_by_name(op);
                                let res:u32;
                                let bits:u8 = self.get_size(op);

                                res = self.rotate_right(value, 1, bits as u32);

                                self.calc_flags(res, bits);
                                self.regs.set_by_name(op, res);


                            } else { 
                                // ror mem 
                                let value:u32 = self.memory_read(op);
                                let res:u32;
                                let bits:u8 = self.get_size(op);

                                res = self.rotate_right(value, 1, bits as u32);

                                self.calc_flags(res, bits);
                                self.memory_write(op, res);
                            }
                        }
                    },

                    Some("rol") => {
                        let op = ins.op_str().unwrap();
                        let parts:Vec<&str> = op.split(", ").collect();
                        let twoparams = parts.len() == 1;

                        if twoparams {
                            if self.is_reg(parts[0]) {
                                // reg
                                if self.is_reg(parts[1]) {
                                    // rol reg, reg
                                    let value0:u32 = self.regs.get_by_name(parts[0]);
                                    let value1:u32 = self.regs.get_by_name(parts[1]);
                                    let res:u32;
                                    let bits:u8 = self.get_size(op);
                                
                                    res = self.rotate_left(value0, value1, bits as u32);
                            
                                    self.calc_flags(res, bits);
                                    self.regs.set_by_name(parts[0], res);


                                } else  {
                                    // rol reg, imm
                                    let value0:u32 = self.regs.get_by_name(parts[0]);
                                    let value1:u32 = self.get_inmediate(parts[1]);
                                    let res:u32;
                                    let bits:u8 = self.get_size(op);
                                    
                                    res = self.rotate_left(value0, value1, bits as u32);

                                    self.calc_flags(res, bits);
                                    self.regs.set_by_name(parts[0], res);
                                }


                            } else {
                                // mem
                                if self.is_reg(parts[1]) {
                                    // rol mem, reg
                                    let value0:u32 = self.memory_read(parts[0]);
                                    let value1:u32 = self.regs.get_by_name(parts[1]);

                                    let res:u32;
                                    let bits:u8 = self.get_size(op);

                                    res = self.rotate_left(value0, value1, bits as u32);
                              
                                    self.calc_flags(res, bits);
                                    self.memory_write(parts[0], res);

                                } else {
                                    // rol mem, imm
                                    let value0:u32 = self.memory_read(parts[0]);
                                    let value1:u32 = self.get_inmediate(parts[1]);
                                    let res:u32;
                                    let bits:u8 = self.get_size(op);

                                    res = self.rotate_left(value0, value1, bits as u32);

                                    self.calc_flags(res, bits);
                                    self.memory_write(parts[0], res);
                                }
                            }


                        } else { // one param
                            if self.is_reg(op) { 
                                // rol reg
                                let value:u32 = self.regs.get_by_name(op);
                                let res:u32;
                                let bits:u8 = self.get_size(op);

                                res = self.rotate_left(value, 1, bits as u32);

                                self.calc_flags(res, bits);
                                self.regs.set_by_name(op, res);


                            } else { 
                                // rol mem 
                                let value:u32 = self.memory_read(op);
                                let res:u32;
                                let bits:u8 = self.get_size(op);

                                res = self.rotate_left(value, 1, bits as u32);

                                self.calc_flags(res, bits);
                                self.memory_write(op, res);
                            }
                        }
                    },

                    Some("mul") => {
                        let op = ins.op_str().unwrap();
                        let bits = self.get_size(op);
                        if self.is_reg(op) {
                            // mul reg

                            match bits {
                                32 => {
                                    let value1:u32 = self.regs.eax;
                                    let value2:u32 = self.regs.get_by_name(op);
                                    let res:u64 = value1 as u64 * value2 as u64;
                                    self.regs.edx = ((res & 0xffffffff00000000) >> 32) as u32;
                                    self.regs.eax = (res & 0x00000000ffffffff) as u32;
                                    self.flags.f_pf = (res & 0xff) % 2 == 0;
                                    self.flags.f_of = self.regs.edx != 0;
                                    self.flags.f_cf = self.regs.edx != 0;
                                },
                                16 => {
                                    let value1:u32 = self.regs.get_ax();
                                    let value2:u32 = self.regs.get_by_name(op);
                                    let res:u32 = value1 * value2;
                                    self.regs.set_dx((res & 0xffff0000) >> 16);
                                    self.regs.set_ax(res & 0xffff);
                                    self.flags.f_pf = (res & 0xff) % 2 == 0;
                                    self.flags.f_of = self.regs.get_dx() != 0;
                                    self.flags.f_cf = self.regs.get_dx() != 0;
                                },
                                8 => {
                                    let value1:u32 = self.regs.get_al();
                                    let value2:u32 = self.regs.get_by_name(op);
                                    let res:u32 = value1 * value2;
                                    self.regs.set_ax(res & 0xffff);
                                    self.flags.f_pf = (res & 0xff) % 2 == 0;
                                    self.flags.f_of = self.regs.get_ah() != 0;
                                    self.flags.f_cf = self.regs.get_ah() != 0;
                                },
                                _ => panic!("weird precision")
                            }

                        } else {
                            // mul mem
                            match bits {
                                32 => {
                                    let value1:u32 = self.regs.eax;
                                    let value2:u32 = self.memory_read(op);
                                    let res:u64 = value1 as u64 * value2 as u64;
                                    self.regs.edx = ((res & 0xffffffff00000000) >> 32) as u32;
                                    self.regs.eax = (res & 0x00000000ffffffff) as u32;
                                    self.flags.f_pf = (res & 0xff) % 2 == 0;
                                    self.flags.f_of = self.regs.edx != 0;
                                    self.flags.f_cf = self.regs.edx != 0;
                                },
                                16 => {
                                    let value1:u32 = self.regs.get_ax();
                                    let value2:u32 = self.memory_read(op) & 0xffff;
                                    let res:u32 = value1 * value2;
                                    self.regs.set_dx((res & 0xffff0000) >> 16);
                                    self.regs.set_ax(res & 0xffff);
                                    self.flags.f_pf = (res & 0xff) % 2 == 0;
                                    self.flags.f_of = self.regs.get_dx() != 0;
                                    self.flags.f_cf = self.regs.get_dx() != 0;
                                },
                                8 => {
                                    let value1:u32 = self.regs.get_al();
                                    let value2:u32 = self.memory_read(op) & 0xff;
                                    let res:u32 = value1 * value2;
                                    self.regs.set_ax(res & 0xffff);
                                    self.flags.f_pf = (res & 0xff) % 2 == 0;
                                    self.flags.f_of = self.regs.get_ah() != 0;
                                    self.flags.f_cf = self.regs.get_ah() != 0;
                                },
                                _ => panic!("weird precision")
                            }
                        }
                    },

                    Some("div") => {
                        let op = ins.op_str().unwrap();
                        let bits = self.get_size(op);
                        if self.is_reg(op) {
                            // div reg

                            match bits {
                                32 => {
                                    let mut value1:u64 = self.regs.edx as u64;
                                        value1 = value1 << 32;
                                        value1 += self.regs.eax as u64;
                                    let value2:u64 = self.regs.get_by_name(op) as u64;
                                    if value2 == 0 {
                                        self.flags.f_tf = true;
                                        println!("/!\\ division by 0 exception");
                                    } else {
                                        let resq:u64 = value1 / value2;
                                        let resr:u64 = value1 % value2;
                                        self.regs.eax = resq as u32;
                                        self.regs.edx = resr as u32;
                                        self.flags.f_pf = (resq & 0xff) % 2 == 0;
                                        self.flags.f_of = resq > 0xffffffff;
                                        if self.flags.f_of {
                                            println!("/!\\ int overflow exception on division")
                                        }
                                    }

                                },
                                16 => {
                                    let value1:u32 = (self.regs.get_dx() << 16) + self.regs.get_ax();
                                    let value2:u32 = self.regs.get_by_name(op);
                                    if value2 == 0 {
                                        self.flags.f_tf = true;
                                        println!("/!\\ division by 0 exception");
                                    } else {
                                        let resq:u32 = value1 / value2;
                                        let resr:u32 = value1 % value2;
                                        self.regs.set_ax(resq);
                                        self.regs.set_dx(resr);
                                        self.flags.f_pf = (resq & 0xff) % 2 == 0;
                                        self.flags.f_of = resq > 0xffff;
                                        self.flags.f_tf = false;
                                        if self.flags.f_of {
                                            println!("/!\\ int overflow exception on division")
                                        }
                                    }
             
                                },
                                8 => {
                                    let value1:u32 = self.regs.get_ax();
                                    let value2:u32 = self.regs.get_by_name(op);
                                    if value2 == 0 {
                                        self.flags.f_tf = true;
                                        println!("/!\\ division by 0 exception");
                                    } else {
                                        let resq:u32 = value1 / value2;
                                        let resr:u32 = value1 % value2;
                                        self.regs.set_al(resq);
                                        self.regs.set_ah(resr);
                                        self.flags.f_pf = (resq & 0xff) % 2 == 0;
                                        self.flags.f_of = resq > 0xff;
                                        self.flags.f_tf = false;
                                        if self.flags.f_of {
                                            println!("/!\\ int overflow exception on division")
                                        }
                                    }
                                    
                                },
                                _ => panic!("weird precision")
                            }

                        } else {
                            // div mem
                            match bits {
                                32 => {
                                    let mut value1:u64 = self.regs.edx as u64;
                                        value1 = value1 << 32;
                                        value1 += self.regs.eax as u64;
                                    let value2:u64 = self.memory_read(op) as u64;
                                    if value2 == 0 {
                                        self.flags.f_tf = true;
                                        println!("/!\\ division by 0 exception");
                                    } else {
                                        let resq:u64 = value1 / value2;
                                        let resr:u64 = value1 % value2;
                                        self.regs.eax = resq as u32;
                                        self.regs.edx = resr as u32;
                                        self.flags.f_pf = (resq & 0xff) % 2 == 0;
                                        self.flags.f_of = resq > 0xffffffff;
                                        if self.flags.f_of {
                                            println!("/!\\ int overflow exception on division")
                                        }
                                    }

                                },
                                16 => {
                                    let value1:u32 = (self.regs.get_dx() << 16) + self.regs.get_ax();
                                    let value2:u32 = self.memory_read(op);
                                    if value2 == 0 {
                                        self.flags.f_tf = true;
                                        println!("/!\\ division by 0 exception");
                                    } else {
                                        let resq:u32 = value1 / value2;
                                        let resr:u32 = value1 % value2;
                                        self.regs.set_ax(resq);
                                        self.regs.set_dx(resr);
                                        self.flags.f_pf = (resq & 0xff) % 2 == 0;
                                        self.flags.f_of = resq > 0xffff;
                                        self.flags.f_tf = false;
                                        if self.flags.f_of {
                                            println!("/!\\ int overflow exception on division")
                                        }
                                    }
             
                                },
                                8 => {
                                    let value1:u32 = self.regs.get_ax();
                                    let value2:u32 = self.memory_read(op);
                                    if value2 == 0 {
                                        self.flags.f_tf = true;
                                        println!("/!\\ division by 0 exception");
                                    } else {
                                        let resq:u32 = value1 / value2;
                                        let resr:u32 = value1 % value2;
                                        self.regs.set_al(resq);
                                        self.regs.set_ah(resr);
                                        self.flags.f_pf = (resq & 0xff) % 2 == 0;
                                        self.flags.f_of = resq > 0xff;
                                        self.flags.f_tf = false;
                                        if self.flags.f_of {
                                            println!("/!\\ int overflow exception on division")
                                        }
                                    }
                                    
                                },
                                _ => panic!("weird precision")
                            }
                        }
                    },

                    Some("idiv") => {
                        let op = ins.op_str().unwrap();
                        let bits = self.get_size(op);
                        if self.is_reg(op) {
                            // idiv reg

                            match bits {
                                32 => {
                                    let mut value1:u64 = self.regs.edx as u64;
                                        value1 = value1 << 32;
                                        value1 += self.regs.eax as u64;
                                    let value2:u64 = self.regs.get_by_name(op) as u64;
                                    if value2 == 0 {
                                        self.flags.f_tf = true;
                                        println!("/!\\ division by 0 exception");
                                    } else {
                                        let resq:u64 = value1 / value2;
                                        let resr:u64 = value1 % value2;
                                        self.regs.eax = resq as u32;
                                        self.regs.edx = resr as u32;
                                        self.flags.f_pf = (resq & 0xff) % 2 == 0;
                                        if resq > 0xffffffff {
                                            println!("/!\\ int overflow exception on division");
                                        } else {
                                            if (value1 as i64) > 0 && (resq as i32) < 0 {
                                                println!("/!\\ sign change exception on division");
                                            } else if (value1 as i64) < 0 && (resq as i32) > 0 { 
                                                println!("/!\\ sign change exception on division");
                                            }
                                        }
                                    }

                                },
                                16 => {
                                    let value1:u32 = (self.regs.get_dx() << 16) + self.regs.get_ax();
                                    let value2:u32 = self.regs.get_by_name(op);
                                    if value2 == 0 {
                                        self.flags.f_tf = true;
                                        println!("/!\\ division by 0 exception");
                                    } else {
                                        let resq:u32 = value1 / value2;
                                        let resr:u32 = value1 % value2;
                                        self.regs.set_ax(resq);
                                        self.regs.set_dx(resr);
                                        self.flags.f_pf = (resq & 0xff) % 2 == 0;
                                        self.flags.f_tf = false;
                                        if resq > 0xffff {
                                            println!("/!\\ int overflow exception on division")
                                        } else {
                                            if (value1 as i32) > 0 && (resq as i16) < 0 {
                                                println!("/!\\ sign change exception on division");
                                            } else if (value1 as i32) < 0 && (resq as i16) > 0 { 
                                                println!("/!\\ sign change exception on division");
                                            }
                                        }
                                    }
             
                                },
                                8 => {
                                    let value1:u32 = self.regs.get_ax();
                                    let value2:u32 = self.regs.get_by_name(op);
                                    if value2 == 0 {
                                        self.flags.f_tf = true;
                                        println!("/!\\ division by 0 exception");
                                    } else {
                                        let resq:u32 = value1 / value2;
                                        let resr:u32 = value1 % value2;
                                        self.regs.set_al(resq);
                                        self.regs.set_ah(resr);
                                        self.flags.f_pf = (resq & 0xff) % 2 == 0;
                                        self.flags.f_tf = false;
                                        if  resq > 0xff {
                                            println!("/!\\ int overflow exception on division")
                                        } else {
                                            if (value1 as i16) > 0 && (resq as i8) < 0 {
                                                println!("/!\\ sign change exception on division");
                                            } else if (value1 as i16) < 0 && (resq as i8) > 0 { 
                                                println!("/!\\ sign change exception on division");
                                            }
                                        }
                                    }
                                    
                                },
                                _ => panic!("weird precision")
                            }

                        } else {
                            // idiv mem
                            match bits {
                                32 => {
                                    let mut value1:u64 = self.regs.edx as u64;
                                        value1 = value1 << 32;
                                        value1 += self.regs.eax as u64;
                                    let value2:u64 = self.memory_read(op) as u64;
                                    if value2 == 0 {
                                        self.flags.f_tf = true;
                                        println!("/!\\ division by 0 exception");
                                    } else {
                                        let resq:u64 = value1 / value2;
                                        let resr:u64 = value1 % value2;
                                        self.regs.eax = resq as u32;
                                        self.regs.edx = resr as u32;
                                        self.flags.f_pf = (resq & 0xff) % 2 == 0;
                                        if resq > 0xffffffff {
                                            println!("/!\\ int overflow exception on division")
                                        } else {
                                            if (value1 as i64) > 0 && (resq as i32) < 0 {
                                                println!("/!\\ sign change exception on division");
                                            } else if (value1 as i64) < 0 && (resq as i32) > 0 { 
                                                println!("/!\\ sign change exception on division");
                                            }
                                        }
                                    }

                                },
                                16 => {
                                    let value1:u32 = (self.regs.get_dx() << 16) + self.regs.get_ax();
                                    let value2:u32 = self.memory_read(op);
                                    if value2 == 0 {
                                        self.flags.f_tf = true;
                                        println!("/!\\ division by 0 exception");
                                    } else {
                                        let resq:u32 = value1 / value2;
                                        let resr:u32 = value1 % value2;
                                        self.regs.set_ax(resq);
                                        self.regs.set_dx(resr);
                                        self.flags.f_pf = (resq & 0xff) % 2 == 0;
                                        self.flags.f_tf = false;
                                        if resq > 0xffff {
                                            println!("/!\\ int overflow exception on division")
                                        } else {
                                            if (value1 as i32) > 0 && (resq as i16) < 0 {
                                                println!("/!\\ sign change exception on division");
                                            } else if (value1 as i32) < 0 && (resq as i16) > 0 { 
                                                println!("/!\\ sign change exception on division");
                                            }
                                        }
                                    }
             
                                },
                                8 => {
                                    let value1:u32 = self.regs.get_ax();
                                    let value2:u32 = self.memory_read(op);
                                    if value2 == 0 {
                                        self.flags.f_tf = true;
                                        println!("/!\\ division by 0 exception");
                                    } else {
                                        let resq:u32 = value1 / value2;
                                        let resr:u32 = value1 % value2;
                                        self.regs.set_al(resq);
                                        self.regs.set_ah(resr);
                                        self.flags.f_pf = (resq & 0xff) % 2 == 0;
                                        self.flags.f_tf = false;
                                        if resq > 0xff {
                                            println!("/!\\ int overflow exception on division")
                                        } else {
                                            if (value1 as i16) > 0 && (resq as i8) < 0 {
                                                println!("/!\\ sign change exception on division");
                                            } else if (value1 as i16) < 0 && (resq as i8) > 0 { 
                                                println!("/!\\ sign change exception on division");
                                            }
                                        }
                                    }
                                    
                                },
                                _ => panic!("weird precision")
                            }
                        }
                    },

                    Some("imul") => {
                        //https://c9x.me/x86/html/file_module_x86_id_138.html
                        panic!("not implemented");
                    },

                    Some("movzx") => {
                        let op = ins.op_str().unwrap();
                        let parts:Vec<&str> = op.split(", ").collect();
                        //let bits1 = self.get_size(parts[0]);
                        //let bits2 = self.get_size(parts[1]);
                        let value2:u32;                    

                        if self.is_reg(parts[1]) {
                            // movzx reg, reg
                            value2 = self.regs.get_by_name(parts[1]);
                        } else {
                            // movzx reg, mem
                            value2 = self.memory_read(parts[1]);
                        }

                        self.regs.set_by_name(parts[0], value2);

                    }

                    Some("test") => {
                        let op = ins.op_str().unwrap();
                        let parts:Vec<&str> = op.split(", ").collect();
                        let bits = self.get_size(parts[0]);
                        let value1:u32;
                        let value2:u32;
                        let result:u32;

                        if self.is_reg(parts[0]) {
                            if self.is_reg(parts[1]) {
                                // cmp reg, reg
                                value1 = self.regs.get_by_name(parts[0]);
                                value2 = self.regs.get_by_name(parts[1]);

                            } else if parts[1].contains("[") {
                                // cmp reg, mem
                                value1 = self.regs.get_by_name(parts[0]);
                                value2 = self.memory_read(parts[1]);


                            } else {
                                // cmp reg, inm
                                value1 = self.regs.get_by_name(parts[0]);
                                value2 = self.get_inmediate(parts[1]);

                            }

                        } else {
                            if self.is_reg(parts[1]) {
                                // cmp mem, reg
                                value1 = self.memory_read(parts[0]);
                                value2 = self.regs.get_by_name(parts[1]);

                            } else {
                                // cmp mem, inm
                                value1 = self.memory_read(parts[0]);
                                value2 = self.get_inmediate(parts[1]);

                            }
                        }

                        result = value1 & value2;

                        self.flags.f_zf = result == 0;
                        self.flags.f_cf = false;
                        self.flags.f_of = false;
                        self.flags.f_pf = (result & 0xff) % 2 == 0;

                        match bits {
                            32 => self.flags.f_sf = (result as i32) < 0,
                            16 => self.flags.f_sf = (result as i16) < 0,
                            8  => self.flags.f_sf = (result as i8) < 0,
                            _  => panic!("weird precision")
                        }

                    },

                    Some("cmp") => {
                        let op = ins.op_str().unwrap();
                        let parts:Vec<&str> = op.split(", ").collect();
                        //let bits = self.get_size(parts[0]);
                        let value1:u32;
                        let value2:u32;

                        if self.is_reg(parts[0]) {
                            if self.is_reg(parts[1]) {
                                // cmp reg, reg
                                value1 = self.regs.get_by_name(parts[0]);
                                value2 = self.regs.get_by_name(parts[1]);

                            } else if parts[1].contains("[") {
                                // cmp reg, mem
                                value1 = self.regs.get_by_name(parts[0]);
                                value2 = self.memory_read(parts[1]);


                            } else {
                                // cmp reg, inm
                                value1 = self.regs.get_by_name(parts[0]);
                                value2 = self.get_inmediate(parts[1]);

                            }

                        } else {
                            if self.is_reg(parts[1]) {
                                // cmp mem, reg
                                value1 = self.memory_read(parts[0]);
                                value2 = self.regs.get_by_name(parts[1]);

                            } else {
                                // cmp mem, inm
                                value1 = self.memory_read(parts[0]);
                                value2 = self.get_inmediate(parts[1]);

                            }
                        }

                        if value1 < value2 {
                            self.flags.f_zf = false;
                            self.flags.f_cf = true;
                        } else if value1 > value2 {
                            self.flags.f_zf = false;
                            self.flags.f_cf = false;
                        } else if value1 == value2 {
                            self.flags.f_zf = true;
                            self.flags.f_cf = false;
                        }

                    },  


                    //branches: https://web.itu.edu.tr/kesgin/mul06/intel/instr/jxx.html
                    //          https://c9x.me/x86/html/file_module_x86_id_146.html
                    //          http://unixwiz.net/techtips/x86-jumps.html <---aqui

                    Some("jo") => {
                        if self.flags.f_of {
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        }
                    },

                    Some("jno") => {
                        if !self.flags.f_of {
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        }
                    },

                    Some("js") => {
                        if self.flags.f_sf {
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        }
                    },

                    Some("jns") => {
                        if !self.flags.f_sf {
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        }
                    },

                    Some("je") => {
                        if self.flags.f_zf {
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        }
                    },

                    Some("jz") => {
                        if self.flags.f_zf {
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        }
                    },


                    Some("jne") => {
                        if !self.flags.f_zf {
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        }
                    },

                    Some("jnz") => {
                        if !self.flags.f_zf {
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        }
                    },

                    Some("jb") => {
                        if self.flags.f_cf {
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        }
                    },

                    Some("jnae") => {
                        if self.flags.f_cf {
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        }
                    },

                    Some("jc") => {
                        if self.flags.f_cf {
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        }
                    },

                    Some("jnb") => {
                        if !self.flags.f_cf {
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        }
                    },

                    Some("jae") => {
                        if !self.flags.f_cf {
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        }
                    },

                    Some("jnc") => {
                        if !self.flags.f_cf {
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        }
                    },

                    Some("jbe") => {
                        if self.flags.f_cf || self.flags.f_zf {
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        }
                    },

                    Some("jna") => {
                        if self.flags.f_cf || self.flags.f_zf {
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        }
                    },

                    Some("ja") => {
                        if !self.flags.f_cf && !self.flags.f_zf {
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        }
                    },

                    Some("jnbe") => {
                        if !self.flags.f_cf && !self.flags.f_zf {
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        }
                    },

                    Some("jl") => {
                        if self.flags.f_sf != self.flags.f_of {
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        }
                    },

                    Some("jnge") => {
                        if self.flags.f_sf != self.flags.f_of {
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        }
                    },

                    Some("jge") => {
                        if self.flags.f_sf == self.flags.f_of {
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        }
                    },

                    Some("jnl") => {
                        if self.flags.f_sf == self.flags.f_of {
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        }
                    },

                    Some("jle") => {
                        if self.flags.f_zf || self.flags.f_sf != self.flags.f_of {
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        }
                    },

                    Some("jng") => {
                        if self.flags.f_zf || self.flags.f_sf != self.flags.f_of {
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        }
                    },

                    Some("jg") => {
                        if !self.flags.f_zf && self.flags.f_sf != self.flags.f_of {
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        }
                    },

                    Some("jnle") => {
                        if !self.flags.f_zf && self.flags.f_sf != self.flags.f_of {
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        }
                    },

                    Some("jp") => {
                        if self.flags.f_pf {
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        }
                    },

                    Some("jpe") => {
                        if self.flags.f_pf {
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        }
                    },

                    Some("jnp") => {
                        if !self.flags.f_pf {
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        }
                    },

                    Some("jpo") => {
                        if !self.flags.f_pf {
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        }
                    },

                    Some("jcxz") => {
                        if self.regs.get_cx() == 0 {
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        }
                    },

                    Some("jecxz") => {
                        if self.regs.ecx == 0 {
                            let addr = self.get_inmediate(ins.op_str().unwrap());       
                            self.set_eip(addr, true);
                            break;
                        }
                    },


                    //TODO: test syenter / int80
                    Some("int3") => {
                        panic!("int 3 sigtrap!!!!");
                        return;
                    },

                    Some("nop") => {

                    },

                    Some("cpuid") => {
                        // guloader checks bit31 which is if its hipervisor
                    },

                    Some("loop") => {
                        let addr = self.get_inmediate(ins.op_str().unwrap());
                        if addr > 0xffff {
                            if self.regs.ecx == 0 {
                                self.regs.ecx = 0xffffffff;
                            } else {
                                self.regs.ecx -= 1;
                            }

                            if self.regs.ecx > 0 {
                                self.set_eip(addr, false);
                                break;
                            }

                        } else {
                            if self.regs.get_cx() == 0 {
                                self.regs.set_cx(0xffff);
                            } else {
                                self.regs.set_cx(self.regs.get_cx() -1);
                            }
                
                            if self.regs.get_cx() > 0 {
                                self.set_eip(addr, false);
                                break;
                            }
                        }
                    },

                    Some("loope") => {
                        let addr = self.get_inmediate(ins.op_str().unwrap());
                        if addr > 0xffff {
                            if self.regs.ecx == 0 {
                                self.regs.ecx = 0xffffffff;
                            } else {
                                self.regs.ecx -= 1;
                            }
                            
                            if self.regs.ecx > 0 && self.flags.f_zf {
                                self.set_eip(addr, false);
                                break;
                            }
                        } else {
                            if self.regs.get_cx() == 0 {
                                self.regs.set_cx(0xffff);
                            } else {
                                self.regs.set_cx(self.regs.get_cx() -1);
                            }
                            
                            if self.regs.get_cx() > 0 && self.flags.f_zf  {
                                self.set_eip(addr, false);
                                break;
                            }
                        }
                    },

                    Some("loopz") => {
                        let addr = self.get_inmediate(ins.op_str().unwrap());
                        if addr > 0xffff {
                            if self.regs.ecx == 0 {
                                self.regs.ecx = 0xffffffff;
                            } else {
                                self.regs.ecx -= 1;
                            }
                            
                            if self.regs.ecx > 0 && self.flags.f_zf {
                                self.set_eip(addr, false);
                                break;
                            }
                        } else {
                            if self.regs.get_cx() == 0 {
                                self.regs.set_cx(0xffff);
                            } else {
                                self.regs.set_cx(self.regs.get_cx() -1);
                            }
                            
                            if self.regs.get_cx() > 0 && self.flags.f_zf  {
                                self.set_eip(addr, false);
                                break;
                            }
                        }
                    },

                    Some("loopne") => {
                        let addr = self.get_inmediate(ins.op_str().unwrap());
                        if addr > 0xffff {
                            if self.regs.ecx == 0 {
                                self.regs.ecx = 0xffffffff;
                            } else {
                                self.regs.ecx -= 1;
                            }
                            
                            if self.regs.ecx > 0 && !self.flags.f_zf {
                                self.set_eip(addr, false);
                                break;
                            }
                        } else {
                            if self.regs.get_cx() == 0 {
                                self.regs.set_cx(0xffff);
                            } else {
                                self.regs.set_cx(self.regs.get_cx() -1);
                            }
                            
                            if self.regs.get_cx() > 0 && !self.flags.f_zf  {
                                self.set_eip(addr, false);
                                break;
                            }
                        }
                    },

                    Some("loopnz") => {
                        let addr = self.get_inmediate(ins.op_str().unwrap());
                        if addr > 0xffff {
                            if self.regs.ecx == 0 {
                                self.regs.ecx = 0xffffffff;
                            } else {
                                self.regs.ecx -= 1;
                            }
                            
                            if self.regs.ecx > 0 && !self.flags.f_zf {
                                self.set_eip(addr, false);
                                break;
                            }
                        } else {
                            if self.regs.get_cx() == 0 {
                                self.regs.set_cx(0xffff);
                            } else {
                                self.regs.set_cx(self.regs.get_cx() -1);
                            }
                            
                            if self.regs.get_cx() > 0 && !self.flags.f_zf  {
                                self.set_eip(addr, false);
                                break;
                            }
                        }
                    },

                    Some("lea") => {
                        let ops = ins.op_str().unwrap();
                        let parts:Vec<&str> = ops.split(", ").collect();
                        let spl:Vec<&str> = parts[1].split("[").collect::<Vec<&str>>()[1].split("]").collect::<Vec<&str>>()[0].split(" ").collect();
                        let mut result:u32 = 0;
                        let value1:u32;
                        let value2:u32;

                        value1 = self.regs.get_by_name(spl[0]);
                        value2 = self.get_inmediate(spl[2]);

                        if spl[1] == "+" {
                            result = value1 + value2;
                        } else if spl[1] == "-" {
                            result = value1 - value2;
                        } else {
                            panic!("unimplemented operation");
                        }

                        self.regs.set_by_name(parts[0], result);
                    },

                    Some("int") => {
                        let op = ins.op_str().unwrap();
                        let interrupt = u32::from_str_radix(op.trim_start_matches("0x"),16).expect("conversion error");
                        match interrupt {
                            0x80 => {
                                println!("/!\\ interrupt 0x80 function:{}", self.regs.eax);
                                match self.regs.eax {
                                    11 => {
                                        panic!("execve() detected");
                                    }
                                    _ => {}
                                }
                            },
                            _ => {
                                panic!("unknown interrupt {}", interrupt);
                            }
                        }
                    },

                    Some(&_) =>  { 
                        panic!("unimplemented instruction");
                    },
                    None => println!("unknon instruction"),
                }

                self.regs.eip += sz as u32;

            }
        }   

        

    }

}