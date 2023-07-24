use std::io::Write;
use std::num::ParseIntError;

pub struct Console {}

impl Console {
    pub fn new() -> Console {
        println!("--- console ---");
        Console {}
    }

    pub fn print(&self, msg: &str) {
        print!("{}", msg);
        std::io::stdout().flush().unwrap();
    }

    pub fn cmd(&self) -> String {
        let mut line = String::new();
        self.print("=>");
        std::io::stdin().read_line(&mut line).unwrap();
        line = line.replace("\r", ""); // some shells (windows) also add \r  thanks Alberto Segura
        line.truncate(line.len() - 1);
        line.to_lowercase()
    }

    pub fn cmd2(&self) -> String {
        let mut line = String::new();
        self.print("=>");
        std::io::stdin().read_line(&mut line).unwrap();
        line = line.replace("\r", ""); // some shells (windows) also add \r  thanks Alberto Segura
        line.truncate(line.len() - 1);
        line
    }

    pub fn cmd_hex32(&self) -> Result<u32, ParseIntError> {
        let mut x = self.cmd();

        if x.ends_with('h') {
            x = x[0..x.len() - 1].to_string();
        }
        if x.starts_with("0x") {
            x = x[2..x.len()].to_string();
        }

        return u32::from_str_radix(x.as_str(), 16);
    }

    pub fn cmd_hex64(&self) -> Result<u64, ParseIntError> {
        let mut x = self.cmd();
        if x.ends_with('h') {
            x = x[0..x.len() - 1].to_string();
        }
        if x.starts_with("0x") {
            x = x[2..x.len()].to_string();
        }

        return u64::from_str_radix(x.as_str(), 16);
    }

    pub fn cmd_num(&self) -> Result<u64, ParseIntError> {
        u64::from_str_radix(self.cmd().as_str(), 10)
    }

    /*
    pub fn cmd_num<T>(&self) -> Result<T,ParseIntError> {
        self.cmd().as_str().parse::<T>()
    }*/

    pub fn help(&self) {
        println!("--- help ---");
        println!("q ...................... quit");
        println!("cls .................... clear screen");
        println!("h ...................... help");
        println!("s ...................... stack");
        println!("v ...................... vars");
        println!("sv ..................... set verbose level 0, 1 or 2");
        println!("r ...................... register show all");
        println!("r reg .................. show reg");
        println!("rc ..................... register change");
        println!("f ...................... show all flags");
        println!("fc ..................... clear all flags");
        println!("fz ..................... toggle flag zero");
        println!("fs ..................... toggle flag sign");
        println!("c ...................... continue");
        println!("b ...................... breakpoint list");
        println!("ba ..................... breakpoint on address");
        println!("bi ..................... breakpoint on instruction number");
        println!("bmr .................... breakpoint on read memory");
        println!("bmw .................... breakpoint on write memory");
        println!("bmx .................... breakpoint on execute memory");
        println!("bcmp ................... break on next cmp or test");
        println!("bc ..................... clear breakpoint");
        println!("n ...................... next instruction");
        println!("eip .................... change eip");
        println!("rip .................... change rip");
        println!("push ................... push dword to the stack");
        println!("pop .................... pop dword from stack");
        println!("fpu .................... fpu view");
        println!("md5 .................... check the md5 of a memory map");
        println!("seh .................... view SEH");
        println!("veh .................... view vectored execption pointer");
        println!("m ...................... memory maps");
        println!("ms ..................... memory filtered by keyword string");
        println!("ma ..................... memory allocs");
        println!("mc ..................... memory create map");
        println!("mn ..................... memory name of an address");
        println!("ml ..................... memory load file content to map");
        println!("mr ..................... memory read, speficy ie: dword ptr [esi]");
        println!(
            "mw ..................... memory write, speficy ie: dword ptr [esi]  and then: 1af"
        );
        println!("mwb .................... memory write bytes, input spaced bytes");
        println!("md ..................... memory dump");
        println!("mrd .................... memory read dwords");
        println!("mrq .................... memory read qwords");
        println!("mds .................... memory dump string");
        println!("mdw .................... memory dump wide string");
        println!("mdd .................... memory dump to disk");
        println!("mdda ................... memory dump all allocations to disk");
        println!("mt ..................... memory test");
        println!("ss ..................... search string");
        println!("sb ..................... search bytes");
        println!("sba .................... search bytes in all the maps");
        println!("ssa .................... search string in all the maps");
        println!("ll ..................... linked list walk");
        println!("d ...................... dissasemble");
        println!("dt ..................... dump structure");
        println!("enter .................. step into");
        println!("tr ..................... trace reg");
        println!("trc .................... trace regs clear");
        println!("ldr .................... show ldr linked list");
        println!("iat .................... find api name in all iat's ");
        println!("iatx ................... find exact api name in all iat's");
        println!("iatd ................... dump the iat of specific module");

        //println!("o ...................... step over");
        println!();
        println!("---");
    }
}
