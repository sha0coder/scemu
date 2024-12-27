use std::io::Write;
use std::num::ParseIntError;

pub struct Console {}

impl Default for Console {
    fn default() -> Self {
        Self::new()
    }
}

impl Console {
    pub fn new() -> Console {
        log::info!("--- console ---");
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

        u32::from_str_radix(x.as_str(), 16)
    }

    pub fn cmd_hex64(&self) -> Result<u64, ParseIntError> {
        let mut x = self.cmd();
        if x.ends_with('h') {
            x = x[0..x.len() - 1].to_string();
        }
        if x.starts_with("0x") {
            x = x[2..x.len()].to_string();
        }

        u64::from_str_radix(x.as_str(), 16)
    }

    pub fn cmd_num(&self) -> Result<u64, ParseIntError> {
        self.cmd().as_str().parse::<u64>()
    }

    /*
    pub fn cmd_num<T>(&self) -> Result<T,ParseIntError> {
        self.cmd().as_str().parse::<T>()
    }*/

    pub fn help(&self) {
        log::info!("--- help ---");
        log::info!("q ...................... quit");
        log::info!("cls .................... clear screen");
        log::info!("h ...................... help");
        log::info!("s ...................... stack");
        log::info!("v ...................... vars");
        log::info!("sv ..................... set verbose level 0, 1 or 2");
        log::info!("r ...................... register show all");
        log::info!("r reg .................. show reg");
        log::info!("rc ..................... register change");
        log::info!("f ...................... show all flags");
        log::info!("fc ..................... clear all flags");
        log::info!("fz ..................... toggle flag zero");
        log::info!("fs ..................... toggle flag sign");
        log::info!("c ...................... continue");
        log::info!("b ...................... breakpoint list");
        log::info!("ba ..................... breakpoint on address");
        log::info!("bi ..................... breakpoint on instruction number");
        log::info!("bmr .................... breakpoint on read memory");
        log::info!("bmw .................... breakpoint on write memory");
        log::info!("bmx .................... breakpoint on execute memory");
        log::info!("bcmp ................... break on next cmp or test");
        log::info!("bc ..................... clear breakpoint");
        log::info!("n ...................... next instruction");
        log::info!("eip .................... change eip");
        log::info!("rip .................... change rip");
        log::info!("push ................... push dword to the stack");
        log::info!("pop .................... pop dword from stack");
        log::info!("fpu .................... fpu view");
        log::info!("md5 .................... check the md5 of a memory map");
        log::info!("seh .................... view SEH");
        log::info!("veh .................... view vectored execption pointer");
        log::info!("m ...................... memory maps");
        log::info!("ms ..................... memory filtered by keyword string");
        log::info!("ma ..................... memory allocs");
        log::info!("mc ..................... memory create map");
        log::info!("mn ..................... memory name of an address");
        log::info!("ml ..................... memory load file content to map");
        log::info!("mr ..................... memory read, speficy ie: dword ptr [esi]");
        log::info!(
            "mw ..................... memory write, speficy ie: dword ptr [esi]  and then: 1af"
        );
        log::info!("mwb .................... memory write bytes, input spaced bytes");
        log::info!("md ..................... memory dump");
        log::info!("mrd .................... memory read dwords");
        log::info!("mrq .................... memory read qwords");
        log::info!("mds .................... memory dump string");
        log::info!("mdw .................... memory dump wide string");
        log::info!("mdd .................... memory dump to disk");
        log::info!("mdda ................... memory dump all allocations to disk");
        log::info!("mt ..................... memory test");
        log::info!("ss ..................... search string");
        log::info!("sb ..................... search bytes");
        log::info!("sba .................... search bytes in all the maps");
        log::info!("ssa .................... search string in all the maps");
        log::info!("ll ..................... linked list walk");
        log::info!("d ...................... dissasemble");
        log::info!("dt ..................... dump structure");
        log::info!("enter .................. step into");
        log::info!("tr ..................... trace reg");
        log::info!("trc .................... trace regs clear");
        log::info!("ldr .................... show ldr linked list");
        log::info!("iat .................... find api name in all iat's ");
        log::info!("iatx ................... addr to api name");
        log::info!("iatd ................... dump the iat of specific module");

        //log::info!("o ...................... step over");
        log::info!("");
        log::info!("---");
    }
}
