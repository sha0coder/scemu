use std::io::Write;
use std::num::ParseIntError;


pub struct Console {

}

impl Console {
    pub fn new() -> Console {
        println!("--- console ---");
        Console{}
    }

    pub fn print(&self, msg:&str) {
        print!("{}", msg);
        std::io::stdout().flush().unwrap();
    }

    pub fn cmd(&self) -> String {
        let mut line = String::new();
        self.print("=>");
        std::io::stdin().read_line(&mut line).unwrap();
        line.truncate(line.len() - 1);
        return line;
    }

    pub fn cmd_hex(&self) -> Result<u32,ParseIntError> {
        return u32::from_str_radix(self.cmd().as_str().trim_start_matches("0x"), 16);
    }

    pub fn cmd_hex64(&self) -> Result<u64,ParseIntError> {
        return u64::from_str_radix(self.cmd().as_str().trim_start_matches("0x"), 16);
    }

    pub fn cmd_num(&self) -> Result<u32,ParseIntError> {
        return u32::from_str_radix(self.cmd().as_str(), 10);
    }

    pub fn help(&self) {
        println!("--- help ---");
        println!("q ...................... quit");
        println!("h ...................... help");
        println!("s ...................... stack");
        println!("v ...................... vars");
        println!("r ...................... register show all");
        println!("r reg .................. show reg");
        println!("rc ..................... register change");
        println!("f ...................... show all flags");
        println!("cf ..................... clear all flags");
        println!("c ...................... continue");
        println!("ba ..................... breakpoint on address");
        println!("bi ..................... breakpoint on instruction number");
        println!("n ...................... next instruction");
        println!("eip .................... change eip");
        println!("push ................... push dword to the stack");
        println!("pop .................... pop dword from stack");
        println!("fpu .................... fpu view");
        println!("m ...................... memory maps");
        println!("mc ..................... memory create map");
        println!("mn ..................... memory name of an address");
        println!("ml ..................... memory load file content to map");
        println!("mr ..................... memory read, speficy ie: dword ptr [esi]");
        println!("mw ..................... memory read, speficy ie: dword ptr [esi]  and then: 1af");
        println!("md ..................... memory dump");
        println!("mds .................... memory dump string");
        println!("mdw .................... memory dump wide string");
        println!("mdd .................... memory dump to disk");
        println!("ss ..................... search string");
        println!("sb ..................... search bytes");
        println!("sba .................... search bytes in all the maps");
        println!("ssa .................... search string in all the maps");
        println!("ll ..................... linked list walk");
        println!("d ...................... dissasemble");
        println!("");
        println!("---");
    }

}
