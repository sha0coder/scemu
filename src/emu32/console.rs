use std::io::Write;

pub struct Console {

}

impl Console {
    pub fn new() -> Console {
        println!("--- console ---");
        Console{}
    }

    pub fn cmd(&self) -> String {
        let mut line = String::new();
        print!("=> ");
        std::io::stdout().flush().unwrap();
        std::io::stdin().read_line(&mut line).unwrap();
        line.truncate(line.len() - 1);
        return line;
    }

    pub fn help(&self) {
        println!("--- help ---");
        println!("q ...................... quit");
        println!("h ...................... help");
        println!("s ...................... stack");
        println!("v ...................... vars");
        println!("r ...................... show all regs");
        println!("f ...................... show all flags");
        println!("cf ..................... clear all flags");
        println!("c ...................... continue");
        println!("n ...................... next instruction");
        println!("eip .................... change eip");
        println!("m ...................... memory maps");
        println!("mr ..................... memory read, speficy ie: dword ptr [esi]");
        println!("mw ..................... memory read, speficy ie: dword ptr [esi]  and then: 1af");
        println!("");
        println!("---");
    }

}