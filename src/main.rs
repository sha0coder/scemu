mod emu32;

use std::env;
use emu32::Emu32;

fn usage() {
    println!("scemu [filename] [mode] <line to inspect optional>");
    println!("   modes:");
    println!("        n            normal mode");
    println!("        q            quick, dont print assembly instructions to be quicker.");
    println!("        l            loop, show  loop iterations, very slow.");
    println!("        r            regs, view the register values in every step.");
    println!("        m            memory, trace memory reads and writes.");
    println!();
    std::process::exit(1);
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        usage();
    }

    let filename = &args[1];

    let mut emu32 = Emu32::new();
    emu32.init();


    let mode = &args[2];

    if mode == "q" {
        emu32.mode_quick();
    } else if mode == "l" {
        emu32.mode_loop();
    } else  if mode == "r" {
        emu32.mode_regs();
    } else if mode == "m" {
        emu32.mode_tracemem();
    }
    

    if args.len() == 4 {
        emu32.explain(&args[3]);
    }
    
    emu32.load_code(&filename);
    emu32.run();


}
