extern crate clap;

mod emu32;
mod config;

use emu32::Emu32;
use config::Config;
use clap::{Arg, App};


fn main() {
    let mut cfg = Config::new();
    let matches = App::new("SCEMU 32bits emulator for Shellcodes")
                    .version("0.1.1")
                    .author("@sha0coder")
                    .arg(Arg::with_name("filename")
                        .short("f")
                        .long("filename")
                        .value_name("FILE")
                        .help("set the shellcode binary file.")
                        .takes_value(true))
                    .arg(Arg::with_name("quick")
                        .short("q")
                        .long("quick")
                        .help("quick mode only print relevant data.")
                        .takes_value(false))
                    .arg(Arg::with_name("memory")
                        .short("m")
                        .long("memory")
                        .help("trace all the memory accesses read and write.")
                        .takes_value(false))
                    .arg(Arg::with_name("registers")
                        .short("r")
                        .long("regs")
                        .help("print the register values in every step.")
                        .takes_value(false))
                    .arg(Arg::with_name("register")
                        .short("R")
                        .long("reg")
                        .value_name("REGISTER")
                        .help("trace a specific register in every step, value and content")
                        .takes_value(true))
                    .arg(Arg::with_name("console")
                        .short("c")
                        .long("console")
                        .help("select in which moment will spawn the console to inspect.")
                        .value_name("NUMBER")
                        .takes_value(true))
                    .arg(Arg::with_name("loops")
                        .short("l")
                        .long("loops")
                        .help("show loop interations, it is slow.")
                        .takes_value(false))
                    .arg(Arg::with_name("nocolors")
                        .short("n")
                        .long("nocolors")
                        .help("print without colors for redirectin to a file >out")
                        .takes_value(false))
                    .arg(Arg::with_name("string")
                        .short("s")
                        .long("string")
                        .help("monitor string on a specific address")
                        .value_name("ADDRESS")
                        .takes_value(true))
                    .arg(Arg::with_name("bytes")
                        .short("b")
                        .long("bytes")
                        .help("monitor bytes on a specific address")
                        .value_name("ADDRESS")
                        .takes_value(true))
                    .arg(Arg::with_name("dword")
                        .short("d")
                        .long("dword")
                        .help("monitor dword on a specific address")
                        .value_name("ADDRESS")
                        .takes_value(true))
                    .arg(Arg::with_name("word")
                        .short("w")
                        .long("word")
                        .help("monitor word on a specific address")
                        .value_name("ADDRESS")
                        .takes_value(true))
                    .get_matches();


    if !matches.is_present("filename") {
        println!("the filename is mandatory, try -f <FILENAME> or --help");
    }

    let filename = matches.value_of("filename").expect("please enter the filename.");
    cfg.quick_mode = matches.is_present("quick");
    cfg.trace_mem = matches.is_present("memory");
    cfg.trace_regs = matches.is_present("registers");
    if matches.is_present("register") {
        cfg.trace_reg = true;
        cfg.reg_name = matches.value_of("register").expect("select the 32bit register example: eax").to_string();
    }
    if matches.is_present("console") {
        cfg.console = true;
        cfg.console_num = u64::from_str_radix(matches.value_of("console").expect("select the number of moment to inspect"), 10).expect("select a valid number to spawn console");
    }
    cfg.loops = matches.is_present("loops");
    cfg.nocolors = matches.is_present("nocolors");
    if matches.is_present("string") {
        cfg.trace_string = true;
        cfg.string_addr = u32::from_str_radix(matches.value_of("string").expect("select the address of the string").trim_start_matches("0x"), 16).expect("invalid address");
    }
    if matches.is_present("dword") {
        cfg.trace_dword = true;
        cfg.dword_addr = u32::from_str_radix(matches.value_of("dword").expect("select the address of the dword").trim_start_matches("0x"), 16).expect("invalid address");
    }
    if matches.is_present("word") {
        cfg.trace_word = true;
        cfg.word_addr = u32::from_str_radix(matches.value_of("word").expect("select the address of the word").trim_start_matches("0x"), 16).expect("invalid address");
    }
    if matches.is_present("bytes") {
        cfg.trace_bytes = true;
        cfg.bytes_addr = u32::from_str_radix(matches.value_of("bytes").expect("select the address of the bytes to show").trim_start_matches("0x"), 16).expect("invalid address");
    }
    


    let mut emu32 = Emu32::new();
    emu32.init();
    emu32.set_config(cfg);
    emu32.load_code(&filename.to_string());
    emu32.run();
}
