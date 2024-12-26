extern crate clap;

use clap::{App, Arg};
use env_logger::Env;
use libmwemu::emu32;
use libmwemu::emu64;
use std::io::Write as _;

macro_rules! match_register_arg {
    ($matches:expr, $emu:expr, $reg:expr) => {
        if $matches.is_present($reg) {
            let value = u64::from_str_radix(
                $matches
                    .value_of($reg)
                    .expect(concat!("select the ", $reg, " register"))
                    .trim_start_matches("0x"),
                16,
            )
            .expect("invalid address");
            $emu.regs.set_reg_by_name($reg, value);
        }
    };
}

macro_rules! clap_arg {
    // Basic argument with just name, short, long, and help
    ($name:expr, $short:expr, $long:expr, $help:expr) => {
        Arg::with_name($name)
            .short($short)
            .long($long)
            .help($help)
            .takes_value(false)
    };

    // Argument that takes a value
    ($name:expr, $short:expr, $long:expr, $help:expr, $value_name:expr) => {
        Arg::with_name($name)
            .short($short)
            .long($long)
            .help($help)
            .takes_value(true)
            .value_name($value_name)
    };

    // Multiple flag variant (using true/false as explicit boolean)
    ($name:expr, $short:expr, $long:expr, $help:expr, multiple: $multiple:expr) => {
        Arg::with_name($name)
            .short($short)
            .long($long)
            .help($help)
            .multiple($multiple)
            .takes_value(false)
    };
}

fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info"))
        .format(|buf, record| writeln!(buf, "{}", record.args()))
        .init();

    let matches = App::new("MWEMU emulator for malware")
        .version(env!("CARGO_PKG_VERSION"))
        .author("@sha0coder")
        .arg(clap_arg!("filename", "f", "filename", "set the shellcode binary file.", "FILE"))
        .arg(clap_arg!("verbose", "v", "verbose", "-vv for view the assembly, -v only messages, without verbose only see the api calls and goes faster", multiple: true))
        .arg(clap_arg!("64bits", "6", "64bits", "enable 64bits architecture emulation"))
        .arg(clap_arg!("memory", "m", "memory", "trace all the memory accesses read and write."))
        .arg(clap_arg!("maps", "M", "maps", "select the memory maps folder", "PATH"))
        .arg(clap_arg!("registers", "r", "regs", "print the register values in every step."))
        .arg(clap_arg!("register", "R", "reg", "trace a specific register in every step, value and content", "REGISTER1,REGISTER2"))
        .arg(clap_arg!("console", "c", "console", "select in which moment will spawn the console to inspect.", "NUMBER"))
        .arg(clap_arg!("loops", "l", "loops", "show loop interations, it is slow."))
        .arg(clap_arg!("nocolors", "n", "nocolors", "print without colors for redirectin to a file >out"))
        .arg(clap_arg!("string", "s", "string", "monitor string on a specific address", "ADDRESS"))
        .arg(clap_arg!("inspect", "i", "inspect", "monitor memory like: -i 'dword ptr [ebp + 0x24]", "DIRECTION"))
        //.arg(clap_arg!("endpoint", "e", "endpoint", "perform communications with the endpoint, use tor or vpn!"))
        .arg(clap_arg!("console_addr", "C", "console_addr", "spawn console on first eip = address", "ADDRESS"))
        .arg(clap_arg!("entry_point", "a", "entry", "entry point of the shellcode, by default starts from the beginning.", "ADDRESS"))
        .arg(clap_arg!("exit_position", "e", "exit", "exit position of the shellcode", "POSITION"))
        .arg(clap_arg!("code_base_address", "b", "base", "set base address for code", "ADDRESS"))
        .arg(clap_arg!("stack_address", "", "stack_address", "set stack address", "ADDRESS"))
        .arg(clap_arg!("stack_trace", "p", "stack", "trace stack on push/pop"))
        .arg(clap_arg!("test_mode", "t", "test", "test mode"))
        .arg(clap_arg!("banzai", "", "banzai", "skip unimplemented instructions, and keep up emulating what can be emulated"))
        .arg(clap_arg!("script", "x", "script", "launch an emulation script, see scripts_examples folder", "SCRIPT"))
        .arg(clap_arg!("trace", "T", "trace", "output trace to specified file", "TRACE_FILENAME"))
        .arg(clap_arg!("rax", "", "rax", "set rax register", "RAX"))
        .arg(clap_arg!("rbx", "", "rbx", "set rbx register", "RBX"))
        .arg(clap_arg!("rcx", "", "rcx", "set rcx register", "RCX"))
        .arg(clap_arg!("rdx", "", "rdx", "set rdx register", "RDX"))
        .arg(clap_arg!("rsp", "", "rsp", "set rsp register", "RSP"))
        .arg(clap_arg!("rbp", "", "rbp", "set rbp register", "RBP"))
        .arg(clap_arg!("rsi", "", "rsi", "set rsi register", "RSI"))
        .arg(clap_arg!("rdi", "", "rdi", "set rdi register", "RDI"))
        .arg(clap_arg!("r8", "", "r8", "set r8 register", "R8"))
        .arg(clap_arg!("r9", "", "r9", "set r9 register", "R9"))
        .arg(clap_arg!("r10", "", "r10", "set r10 register", "R10"))
        .arg(clap_arg!("r11", "", "r11", "set r11 register", "R11"))
        .arg(clap_arg!("r12", "", "r12", "set r12 register", "R12"))
        .arg(clap_arg!("r13", "", "r13", "set r13 register", "R13"))
        .arg(clap_arg!("r14", "", "r14", "set r14 register", "R14"))
        .arg(clap_arg!("r15", "", "r15", "set r15 register", "R15"))
        .arg(clap_arg!("rflags", "", "rflags", "set rflags register", "RFLAGS"))
        .arg(clap_arg!("mxcsr", "", "mxcsr", "set mxcsr register", "MXCSR"))
        .get_matches();

    if !matches.is_present("filename") {
        log::error!("the filename is mandatory, try -f <FILENAME> or --help");
    }

    let mut emu: libmwemu::emu::Emu;

    // 32 or 64 bit
    if matches.is_present("64bits") {
        emu = emu64();
        emu.cfg.is_64bits = true;
    } else {
        emu = emu32();
        emu.cfg.is_64bits = false;
    }

    // filename
    let filename = matches
        .value_of("filename")
        .expect("please enter the filename.")
        .to_string();
    emu.cfg.filename = filename.clone();

    // verbose
    emu.cfg.verbose = matches.occurrences_of("verbose") as u32;
    emu.set_verbose(emu.cfg.verbose);
    if emu.cfg.verbose == 0 {
        log::info!("use -vv to see the assembly code emulated, and -v to see the messages");
    }

    // tracing
    emu.cfg.trace_mem = matches.is_present("memory");
    emu.cfg.trace_regs = matches.is_present("registers");
    if matches.is_present("register") {
        emu.cfg.trace_reg = true;
        let regs: String = matches
            .value_of("register")
            .expect("select the register example: eax,ebx")
            .to_string();
        emu.cfg.reg_names = regs.split(',').map(|x| x.to_string()).collect();
    }
    if matches.is_present("string") {
        emu.cfg.trace_string = true;
        emu.cfg.string_addr = u64::from_str_radix(
            matches
                .value_of("string")
                .expect("select the address of the string")
                .trim_start_matches("0x"),
            16,
        )
        .expect("invalid address");
    }
    if matches.is_present("trace") {
        let trace_filename = matches
            .value_of("trace")
            .expect("specify the trace output file")
            .to_string();
        let mut trace_file =
            std::fs::File::create(&trace_filename).expect("Failed to create trace file");
        writeln!(
            trace_file,
            r#""Index","Address","Bytes","Disassembly","Registers","Memory","Comments""#
        )
        .expect("Failed to write trace file header");
        emu.cfg.trace_file = Some(trace_file);
    }

    // console
    if matches.is_present("console") {
        emu.cfg.console = true;
        emu.cfg.console_num = matches
                .value_of("console")
                .expect("select the number of moment to inspect").parse::<u64>()
        .expect("select a valid number to spawn console");
        emu.spawn_console_at(emu.cfg.console_num);
    }
    emu.cfg.loops = matches.is_present("loops");
    emu.cfg.nocolors = matches.is_present("nocolors");

    // inspect
    if matches.is_present("inspect") {
        emu.cfg.inspect = true;
        emu.cfg.inspect_seq = matches
            .value_of("inspect")
            .expect("select the address in the way 'dword ptr [eax + 0xa]'")
            .to_string();
    }

    // banzai
    if matches.is_present("banzai") {
        emu.cfg.skip_unimplemented = true;
    }

    // maps
    if matches.is_present("maps") {
        emu.set_maps_folder(matches.value_of("maps").expect("specify the maps folder"));
    } else {
        // if maps is not selected, by default ...
        if emu.cfg.is_64bits {
            emu.set_maps_folder("maps64/");
        } else {
            emu.set_maps_folder("maps32/");
        }
    }

    // code base address
    if matches.is_present("code_base_address") {
        emu.cfg.code_base_addr = u64::from_str_radix(
            matches
                .value_of("code_base_address")
                .expect("select the code base address -b")
                .trim_start_matches("0x"),
            16,
        )
        .expect("invalid address");
        if !matches.is_present("entry_point") {
            log::error!("if the code base is selected, you have to select the entry point ie -b 0x600000 -a 0x600000");
            std::process::exit(1);
        }
    }

    // stack address
    if matches.is_present("stack_address") {
        emu.cfg.stack_addr = u64::from_str_radix(
            matches
                .value_of("stack_address")
                .expect("select the stack address")
                .trim_start_matches("0x"),
            16,
        )
        .expect("invalid address");
    }

    // register values
    match_register_arg!(matches, emu, "rax");
    match_register_arg!(matches, emu, "rbx");
    match_register_arg!(matches, emu, "rcx");
    match_register_arg!(matches, emu, "rdx");
    match_register_arg!(matches, emu, "rsp");
    match_register_arg!(matches, emu, "rbp");
    match_register_arg!(matches, emu, "rsi");
    match_register_arg!(matches, emu, "rdi");
    match_register_arg!(matches, emu, "r8");
    match_register_arg!(matches, emu, "r9");
    match_register_arg!(matches, emu, "r10");
    match_register_arg!(matches, emu, "r11");
    match_register_arg!(matches, emu, "r12");
    match_register_arg!(matches, emu, "r13");
    match_register_arg!(matches, emu, "r14");
    match_register_arg!(matches, emu, "r15");
    if matches.is_present("rflags") {
        let value = u64::from_str_radix(
            matches
                .value_of("rflags")
                .expect("select the rflags register")
                .trim_start_matches("0x"),
            16,
        )
        .expect("invalid address");
        emu.flags.load(value as u32);
    }
    if matches.is_present("mxcsr") {
        let value = u64::from_str_radix(
            matches
                .value_of("mxcsr")
                .expect("select the mxcsr register")
                .trim_start_matches("0x"),
            16,
        )
        .expect("invalid address");
        emu.fpu.mxcsr = value as u32;
    }

    // init
    let clear_registers = false; // TODO: this needs to be more dynamic, like if we have a register set via args or not
    let clear_flags = false; // TODO: this needs to be more dynamic, like if we have a flag set via args or not
    emu.init(clear_registers, clear_flags);

    // endpoint
    if matches.is_present("endpoint") {
        //TODO: emu::endpoint::warning();
        emu.cfg.endpoint = true;
    }

    // console
    if matches.is_present("console_addr") {
        emu.cfg.console2 = true;
        emu.cfg.console_addr = u64::from_str_radix(
            matches
                .value_of("console_addr")
                .expect("select the address to spawn console with -C")
                .trim_start_matches("0x"),
            16,
        )
        .expect("invalid address");
        emu.spawn_console_at_addr(emu.cfg.console_addr);
    }

    // entry point
    if matches.is_present("entry_point") {
        emu.cfg.entry_point = u64::from_str_radix(
            matches
                .value_of("entry_point")
                .expect("select the entry point address -a")
                .trim_start_matches("0x"),
            16,
        )
        .expect("invalid address");
    }

    // exit position
    if matches.is_present("exit_position") {
        emu.cfg.exit_position = u64::from_str_radix(
            matches
                .value_of("exit_position")
                .expect("select the exit position address -e")
                .trim_start_matches("0x"),
            16,
        )
        .expect("invalid position");
    }

    // stack trace
    if matches.is_present("stack_trace") {
        emu.cfg.stack_trace = true;
    }

    // test mode
    if matches.is_present("test_mode") {
        emu.cfg.test_mode = true;
    }

    // load code
    emu.load_code(&filename);

    // script
    if matches.is_present("script") {
        emu.disable_ctrlc();
        let mut script = libmwemu::emu::script::Script::new();
        script.load(
            matches
                .value_of("script")
                .expect("select a script filename"),
        );
        script.run(&mut emu);
    } else {
        //emu.enable_ctrlc(); // TODO: make configurable with command line arg
        emu.run(None).unwrap();
    }
}
