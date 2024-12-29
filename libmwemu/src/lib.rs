#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_must_use)]
#![allow(clippy::assertions_on_constants)]

pub mod banzai;
pub mod breakpoint;
pub mod colors;
pub mod config;
pub mod console;
pub mod constants;
pub mod context32;
pub mod context64;
pub mod eflags;
pub mod elf32;
pub mod elf64;
pub mod emu;
//pub mod endpoint;
pub mod engine;
pub mod err;
pub mod exception;
pub mod flags;
pub mod fpu;
pub mod hooks;
pub mod inline;
#[macro_use]
pub mod macros;
pub mod maps;
pub mod ntapi32;
pub mod pe32;
pub mod pe64;
pub mod peb32;
pub mod peb64;
pub mod regs64;
pub mod script;
pub mod structures;
pub mod syscall32;
pub mod syscall64;
pub mod winapi32;
pub mod winapi64;
pub mod serialization;

#[cfg(test)]
mod tests;

use config::Config;
use emu::Emu;

pub fn emu64() -> Emu {
    let mut emu = Emu::new();
    let mut cfg = Config::new();
    cfg.is_64bits = true;
    emu.set_config(cfg);
    emu.disable_ctrlc();

    emu
}

pub fn emu32() -> Emu {
    let mut emu = Emu::new();
    let mut cfg = Config::new();
    cfg.is_64bits = false;
    emu.set_config(cfg);
    emu.disable_ctrlc();

    emu
}
