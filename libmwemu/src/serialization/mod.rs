use std::collections::BTreeMap;
use std::convert::TryInto as _;
use std::fs::File;
use std::sync::atomic;
use std::sync::Arc;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use iced_x86::Instruction;
use serde::Deserialize;
use serde::Serialize;

use crate::banzai::Banzai;
use crate::breakpoint::Breakpoint;
use crate::colors::Colors;
use crate::config::Config;
use crate::eflags::Eflags;
use crate::emu::Emu;
use crate::flags::Flags;
use crate::fpu::FPU;
use crate::hooks::Hooks;
use crate::maps::Maps;
use crate::pe32::PE32;
use crate::pe64::PE64;
use crate::regs64::Regs64;
use crate::structures::MemoryOperation;

#[derive(Serialize, Deserialize)]
pub struct SerializableInstant {
    // Store as duration since UNIX_EPOCH
    timestamp: u64,
}

impl From<Instant> for SerializableInstant {
    fn from(instant: Instant) -> Self {
        // Convert Instant to duration since UNIX_EPOCH
        let duration = instant
            .duration_since(Instant::now())
            + SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap();
        
        SerializableInstant {
            timestamp: duration.as_secs(),
        }
    }
}

impl SerializableInstant {
    fn to_instant(&self) -> Instant {
        // Convert back to Instant
        let system_now = SystemTime::now();
        let instant_now = Instant::now();
        
        instant_now - system_now
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .saturating_sub(std::time::Duration::from_secs(self.timestamp))
    }
}

#[derive(Serialize, Deserialize)]
pub struct SerializableFPU {
    pub st: Vec<f64>,
    pub st_depth: u8,
    pub tag: u16,
    pub stat: u16,
    pub ctrl: u16,
    pub ip: u64,
    pub err_off: u32,
    pub err_sel: u32,
    pub code_segment: u16,
    pub data_segment: u16,
    pub operand_ptr: u64,
    pub reserved: Vec<u8>, // not a slice
    pub reserved2: Vec<u8>, // not a slice
    pub xmm: Vec<u128>, // not a slice
    pub top: i8,
    pub f_c0: bool, // overflow
    pub f_c1: bool, // underflow
    pub f_c2: bool, // div by zero
    pub f_c3: bool, // precission
    pub f_c4: bool, // stack fault
    pub mxcsr: u32,
    pub fpu_control_word: u16,
    pub opcode: u16,
}

impl From<FPU> for SerializableFPU {
    fn from(fpu: FPU) -> Self {
        SerializableFPU {
            st: fpu.st,
            st_depth: fpu.st_depth,
            tag: fpu.tag,
            stat: fpu.stat,
            ctrl: fpu.ctrl,
            ip: fpu.ip,
            err_off: fpu.err_off,
            err_sel: fpu.err_sel,
            code_segment: fpu.code_segment,
            data_segment: fpu.data_segment,
            operand_ptr: fpu.operand_ptr,
            reserved: fpu.reserved.to_vec(),
            reserved2: fpu.reserved2.to_vec(),
            xmm: fpu.xmm.to_vec(),
            top: fpu.top,
            f_c0: fpu.f_c0,
            f_c1: fpu.f_c1,
            f_c2: fpu.f_c2,
            f_c3: fpu.f_c3,
            f_c4: fpu.f_c4,
            mxcsr: fpu.mxcsr,
            fpu_control_word: fpu.fpu_control_word,
            opcode: fpu.opcode,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct SerializablePE32 {
    pub raw: Vec<u8>,
}

impl From<PE32> for SerializablePE32 {
    fn from(pe32: PE32) -> Self {
        SerializablePE32 {
            raw: pe32.raw,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct SerializablePE64 {
    pub raw: Vec<u8>,
}

impl From<PE64> for SerializablePE64 {
    fn from(pe64: PE64) -> Self {
        SerializablePE64 {
            raw: pe64.raw,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct SerializableEmu {
    pub regs: Regs64,
    pub pre_op_regs: Regs64,
    pub post_op_regs: Regs64,
    pub flags: Flags,
    pub pre_op_flags: Flags,
    pub post_op_flags: Flags,
    pub eflags: Eflags,
    pub fpu: SerializableFPU,
    pub maps: Maps,
    //pub hooks: Hooks, // not possible
    pub exp: u64,
    pub break_on_alert: bool,
    pub bp: Breakpoint,
    pub seh: u64,
    pub veh: u64,
    pub feh: u64,
    pub eh_ctx: u32,
    pub cfg: Config,
    pub colors: Colors,
    pub pos: u64,
    pub force_break: bool,
    pub force_reload: bool,
    pub tls_callbacks: Vec<u64>,
    pub tls32: Vec<u32>,
    pub tls64: Vec<u64>,
    pub fls: Vec<u32>,
    pub out: String,
    pub instruction: Option<Instruction>,
    pub decoder_position: usize,
    pub memory_operations: Vec<MemoryOperation>,
    pub main_thread_cont: u64,
    pub gateway_return: u64,
    pub is_running: u32,
    pub break_on_next_cmp: bool,
    pub break_on_next_return: bool,
    pub filename: String,
    pub enabled_ctrlc: bool,
    pub run_until_ret: bool,
    pub running_script: bool,
    pub banzai: Banzai,
    pub mnemonic: String,
    pub dbg: bool,
    pub linux: bool,
    pub fs: BTreeMap<u64, u64>,
    pub now: SerializableInstant,
    pub skip_apicall: bool,
    pub its_apicall: Option<u64>,
    pub last_instruction_size: usize,
    pub pe64: Option<SerializablePE64>,
    pub pe32: Option<SerializablePE32>,
    pub rep: Option<u64>,
    pub tick: usize,
}

impl From<SerializableFPU> for FPU {
    fn from(serialized: SerializableFPU) -> Self {
        FPU {
            st: serialized.st,
            st_depth: serialized.st_depth,
            tag: serialized.tag,
            stat: serialized.stat,
            ctrl: serialized.ctrl,
            ip: serialized.ip,
            err_off: serialized.err_off,
            err_sel: serialized.err_sel,
            code_segment: serialized.code_segment,
            data_segment: serialized.data_segment,
            operand_ptr: serialized.operand_ptr,
            reserved: serialized.reserved.try_into().unwrap(),
            reserved2: serialized.reserved2.try_into().unwrap(),
            xmm: serialized.xmm.try_into().unwrap(),
            top: serialized.top,
            f_c0: serialized.f_c0,
            f_c1: serialized.f_c1,
            f_c2: serialized.f_c2,
            f_c3: serialized.f_c3,
            f_c4: serialized.f_c4,
            mxcsr: serialized.mxcsr,
            fpu_control_word: serialized.fpu_control_word,
            opcode: serialized.opcode,
        }
    }
}

impl From<SerializablePE32> for PE32 {
    fn from(serialized: SerializablePE32) -> Self {
        PE32::load_from_raw(&serialized.raw)
    }
}

impl From<SerializablePE64> for PE64 {
    fn from(serialized: SerializablePE64) -> Self {
        PE64::load_from_raw(&serialized.raw)
    }
}

impl From<Emu> for SerializableEmu {
    fn from(emu: Emu) -> Self {
        SerializableEmu {
            regs: emu.regs,
                pre_op_regs: emu.pre_op_regs,
                post_op_regs: emu.post_op_regs,
                flags: emu.flags,
                pre_op_flags: emu.pre_op_flags,
                post_op_flags: emu.post_op_flags,
                eflags: emu.eflags,
                fpu: emu.fpu.into(),
                maps: emu.maps,
                exp: emu.exp,
                break_on_alert: emu.break_on_alert,
                bp: emu.bp,
                seh: emu.seh,
                veh: emu.veh,
                feh: emu.feh,
                eh_ctx: emu.eh_ctx,
                cfg: emu.cfg,
                colors: emu.colors,
                pos: emu.pos,
                force_break: emu.force_break,
                force_reload: emu.force_reload,
                tls_callbacks: emu.tls_callbacks,
                tls32: emu.tls32,
                tls64: emu.tls64,
                fls: emu.fls,
                out: emu.out,
                instruction: emu.instruction,
                decoder_position: emu.decoder_position,
                memory_operations: emu.memory_operations,
                main_thread_cont: emu.main_thread_cont,
                gateway_return: emu.gateway_return,
                is_running: emu.is_running.load(std::sync::atomic::Ordering::Relaxed),
                break_on_next_cmp: emu.break_on_next_cmp,
                break_on_next_return: emu.break_on_next_return,
                filename: emu.filename,
                enabled_ctrlc: emu.enabled_ctrlc,
                run_until_ret: emu.run_until_ret,
                running_script: emu.running_script,
                banzai: emu.banzai,
                mnemonic: emu.mnemonic,
                dbg: emu.dbg,
                linux: emu.linux,
                fs: emu.fs,
                now: SerializableInstant::from(emu.now),
                skip_apicall: emu.skip_apicall,
                its_apicall: emu.its_apicall,
                last_instruction_size: emu.last_instruction_size,
                pe64: emu.pe64.map(|x| x.into()),
                pe32: emu.pe32.map(|x| x.into()),
                rep: emu.rep,
                tick: emu.tick,
        }
    }
}   

impl From<SerializableEmu> for Emu {
    fn from(serialized: SerializableEmu) -> Self {
        let trace_file = if let Some(trace_filename) = &serialized.cfg.trace_filename {
            let file = File::open(trace_filename.clone()).unwrap();
            Some(file)
        } else {
            None
        };

        Emu {
            regs: serialized.regs,
            pre_op_regs: serialized.pre_op_regs,
            post_op_regs: serialized.post_op_regs,
            flags: serialized.flags,
            pre_op_flags: serialized.pre_op_flags,
            post_op_flags: serialized.post_op_flags,
            eflags: serialized.eflags,
            fpu: serialized.fpu.into(),
            maps: serialized.maps,
            hooks: Hooks::default(), // not possible
            exp: serialized.exp,
            break_on_alert: serialized.break_on_alert,
            bp: serialized.bp,
            seh: serialized.seh,
            veh: serialized.veh,
            feh: serialized.feh,
            eh_ctx: serialized.eh_ctx,
            cfg: serialized.cfg.clone(),
            colors: serialized.colors,
            pos: serialized.pos,
            force_break: serialized.force_break,
            force_reload: serialized.force_reload,
            tls_callbacks: serialized.tls_callbacks,
            tls32: serialized.tls32,
            tls64: serialized.tls64,
            fls: serialized.fls,
            out: serialized.out,
            instruction: serialized.instruction,
            decoder_position: serialized.decoder_position,
            memory_operations: serialized.memory_operations,
            main_thread_cont: serialized.main_thread_cont,
            gateway_return: serialized.gateway_return,
            is_running: Arc::new(atomic::AtomicU32::new(serialized.is_running)),
            break_on_next_cmp: serialized.break_on_next_cmp,
            break_on_next_return: serialized.break_on_next_return,
            filename: serialized.filename,
            enabled_ctrlc: serialized.enabled_ctrlc,
            run_until_ret: serialized.run_until_ret,
            running_script: serialized.running_script,
            banzai: serialized.banzai,
            mnemonic: serialized.mnemonic,
            dbg: serialized.dbg,
            linux: serialized.linux,
            fs: serialized.fs,
            now: serialized.now.to_instant(),
            skip_apicall: serialized.skip_apicall,
            its_apicall: serialized.its_apicall,
            last_instruction_size: serialized.last_instruction_size,
            pe64: serialized.pe64.map(|x| x.into()),
            pe32: serialized.pe32.map(|x| x.into()),
            rep: serialized.rep,
            tick: serialized.tick,
            trace_file: trace_file,
        }
    }
}