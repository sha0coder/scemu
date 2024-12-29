use std::sync::atomic;
use std::sync::Arc;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;

use crate::emu::Emu;
use crate::hooks::Hooks;

#[derive(Serialize, Deserialize)]
struct SerializableInstant {
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

impl Serialize for Emu {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serde_json::Map::new();
        value.insert("regs".to_string(), serde_json::to_value(&self.regs).unwrap());
        value.insert("pre_op_regs".to_string(), serde_json::to_value(&self.pre_op_regs).unwrap());
        value.insert("post_op_regs".to_string(), serde_json::to_value(&self.post_op_regs).unwrap());
        value.insert("flags".to_string(), serde_json::to_value(&self.flags).unwrap());
        value.insert("pre_op_flags".to_string(), serde_json::to_value(&self.pre_op_flags).unwrap());
        value.insert("post_op_flags".to_string(), serde_json::to_value(&self.post_op_flags).unwrap());
        value.insert("eflags".to_string(), serde_json::to_value(&self.eflags).unwrap());
        value.insert("fpu".to_string(), serde_json::to_value(&self.fpu).unwrap());
        value.insert("maps".to_string(), serde_json::to_value(&self.maps).unwrap());
        //value.insert("hooks".to_string(), serde_json::to_value(&self.hooks).unwrap()); // not possible
        value.insert("exp".to_string(), serde_json::to_value(&self.exp).unwrap());
        value.insert("break_on_alert".to_string(), serde_json::to_value(&self.break_on_alert).unwrap());
        value.insert("bp".to_string(), serde_json::to_value(&self.bp).unwrap());
        value.insert("seh".to_string(), serde_json::to_value(&self.seh).unwrap());
        value.insert("veh".to_string(), serde_json::to_value(&self.veh).unwrap());
        value.insert("feh".to_string(), serde_json::to_value(&self.feh).unwrap());
        value.insert("eh_ctx".to_string(), serde_json::to_value(&self.eh_ctx).unwrap());
        value.insert("cfg".to_string(), serde_json::to_value(&self.cfg).unwrap());
        value.insert("colors".to_string(), serde_json::to_value(&self.colors).unwrap());
        value.insert("pos".to_string(), serde_json::to_value(&self.pos).unwrap());
        value.insert("force_break".to_string(), serde_json::to_value(&self.force_break).unwrap());
        value.insert("force_reload".to_string(), serde_json::to_value(&self.force_reload).unwrap());
        value.insert("tls_callbacks".to_string(), serde_json::to_value(&self.tls_callbacks).unwrap());
        value.insert("tls32".to_string(), serde_json::to_value(&self.tls32).unwrap());
        value.insert("tls64".to_string(), serde_json::to_value(&self.tls64).unwrap());
        value.insert("fls".to_string(), serde_json::to_value(&self.fls).unwrap());
        value.insert("out".to_string(), serde_json::to_value(&self.out).unwrap());
        value.insert("instruction".to_string(), serde_json::to_value(&self.instruction).unwrap());
        value.insert("decoder_position".to_string(), serde_json::to_value(&self.decoder_position).unwrap());
        value.insert("memory_operations".to_string(), serde_json::to_value(&self.memory_operations).unwrap());
        value.insert("main_thread_cont".to_string(), serde_json::to_value(&self.main_thread_cont).unwrap());
        value.insert("gateway_return".to_string(), serde_json::to_value(&self.gateway_return).unwrap());
        value.insert("is_running".to_string(), serde_json::to_value(&*self.is_running).unwrap());
        value.insert("break_on_next_cmp".to_string(), serde_json::to_value(&self.break_on_next_cmp).unwrap());
        value.insert("break_on_next_return".to_string(), serde_json::to_value(&self.break_on_next_return).unwrap());
        value.insert("filename".to_string(), serde_json::to_value(&self.filename).unwrap());
        value.insert("enabled_ctrlc".to_string(), serde_json::to_value(&self.enabled_ctrlc).unwrap());
        value.insert("run_until_ret".to_string(), serde_json::to_value(&self.run_until_ret).unwrap());
        value.insert("running_script".to_string(), serde_json::to_value(&self.running_script).unwrap());
        value.insert("banzai".to_string(), serde_json::to_value(&self.banzai).unwrap());
        value.insert("mnemonic".to_string(), serde_json::to_value(&self.mnemonic).unwrap());
        value.insert("dbg".to_string(), serde_json::to_value(&self.dbg).unwrap());
        value.insert("linux".to_string(), serde_json::to_value(&self.linux).unwrap());
        value.insert("fs".to_string(), serde_json::to_value(&self.fs).unwrap());
        value.insert("now".to_string(), serde_json::to_value(&SerializableInstant::from(self.now)).unwrap());
        value.insert("skip_apicall".to_string(), serde_json::to_value(&self.skip_apicall).unwrap());
        value.insert("its_apicall".to_string(), serde_json::to_value(&self.its_apicall).unwrap());
        value.insert("last_instruction_size".to_string(), serde_json::to_value(&self.last_instruction_size).unwrap());
        value.insert("pe64".to_string(), serde_json::to_value(&self.pe64).unwrap());
        value.insert("pe32".to_string(), serde_json::to_value(&self.pe32).unwrap());
        value.insert("rep".to_string(), serde_json::to_value(&self.rep).unwrap());
        value.insert("tick".to_string(), serde_json::to_value(&self.tick).unwrap());
        serializer.serialize_str(&serde_json::to_string(&value).unwrap())
    }
}

impl<'de> Deserialize<'de> for Emu {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        
        // First deserialize the string containing the JSON
        let json_str = String::deserialize(deserializer)?;
        
        // Parse the JSON string into a Map
        let value: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&json_str)
            .map_err(D::Error::custom)?;

        let is_running = serde_json::from_value(value.get("is_running").unwrap().clone()).unwrap();

        let now = serde_json::from_value(value.get("now").unwrap().clone()).unwrap();
        let now = SerializableInstant::from(now).to_instant();

        Ok(Emu {
            regs: serde_json::from_value(value.get("regs").unwrap().clone()).unwrap(),
            pre_op_regs: serde_json::from_value(value.get("pre_op_regs").unwrap().clone()).unwrap(),
            post_op_regs: serde_json::from_value(value.get("post_op_regs").unwrap().clone()).unwrap(),
            flags: serde_json::from_value(value.get("flags").unwrap().clone()).unwrap(),
            pre_op_flags: serde_json::from_value(value.get("pre_op_flags").unwrap().clone()).unwrap(),
            post_op_flags: serde_json::from_value(value.get("post_op_flags").unwrap().clone()).unwrap(),
            eflags: serde_json::from_value(value.get("eflags").unwrap().clone()).unwrap(),
            fpu: serde_json::from_value(value.get("fpu").unwrap().clone()).unwrap(),
            maps: serde_json::from_value(value.get("maps").unwrap().clone()).unwrap(),
            hooks: Hooks::new(),
            exp: serde_json::from_value(value.get("exp").unwrap().clone()).unwrap(),
            break_on_alert: serde_json::from_value(value.get("break_on_alert").unwrap().clone()).unwrap(),
            bp: serde_json::from_value(value.get("bp").unwrap().clone()).unwrap(),
            seh: serde_json::from_value(value.get("seh").unwrap().clone()).unwrap(),
            veh: serde_json::from_value(value.get("veh").unwrap().clone()).unwrap(),
            feh: serde_json::from_value(value.get("feh").unwrap().clone()).unwrap(),
            eh_ctx: serde_json::from_value(value.get("eh_ctx").unwrap().clone()).unwrap(),
            cfg: serde_json::from_value(value.get("cfg").unwrap().clone()).unwrap(),
            colors: serde_json::from_value(value.get("colors").unwrap().clone()).unwrap(),
            pos: serde_json::from_value(value.get("pos").unwrap().clone()).unwrap(),
            force_break: serde_json::from_value(value.get("force_break").unwrap().clone()).unwrap(),
            force_reload: serde_json::from_value(value.get("force_reload").unwrap().clone()).unwrap(),
            tls_callbacks: serde_json::from_value(value.get("tls_callbacks").unwrap().clone()).unwrap(),
            tls32: serde_json::from_value(value.get("tls32").unwrap().clone()).unwrap(),
            tls64: serde_json::from_value(value.get("tls64").unwrap().clone()).unwrap(),
            fls: serde_json::from_value(value.get("fls").unwrap().clone()).unwrap(),
            out: serde_json::from_value(value.get("out").unwrap().clone()).unwrap(),
            instruction: serde_json::from_value(value.get("instruction").unwrap().clone()).unwrap(),
            decoder_position: serde_json::from_value(value.get("decoder_position").unwrap().clone()).unwrap(),
            memory_operations: serde_json::from_value(value.get("memory_operations").unwrap().clone()).unwrap(),
            main_thread_cont: serde_json::from_value(value.get("main_thread_cont").unwrap().clone()).unwrap(),
            gateway_return: serde_json::from_value(value.get("gateway_return").unwrap().clone()).unwrap(),
            is_running: Arc::new(atomic::AtomicU32::new(is_running)),
            break_on_next_cmp: serde_json::from_value(value.get("break_on_next_cmp").unwrap().clone()).unwrap(),
            break_on_next_return: serde_json::from_value(value.get("break_on_next_return").unwrap().clone()).unwrap(),
            filename: serde_json::from_value(value.get("filename").unwrap().clone()).unwrap(),
            enabled_ctrlc: serde_json::from_value(value.get("enabled_ctrlc").unwrap().clone()).unwrap(),
            run_until_ret: serde_json::from_value(value.get("run_until_ret").unwrap().clone()).unwrap(),
            running_script: serde_json::from_value(value.get("running_script").unwrap().clone()).unwrap(),
            banzai: serde_json::from_value(value.get("banzai").unwrap().clone()).unwrap(),
            mnemonic: serde_json::from_value(value.get("mnemonic").unwrap().clone()).unwrap(),
            dbg: serde_json::from_value(value.get("dbg").unwrap().clone()).unwrap(),
            linux: serde_json::from_value(value.get("linux").unwrap().clone()).unwrap(),
            fs: serde_json::from_value(value.get("fs").unwrap().clone()).unwrap(),
            now: now,
            skip_apicall: serde_json::from_value(value.get("skip_apicall").unwrap().clone()).unwrap(),
            its_apicall: serde_json::from_value(value.get("its_apicall").unwrap().clone()).unwrap(),
            last_instruction_size: serde_json::from_value(value.get("last_instruction_size").unwrap().clone()).unwrap(),
            pe64: serde_json::from_value(value.get("pe64").unwrap().clone()).unwrap(),
            pe32: serde_json::from_value(value.get("pe32").unwrap().clone()).unwrap(),
            rep: serde_json::from_value(value.get("rep").unwrap().clone()).unwrap(),
            tick: serde_json::from_value(value.get("tick").unwrap().clone()).unwrap(),
            trace_file: None,
        })
    }
}