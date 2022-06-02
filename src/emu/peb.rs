use crate::emu;
use crate::emu::structures::PEB;

pub fn init_peb32(emu:&mut emu::Emu) {
    let mut peb_map = emu.maps.create_map("peb");
    peb_map.set_base(0x7ffdf000); //TODO: use allocator
    peb_map.set_size(PEB::size() as u64);

    let ldr = 0x77647880; // ntdll_data for now
    let process_parameters = 0x2c1118;  // reserved map for now
    let alt_thunk_list_ptr = 0;
    let reserved7 = 0x773cd568;
    let alt_thunk_list_ptr_32 = 0;
    let post_process_init_routine = 0;
    let session_id = 0; 

    let peb = PEB::new(ldr, process_parameters, alt_thunk_list_ptr, reserved7, alt_thunk_list_ptr_32, post_process_init_routine, session_id);
    peb.save(&mut peb_map);
}



