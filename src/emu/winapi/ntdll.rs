use crate::emu;
use crate::emu::winapi::helper;
use crate::emu::context32::Context32;
use crate::emu::structures;
use crate::emu::constants;


pub fn gateway(addr:u32, emu:&mut emu::Emu) {
    match addr {
        0x775b52d8 => NtAllocateVirtualMemory(emu),
        0x775b5a18 => NtGetContextThread(emu),
        0x7757f774 => RtlVectoredExceptionHandler(emu),
        0x775d22b8 => LdrLoadDll(emu),
        0x775b6258 => NtQueryVirtualMemory(emu),
        0x775d531f => stricmp(emu),
        0x7759f611 => RtlExitUserThread(emu),
        _ => panic!("calling unimplemented ntdll API 0x{:x}", addr),
    }
}


fn NtAllocateVirtualMemory(emu:&mut emu::Emu) {
    /*
        __kernel_entry NTSYSCALLAPI NTSTATUS NtAllocateVirtualMemory(
            [in]      HANDLE    ProcessHandle,
            [in, out] PVOID     *BaseAddress,
            [in]      ULONG_PTR ZeroBits,
            [in, out] PSIZE_T   RegionSize,
            [in]      ULONG     AllocationType,
            [in]      ULONG     Protect
            );
    */

    let addr_ptr = emu.maps.read_dword(emu.regs.esp+4).expect("bad NtAllocateVirtualMemory address pointer parameter");
    let size_ptr = emu.maps.read_dword(emu.regs.esp+12).expect("bad NtAllocateVirtualMemory size pointer parameter");
    let addr = emu.maps.read_dword(addr_ptr).expect("bad NtAllocateVirtualMemory address parameter");
    let size = emu.maps.read_dword(size_ptr).expect("bad NtAllocateVirtualMemory size parameter");
    let do_alloc:bool;
    let alloc_addr:u32;

    if addr == 0 {
        do_alloc = true;
    } else {
        do_alloc = emu.maps.is_mapped(addr);
    }

    if size == 0 {
        panic!("NtAllocateVirtualMemory mapping zero bytes.")
    }

    if do_alloc {
        alloc_addr = match emu.maps.alloc(size) {
            Some(a) => a,
            None => panic!("/!\\ out of memory   cannot allocate forntdll!NtAllocateVirtualMemory "),
        };
    } else { 
        alloc_addr = addr;
    }

    println!("{}** {} ntdll!NtAllocateVirtualMemory  addr: 0x{:x} sz: {} alloc: 0x{:x} {}", emu.colors.light_red, emu.pos, addr, size, alloc_addr, emu.colors.nc);

    let alloc = emu.maps.create_map(format!("valloc_{:x}", alloc_addr).as_str());
    alloc.set_base(alloc_addr);
    alloc.set_size(size);
    //alloc.set_bottom(alloc_addr + size);

    if !emu.maps.write_dword(addr_ptr, alloc_addr) {
        panic!("NtAllocateVirtualMemory: cannot write on address pointer");
    }

    emu.regs.eax = emu::constants::STATUS_SUCCESS;

    for _ in 0..6 {
        emu.stack_pop(false);
    }
}



fn stricmp(emu:&mut emu::Emu) {
    let str1ptr = emu.maps.read_dword(emu.regs.esp).expect("ntdll!stricmp: error reading string1");
    let str2ptr = emu.maps.read_dword(emu.regs.esp+4).expect("ntdll!stricmp: error reading string2");
    let str1 = emu.maps.read_string(str1ptr);
    let str2 = emu.maps.read_string(str2ptr);

    println!("{}** {} ntdll!stricmp  '{}'=='{}'? {}", emu.colors.light_red, emu.pos, str1, str2, emu.colors.nc);

    if str1 == str2 {
        emu.regs.eax = 0;
    } else {
        emu.regs.eax = 1;
    }

    for _ in 0..2 {
        emu.stack_pop(false);
    }
}

fn NtQueryVirtualMemory(emu:&mut emu::Emu) {
    let handle = emu.maps.read_dword(emu.regs.esp).expect("ntdll!NtQueryVirtualMemory: error reading handle");
    let addr = emu.maps.read_dword(emu.regs.esp+4).expect("ntdll!NtQueryVirtualMemory: error reading address");

    println!("{}** {} ntdll!NtQueryVirtualMemory addr: 0x{:x} {}", emu.colors.light_red, emu.pos, addr, emu.colors.nc);

    if handle != 0xffffffff {
        println!("\tusing handle of remote process {:x}", handle);

        if !helper::handler_exist(handle) {
            println!("\nhandler doesnt exist.");
        }
    }

    let out_meminfo_ptr = emu.maps.read_dword(emu.regs.esp+12).expect("ntdll_NtQueryVirtualMemory: error reading out pointer to meminfo");

    if !emu.maps.is_mapped(addr) {
        println!("/!\\ ntdll!NtQueryVirtualMemory: querying non maped addr: 0x{:x}", addr);
        for _ in 0..6 {
            emu.stack_pop(false);
        }
        emu.regs.eax = emu::constants::STATUS_INVALID_PARAMETER;
    }

    let base = emu.maps.get_addr_base(addr).unwrap_or(0);

    let mut mem_info = structures::MemoryBasicInformation::load(out_meminfo_ptr, &emu.maps);
    mem_info.base_address = base; //addr & 0xfff;
    mem_info.allocation_base = base; //  addr & 0xfff;
    mem_info.allocation_protect = constants::PAGE_EXECUTE | constants::PAGE_READWRITE;
    mem_info.state = constants::MEM_COMMIT;
    mem_info.typ = constants::MEM_PRIVATE;
    mem_info.save(out_meminfo_ptr, &mut emu.maps);
   
    for _ in 0..6 {
        emu.stack_pop(false);
    }

    emu.regs.eax = constants::STATUS_SUCCESS;
}


fn LdrLoadDll(emu:&mut emu::Emu) {
    let libaddr_ptr = emu.maps.read_dword(emu.regs.esp+12).expect("LdrLoadDll: error reading lib ptr");
    let libname_ptr = emu.maps.read_dword(emu.regs.esp+20).expect("LdrLoadDll: error reading lib param");

    let libname = emu.maps.read_wide_string(libname_ptr);
    println!("{}** {} ntdll!LdrLoadDll   lib: {} {}", emu.colors.light_red, emu.pos, libname, emu.colors.nc);

    
    if libname == "user32.dll" {
        let user32 = emu.maps.create_map("user32");
        user32.set_base(0x773b0000);
        user32.load("maps32/user32.bin");
        let user32_text = emu.maps.create_map("user32_text");
        user32_text.set_base(0x773b1000);
        user32_text.load("maps32/user32_text.bin");

        if !emu.maps.write_dword(libaddr_ptr, 0x773b0000) {
            panic!("ntdll_LdrLoadDll: cannot write in addr param");
        }
    }


    for _ in 0..4 {
        emu.stack_pop(false);
    }
    emu.regs.eax = emu::constants::STATUS_SUCCESS;
}

fn RtlVectoredExceptionHandler(emu:&mut emu::Emu) {
    let p1 = emu.maps.read_dword(emu.regs.esp).expect("ntdll_RtlVectoredExceptionHandler: error reading p1");
    let fptr = emu.maps.read_dword(emu.regs.esp+4).expect("ntdll_RtlVectoredExceptionHandler: error reading fptr");

    println!("{}** {} ntdll!RtlVectoredExceptionHandler  {} callback: 0x{:x} {}", emu.colors.light_red, emu.pos, p1, fptr, emu.colors.nc);

    emu.veh = fptr;

    emu.regs.eax = 0x2c2878;
    emu.stack_pop(false);
    emu.stack_pop(false);
}

fn NtGetContextThread(emu:&mut emu::Emu) {
    let handle = emu.maps.read_dword(emu.regs.esp).expect("ntdll_NtGetContextThread: error reading stack");
    let ctx_ptr = emu.maps.read_dword(emu.regs.esp+4).expect("ntdll_NtGetContextThread: error reading context pointer");
    let ctx_ptr2 = emu.maps.read_dword(ctx_ptr).expect("ntdll_NtGetContextThread: error reading context ptr");
    
    println!("{}** {} ntdll_NtGetContextThread   ctx  {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    /*
    if !emu.maps.write_dword(ctx+4, 0) {
        panic!("ntdll_NtGetContextThread: error writting Dr0 in context");
    }
    if !emu.maps.write_dword(ctx+8, 0) {
        panic!("ntdll_NtGetContextThread: error writting Dr1 in context");
    }
    if !emu.maps.write_dword(ctx+12, 0) {
        panic!("ntdll_NtGetContextThread: error writting Dr2 in context");
    }
    if !emu.maps.write_dword(ctx+16, 0) {
        panic!("ntdll_NtGetContextThread: error writting Dr3 in context");
    }
    if !emu.maps.write_dword(ctx+16, 0) {
        panic!("ntdll_NtGetContextThread: error writting Dr6 in context");
    }
    if !emu.maps.write_dword(ctx+16, 0) {
        panic!("ntdll_NtGetContextThread: error writting Dr7 in context");
    }*/

    let ctx = Context32::new(&emu.regs);
    ctx.save(ctx_ptr2, &mut emu.maps);

    emu.regs.eax = 0;
    emu.stack_pop(false);
    emu.stack_pop(false);

}

fn RtlExitUserThread(emu:&mut emu::Emu) {
    println!("{}** {} ntdll!RtlExitUserThread   {}", emu.colors.light_red, emu.pos, emu.colors.nc);   
    std::process::exit(1);
}

