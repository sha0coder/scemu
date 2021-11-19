use crate::emu32;

pub fn gateway(addr:u32, emu:&mut emu32::Emu32) {
    match addr {
        0x775b52d8 => NtAllocateVirtualMemory(emu),
        0x775b5a18 => NtGetContextThread(emu),
        0x7757f774 => RtlVectoredExceptionHandler(emu),
        0x775d22b8 => LdrLoadDll(emu),
        0x775b6258 => NtQueryVirtualMemory(emu),
        0x775d531f => stricmp(emu),
        _ => panic!("calling unknown ntdll API 0x{:x}", addr),
    }
}


fn NtAllocateVirtualMemory(emu:&mut emu32::Emu32) {
    let colors = emu32::colors::Colors::new();
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

    match emu.maps.get_addr_name(addr) {
        Some(name) => panic!("address already mapped: {}", name),
        None => println!("creating map on 0x{:x}", addr),
    }

    if size <= 0 {
        panic!("NtAllocateVirtualMemory mapping zero bytes.")
    }

    println!("{}** NtAllocateVirtualMemory  0x003e0000 {}",colors.light_red, colors.nc);

    //TODO: modify this, its allowing just one allocation
    let alloc = emu.maps.create_map("alloc");
    let alloc_addr = 0x003e0000;
    alloc.set_base(alloc_addr);
    alloc.set_bottom(alloc_addr + size);

    if !emu.maps.write_dword(addr_ptr, alloc_addr) {
        panic!("NtAllocateVirtualMemory: cannot write on address pointer");
    }

    emu.regs.eax = emu32::constants::STATUS_SUCCESS;

    for _ in 0..6 {
        emu.stack_pop(false);
    }
}



fn stricmp(emu:&mut emu32::Emu32) {
    let str1ptr = emu.maps.read_dword(emu.regs.esp).expect("ntdll_stricmp: error reading string1");
    let str2ptr = emu.maps.read_dword(emu.regs.esp+4).expect("ntdll_stricmp: error reading string2");
    let str1 = emu.maps.read_string(str1ptr);
    let str2 = emu.maps.read_string(str2ptr);
    let colors = emu32::colors::Colors::new();
    println!("{}** ntdll_stricmp  '{}'=='{}'? {}", colors.light_red, str1, str2, colors.nc);

    if str1 == str2 {
        emu.regs.eax = 0;
    } else {
        emu.regs.eax = 1;
    }

    for _ in 0..2 {
        emu.stack_pop(false);
    }
}

fn NtQueryVirtualMemory(emu:&mut emu32::Emu32) {
    let handle = emu.maps.read_dword(emu.regs.esp).expect("ntdll_NtQueryVirtualMemory: error reading handle");
    let addr = emu.maps.read_dword(emu.regs.esp+4).expect("ntdll_NtQueryVirtualMemory: error reading address");

    if handle != 0xffffffff {
        panic!("ntdll_NtQueryVirtualMemory: using handle of remote process {:x}", handle);
    }

    let out_meminfo_ptr = emu.maps.read_dword(emu.regs.esp+12).expect("ntdll_NtQueryVirtualMemory: error reading out pointer to meminfo");

    if !emu.maps.is_mapped(addr) {
        println!("/!\\ ntdll_NtQueryVirtualMemory: querying non maped addr: 0x{:x}", addr);
        for _ in 0..6 {
            emu.stack_pop(false);
        }
        emu.regs.eax = emu32::constants::STATUS_INVALID_PARAMETER;
    }

    /*
    __kernel_entry NTSYSCALLAPI NTSTATUS NtQueryVirtualMemory(
        [in]            HANDLE                   ProcessHandle,
        [in, optional]  PVOID                    BaseAddress,
        [in]            MEMORY_INFORMATION_CLASS MemoryInformationClass,
        [out]           PVOID                    MemoryInformation,
        [in]            SIZE_T                   MemoryInformationLength,
        [out, optional] PSIZE_T                  ReturnLength
    );
    */

    let colors = emu32::colors::Colors::new();
    println!("{}** ntdll_NtQueryVirtualMemory {}", colors.light_red, colors.nc);

    if !emu.maps.write_spaced_bytes(out_meminfo_ptr, "00 00 01 00 00 00 01 00 04 00 00 00 00 00 01 00 00 10 00 00 04 00 00 00 00 00 04 00 00 00 00 00 00 00 00 00".to_string()) {
        panic!("ntdll_NtQueryVirtualMemory: cannot write in out ptr 0x{:x} the meminfo struct", out_meminfo_ptr);
    }

    for _ in 0..6 {
        emu.stack_pop(false);
    }

    emu.regs.eax = emu32::constants::STATUS_SUCCESS;
}


fn LdrLoadDll(emu:&mut emu32::Emu32) {
    let libaddr_ptr = emu.maps.read_dword(emu.regs.esp+12).expect("LdrLoadDll: error reading lib ptr");
    let libname_ptr = emu.maps.read_dword(emu.regs.esp+20).expect("LdrLoadDll: error reading lib param");

    let colors = emu32::colors::Colors::new();
    let libname = emu.maps.read_wide_string(libname_ptr);
    println!("{}** ntdll_LdrLoadDll   lib:{} {}",colors.light_red, libname, colors.nc);

    
    if libname == "user32.dll" {
        let user32 = emu.maps.create_map("user32");
        user32.set_base(0x773b0000);
        user32.load("maps/user32.bin");
        let user32_text = emu.maps.create_map("user32_text");
        user32_text.set_base(0x773b1000);
        user32_text.load("maps/user32_text.bin");

        if !emu.maps.write_dword(libaddr_ptr, 0x773b0000) {
            panic!("ntdll_LdrLoadDll: cannot write in addr param");
        }
    }


    for _ in 0..4 {
        emu.stack_pop(false);
    }
    emu.regs.eax = emu32::constants::STATUS_SUCCESS;
}

fn RtlVectoredExceptionHandler(emu:&mut emu32::Emu32) {
    let p1 = emu.maps.read_dword(emu.regs.esp).expect("ntdll_RtlVectoredExceptionHandler: error reading p1");
    let fptr = emu.maps.read_dword(emu.regs.esp+4).expect("ntdll_RtlVectoredExceptionHandler: error reading fptr");

    let colors = emu32::colors::Colors::new();
    println!("{}** ntdll_RtlVectoredExceptionHandler  {} callback:0x{:x} {}", colors.light_red, p1, fptr, colors.nc);

    emu.veh = fptr;

    emu.regs.eax = 0x2c2878;
    emu.stack_pop(false);
    emu.stack_pop(false);
}

fn NtGetContextThread(emu:&mut emu32::Emu32) {
    let handle = emu.maps.read_dword(emu.regs.esp).expect("ntdll_NtGetContextThread: error reading stack");
    let ctx_ptr = emu.maps.read_dword(emu.regs.esp+4).expect("ntdll_NtGetContextThread: error reading context pointer");
    let ctx = emu.maps.read_dword(ctx_ptr).expect("ntdll_NtGetContextThread: error reading context ptr");
    let context_flags = emu.maps.read_dword(ctx).expect("ntdll_NtGetContextThread: error reading context flags");

    let colors = emu32::colors::Colors::new();
    println!("{}** ntdll_NtGetContextThread   ctx flags:0x{:x} {}",colors.light_red, context_flags, colors.nc);

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
    }

    emu.regs.eax = 0;
    emu.stack_pop(false);
    emu.stack_pop(false);
    
    /*

    DR0-DR3 – breakpoint registers
    DR4 & DR5 – reserved
    DR6 – debug status
    DR7 – debug control


    typedef struct _CONTEXT
    {
        ULONG ContextFlags;
        ULONG Dr0;
        ULONG Dr1;
        ULONG Dr2;
        ULONG Dr3;
        ULONG Dr6;
        ULONG Dr7;
        FLOATING_SAVE_AREA FloatSave;
        ULONG SegGs;
        ULONG SegFs;
        ULONG SegEs;
        ULONG SegDs;
        ULONG Edi;
        ULONG Esi;
        ULONG Ebx;
        ULONG Edx;
        ULONG Ecx;
        ULONG Eax;
        ULONG Ebp;
        ULONG Eip;
        ULONG SegCs;
        ULONG EFlags;
        ULONG Esp;
        ULONG SegSs;
        UCHAR ExtendedRegisters[512];
    } CONTEXT, *PCONTEXT;
    */

}

