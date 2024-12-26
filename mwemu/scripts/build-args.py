#!/usr/bin/env python3

X64DBG_TRACE_PATH = '/Users/brandon/Downloads/export-20241222-171939.csv' # x64dbg

columns = "Index,Address,Bytes,Disassembly,Registers,Memory,Comments"

# Read the CSV file and get the second line
with open(X64DBG_TRACE_PATH, 'r') as f:
    # Skip the header line
    next(f)

    # Read the second line
    input = next(f).strip()

    # Split the input into fields
    fields = input.split(',')

    # Extract the entry point address and convert to int
    entry_address = int(fields[1].split()[0], 16)

    # Parse the registers string
    registers = fields[4]
    reg_dict = {}

    print(f"DEBUG: Raw registers string: {registers}")

    # Split register string into register:value pairs
    for reg_pair in registers.split(' r'):
        if not reg_pair.strip():
            continue
        
        # Add 'r' back if it was removed (except for first item which might start with 'r')
        if not reg_pair.startswith('r'):
            reg_pair = 'r' + reg_pair
        
        print(f"DEBUG: Processing register pair: {reg_pair}")
        if ':' in reg_pair:
            name, value = reg_pair.split(':', 1)  # Split on first colon only
            # Extract the first value before '->'
            value = value.split('->')[0].strip()
            print(f"DEBUG: Found register {name} = {value}")
            reg_dict[name] = value

    print(f"DEBUG: Final reg_dict: {reg_dict}")

    # calculate base address from entry address
    base_address = entry_address - 0x1035FF0

    # Build the command line arguments
    args = [
        f"--base 0x{base_address:X}",
        f"--entry 0x{entry_address:X}",
        f"--rax 0x{reg_dict['rax']}",
        f"--rbx 0x{reg_dict['rbx']}",
        f"--rcx 0x{reg_dict['rcx']}",
        f"--rdx 0x{reg_dict['rdx']}",
        f"--rsp 0x{reg_dict['rsp']}",
        f"--rbp 0x{reg_dict['rbp']}",
        f"--rsi 0x{reg_dict['rsi']}",
        f"--rdi 0x{reg_dict['rdi']}",
        f"--r8 0x{reg_dict['r8']}",
        f"--r9 0x{reg_dict['r9']}",
        f"--r10 0x{reg_dict['r10']}",
        f"--r11 0x{reg_dict['r11']}",
        f"--r12 0x{reg_dict['r12']}",
        f"--r13 0x{reg_dict['r13']}",
        f"--r14 0x{reg_dict['r14']}",
        f"--r15 0x{reg_dict['r15']}",
    ]

    # Handle rflags separately to avoid index errors
    if 'rflags' in reg_dict:
        rflags_parts = reg_dict['rflags'].split('->')
        if len(rflags_parts) > 1:
            rflags_value = rflags_parts[1].strip()
        else:
            rflags_value = rflags_parts[0].strip()
        args.append(f"--rflags 0x{rflags_value}")

    # Print the formatted arguments
    print(' \\\n    '.join(args))

