#!/usr/bin/env python3

import csv

SCEMU_TRACE_PATH = '/tmp/output.csv' # scemu
X64DBG_TRACE_PATH = '/Users/brandon/Downloads/export-20241222-171939.csv' # x64dbg
EXPECTED_HEADERS = ["Index", "Address", "Bytes", "Disassembly", "Registers", "Memory", "Comments"]
EXPECTED_BASE = 0x180000000
EXPECTED_ENTRY = 0x181035FF0

def validate_headers(headers):
    if headers != EXPECTED_HEADERS:
        raise ValueError(f"Invalid CSV headers. Expected {EXPECTED_HEADERS}, got {headers}")

def parse_hex(s):
    # Strip any leading/trailing whitespace and remove any '0x' prefix
    s = s.strip().replace('0x', '')
    # Handle empty strings
    if not s:
        return 0
    return int(s, 16)

def calculate_offset(first_addr):
    """Calculate the offset needed to normalize addresses to expected RVA"""
    return first_addr - EXPECTED_ENTRY

def compare_traces():
    print(f"Opening files:")
    print(f"scemu trace: {SCEMU_TRACE_PATH}")
    print(f"x64dbg trace: {X64DBG_TRACE_PATH}")
    
    with open(SCEMU_TRACE_PATH, 'r') as f_scemu, open(X64DBG_TRACE_PATH, 'r') as f_x64dbg:
        print("Files opened successfully")
        
        scemu_reader = csv.DictReader(f_scemu)
        x64dbg_reader = csv.DictReader(f_x64dbg)
        
        # Get first row to calculate offsets
        scemu_row = next(scemu_reader)
        x64dbg_row = next(x64dbg_reader)

        # add Source column to traces
        scemu_row['Source'] = 'scemu'
        x64dbg_row['Source'] = 'x64dbg'
        
        # Calculate offsets based on first address
        scemu_offset = calculate_offset(parse_hex(scemu_row['Address'].split()[0]))
        x64dbg_offset = calculate_offset(parse_hex(x64dbg_row['Address'].split()[0]))
        
        print(f"scemu trace offset: 0x{scemu_offset:x}")
        print(f"x64dbg trace offset: 0x{x64dbg_offset:x}")

        if scemu_offset != x64dbg_offset:
            raise ValueError(f"Trace offsets do not match: scemu=0x{scemu_offset:x}, x64dbg=0x{x64dbg_offset:x}")

        # Add buffer for previous lines
        scemu_prev_lines = [(parse_hex(scemu_row['Index']), 
                        parse_hex(scemu_row['Address'].split()[0]) - scemu_offset, 
                        scemu_row)]
        x64dbg_prev_lines = [(parse_hex(x64dbg_row['Index']), 
                        parse_hex(x64dbg_row['Address'].split()[0]) - x64dbg_offset, 
                        x64dbg_row)]
        max_history = 10

        # Compare all rows
        for row_num, (scemu_row, x64dbg_row) in enumerate(zip(scemu_reader, x64dbg_reader), start=2):
            scemu_idx = parse_hex(scemu_row['Index'])
            x64dbg_idx = parse_hex(x64dbg_row['Index'])
            scemu_addr = parse_hex(scemu_row['Address'].split()[0]) - scemu_offset
            x64dbg_addr = parse_hex(x64dbg_row['Address'].split()[0]) - x64dbg_offset

            # add Source column to traces
            scemu_row['Source'] = 'scemu'
            x64dbg_row['Source'] = 'x64dbg'

            # Store current line in history
            scemu_prev_lines.append((scemu_idx, scemu_addr, scemu_row))
            x64dbg_prev_lines.append((x64dbg_idx, x64dbg_addr, x64dbg_row))
            if len(scemu_prev_lines) > max_history:
                scemu_prev_lines.pop(0)
                x64dbg_prev_lines.pop(0)

            if scemu_idx != x64dbg_idx or scemu_addr != x64dbg_addr:
                print(f"\nDifference found at row {row_num}:")
                print(f"\nPrevious {max_history} lines from scemu trace:")
                for prev_idx, prev_addr, prev_row in scemu_prev_lines:
                    print(f"Index=0x{prev_idx:x}, RVA=0x{prev_addr:x}")
                    print(f"Full row: {prev_row}")
                print(f"\nPrevious {max_history} lines from x64dbg trace:")
                for prev_idx, prev_addr, prev_row in x64dbg_prev_lines:
                    print(f"Index=0x{prev_idx:x}, RVA=0x{prev_addr:x}")
                    print(f"Full row: {prev_row}")
                print("\nDifferent lines:")
                print(f"scemu trace: Index=0x{scemu_idx:x}, RVA=0x{scemu_addr:x}")
                print(f"x64dbg trace: Index=0x{x64dbg_idx:x}, RVA=0x{x64dbg_addr:x}")
                print("\nRaw values:")
                print(f"scemu trace: {scemu_row}")
                print(f"x64dbg trace: {x64dbg_row}")
                return

if __name__ == '__main__':
    try:
        compare_traces()
    except Exception as e:
        print(f"Error: {e}")
