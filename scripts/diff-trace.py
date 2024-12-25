#!/usr/bin/env python3

import csv

TRACE1_PATH = '/tmp/output.csv' # scemu
TRACE2_PATH = '/Users/brandon/Downloads/export-20241222-171939.csv' # x64dbg
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
    print(f"Trace 1: {TRACE1_PATH}")
    print(f"Trace 2: {TRACE2_PATH}")
    
    with open(TRACE1_PATH, 'r') as f1, open(TRACE2_PATH, 'r') as f2:
        print("Files opened successfully")
        
        reader1 = csv.DictReader(f1)
        reader2 = csv.DictReader(f2)
        
        # Get first row to calculate offsets
        row1 = next(reader1)
        row2 = next(reader2)
        
        # Calculate offsets based on first address
        offset1 = calculate_offset(parse_hex(row1['Address'].split()[0]))
        offset2 = calculate_offset(parse_hex(row2['Address'].split()[0]))
        
        print(f"Trace 1 offset: 0x{offset1:x}")
        print(f"Trace 2 offset: 0x{offset2:x}")

        # Compare first row
        idx1 = parse_hex(row1['Index'])
        idx2 = parse_hex(row2['Index'])
        addr1 = parse_hex(row1['Address'].split()[0]) - offset1
        addr2 = parse_hex(row2['Address'].split()[0]) - offset2

        if idx1 != idx2 or addr1 != addr2:
            print(f"Difference found in first row:")
            print(f"Trace 1: Index=0x{idx1:x}, RVA=0x{addr1:x}")
            print(f"Trace 2: Index=0x{idx2:x}, RVA=0x{addr2:x}")
            return

        # Add buffer for previous lines
        prev_lines1 = []
        prev_lines2 = []
        max_history = 4

        # Compare remaining rows
        for row_num, (row1, row2) in enumerate(zip(reader1, reader2), start=2):
            idx1 = parse_hex(row1['Index'])
            idx2 = parse_hex(row2['Index'])
            addr1 = parse_hex(row1['Address'].split()[0]) - offset1
            addr2 = parse_hex(row2['Address'].split()[0]) - offset2

            # Store current line in history
            prev_lines1.append((idx1, addr1, row1))
            prev_lines2.append((idx2, addr2, row2))
            if len(prev_lines1) > max_history:
                prev_lines1.pop(0)
                prev_lines2.pop(0)

            if idx1 != idx2 or addr1 != addr2:
                print(f"\nDifference found at row {row_num}:")
                print("\nPrevious 4 lines from Trace 1:")
                for prev_idx, prev_addr, prev_row in prev_lines1:
                    print(f"Index=0x{prev_idx:x}, RVA=0x{prev_addr:x}")
                    print(f"Full row: {prev_row}")
                print("\nPrevious 4 lines from Trace 2:")
                for prev_idx, prev_addr, prev_row in prev_lines2:
                    print(f"Index=0x{prev_idx:x}, RVA=0x{prev_addr:x}")
                    print(f"Full row: {prev_row}")
                print("\nDifferent lines:")
                print(f"Trace 1: Index=0x{idx1:x}, RVA=0x{addr1:x}")
                print(f"Trace 2: Index=0x{idx2:x}, RVA=0x{addr2:x}")
                print("\nRaw values:")
                print(f"Trace 1: {row1}")
                print(f"Trace 2: {row2}")
                return

if __name__ == '__main__':
    try:
        compare_traces()
    except Exception as e:
        print(f"Error: {e}")
