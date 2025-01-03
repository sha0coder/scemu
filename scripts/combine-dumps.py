# example: python scripts/combine-dumps.py dumps/surprise-combined-output.bin dumps/*-surprise*

import os
import sys
from pathlib import Path

def combine_binary_files(input_files, output_file):
    # Find the lowest and highest addresses
    addresses = []
    print("\nProcessing files:")
    for filename in input_files:
        base_filename = filename.split('/')[-1]
        addr = int(base_filename.split('-')[0], 16)
        print(f"  File: {filename}")
        print(f"    Base filename: {base_filename}")
        print(f"    Address: 0x{addr:x}")
        addresses.append(addr)
    
    base_addr = min(addresses)
    max_addr = max(addresses)
    print(f"\nAddress range:")
    print(f"  Base address: 0x{base_addr:x}")
    print(f"  Max address:  0x{max_addr:x}")
    print(f"  Total size:   0x{max_addr - base_addr:x} bytes")
    
    # Create output buffer
    with open(output_file, 'wb') as outf:
        print(f"\nInitializing output file '{output_file}' with zeros")
        outf.seek(max_addr - base_addr)
        outf.write(b'\0')
        
        # Write each file at its correct offset
        print("\nWriting files:")
        for filename in input_files:
            base_filename = filename.split('/')[-1]
            addr = int(base_filename.split('-')[0], 16)
            offset = addr - base_addr
            
            with open(filename, 'rb') as inf:
                data = inf.read()
                end_addr = addr + len(data)
                print(f"  Writing {base_filename}")
                print(f"    Address Range: 0x{addr:x} - 0x{end_addr:x}")
                print(f"    Size:         0x{len(data):x} bytes")
                print(f"    Offset:       0x{offset:x}")
                outf.seek(offset)
                outf.write(data)
    
    print(f"\nCombined dump written to {output_file}")

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python combine_bins.py output.bin input1.bin input2.bin ...")
        sys.exit(1)
        
    output_file = sys.argv[1]
    input_files = sys.argv[2:]
    print("\nInitial input files:", input_files)
    
    # Filter out files ending in ldr.bin
    input_files = [f for f in input_files if not f.endswith('ldr.bin')]
    print("\nInput files (excluding ldr.bin):", input_files)
    
    # Sort input files
    input_files.sort(key=lambda x: int(x.split('/')[-1].split('-')[0], 16))
    print("\nSorted input files:", input_files)
    
    combine_binary_files(input_files, output_file)