#!/bin/bash
RUST_BACKTRACE=1 cargo run \
  --target x86_64-apple-darwin \
  --release \
  -- \
  -6 \
  -vvv \
  --regs \
  -f /Users/brandonros/Desktop/scemu/scripts/DTS9_PatcherV.exe > /Users/brandonros/Desktop/scemu/scripts/scemu-output.txt
node scripts/scemu-vs-x64dbg-parser.js
