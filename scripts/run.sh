#!/bin/sh
export RUST_BACKTRACE=1
cargo run \
  --target x86_64-apple-darwin \
  --release \
  -- \
  -6 \
  -vvv \
  --regs \
  --memory \
  --inspect 'qword ptr [rsp]' \
  -f ./shellcodes64/DTS9_PatcherV.exe > ./scripts/scemu-output.txt
node ./scripts/scemu-vs-x64dbg-parser.js