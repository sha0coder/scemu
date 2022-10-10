#!/bin/sh

export RUST_BACKTRACE=1

TARGET=x86_64-pc-windows-msvc
if [[ $OSTYPE == "darwin21" ]]
then
  TARGET="x86_64-apple-darwin"
elif [[ $OSTYPE == "linux-gnu" ]]
then
  TARGET="x86_64-unknown-linux-gnu"
fi

cargo run \
  --target $TARGET \
  --release \
  -- \
  -6 \
  -vvv \
  --regs \
  --memory \
  -f ./shellcodes64/DTS9_PatcherV.exe > ./scripts/scemu-output.txt
node ./scripts/scemu-vs-x64dbg-parser.js
