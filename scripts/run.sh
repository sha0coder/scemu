#!/bin/bash

if [[ "$OSTYPE" == "darwin21" ]]
then
  TARGET="x86_64-apple-darwin"
elif [[ "$OSTYPE" == "linux-gnu" ]]
then
  TARGET="x86_64-unknown-linux-gnu"
elif [[ "$OSTYPE" == "linux-musl" ]]
then
  TARGET="x86_64-unknown-linux-musl"
elif [[ "$OSTYPE" == "msys" ]]
then
  TARGET="x86_64-pc-windows-msvc"
else
  echo "unknown OSTYPE: $OSTYPE"
  exit
fi

export RUST_BACKTRACE=1

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
