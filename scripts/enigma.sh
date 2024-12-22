#!/bin/bash

set -x

export RUST_BACKTRACE=1

cargo run --target x86_64-apple-darwin \
    -- \
    -vv \
    --64bits \
    --maps ./maps64 \
    --trace /tmp/output.csv \
    --memory \
    --base 0x00007FFBEE4B0000 \
    --entry 0x00007FFBEF4E5FF0 \
    --filename ~/Desktop/enigma/surprise.dll
