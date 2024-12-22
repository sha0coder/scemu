#!/bin/bash

set -x

export RUST_BACKTRACE=1

cargo run --target x86_64-apple-darwin \
    -- \
    -vv \
    --64bits \
    --maps scemu/maps64 \
    --trace /tmp/output.csv \
    --memory \
    --filename ~/Desktop/enigma/surprise.dll
