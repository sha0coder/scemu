#!/bin/bash

set -x

export RUST_BACKTRACE=1
export RUST_LOG=info

# Set target architecture based on OS
if [[ "$OSTYPE" == "msys"* ]] || [[ "$OSTYPE" == "cygwin"* ]]; then
    TARGET=x86_64-pc-windows-msvc
else
    TARGET=x86_64-apple-darwin
fi

cargo run -p mwemu --release \
    --target $TARGET \
    -- \
    --filename ~/Desktop/enigma/surprise.dll \
    --maps ./maps64/ \
    --64bits \
    --rdx 1 \
    --banzai