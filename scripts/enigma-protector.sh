#!/bin/bash

set -x

export RUST_BACKTRACE=1
export RUST_LOG=info

# Check if mode parameter is provided
if [ -z "$1" ]; then
    echo "Error: Mode parameter required (dump/load)"
    exit 1
fi

MODE=$1

# Set target architecture based on OS
if [[ "$OSTYPE" == "msys"* ]] || [[ "$OSTYPE" == "cygwin"* ]]; then
    TARGET=x86_64-pc-windows-msvc
else
    TARGET=x86_64-apple-darwin
fi

# Execute based on mode
if [ "$MODE" == "dump" ]; then
    cargo run \
        -p mwemu \
        --release \
        --target $TARGET \
        -- \
        --filename ~/Desktop/enigma/surprise.dll \
        --maps ./maps64/ \
        --64bits \
        --rdx 1 \
        --exit 232239501
elif [ "$MODE" == "load" ]; then
    cargo run \
        -p mwemu \
        --release \
        --target $TARGET \
        -- \
        --filename ~/Desktop/enigma/surprise.dll \
        --maps ./maps64/ \
        --64bits \
        --dump emu.bin.bak
else
    echo "Error: Invalid mode. Use 'dump' or 'load'"
    exit 1
fi