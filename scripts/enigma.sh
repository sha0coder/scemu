#!/bin/bash

set -x

export RUST_BACKTRACE=1
export RUST_LOG=info

cargo run --release \
    --target x86_64-apple-darwin \
    -- \
    -vv \
    --64bits \
    --trace /tmp/output.csv \
    --memory \
    --mxcsr 0x1FC00001FA0 \
    --base 0x7FFBF51D0000 \
    --exit 0xD95092E \
    --entry 0x7FFBF6205FF0 \
    --rax 0x7FFBF6205FF0 \
    --rbx 0x7FFE0385 \
    --rcx 0x7FFBF51D0000 \
    --rdx 0x1 \
    --rsp 0x4FD74FDE78 \
    --rbp 0x4FD74FE1B8 \
    --rsi 0x1 \
    --rdi 0x7FFE0384 \
    --r8 0x0 \
    --r9 0x0 \
    --r10 0xA440AE23305F3A70 \
    --r11 0x4FD74FDEE8 \
    --r12 0x7FFBF6205FF0 \
    --r13 0x176DB67A750 \
    --r14 0x7FFBF51D0000 \
    --r15 0x0 \
    --rflags 0x344 \
    --stack_address 0x4FD74FD000 \
    --filename ~/Desktop/enigma/surprise.dll
