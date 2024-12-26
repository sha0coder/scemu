#!/bin/bash

set -x

export RUST_BACKTRACE=1
export RUST_LOG=info

cargo run --target x86_64-apple-darwin \
    -- \
    -vv \
    --64bits \
    --trace /tmp/output.csv \
    --memory \
    --base 0x00007FFBEE4B0000 \
    --entry 0x00007FFBEF4E5FF0 \
    --rax 0x7FFBEF4E5FF0 \
    --rbx 0x7FFE0385 \
    --rcx 0x7FFBEE4B0000 \
    --rdx 0x1 \
    --rsp 0x98EB5DDFF8 \
    --rbp 0x98EB5DE338 \
    --rsi 0x1 \
    --rdi 0x7FFE0384 \
    --r8 0x0 \
    --r9 0x0 \
    --r10 0xA440AE23305F3A70 \
    --r11 0x98EB5DE068 \
    --r12 0x7FFBEF4E5FF0 \
    --r13 0x1FC18C72DC0 \
    --r14 0x7FFBEE4B0000 \
    --r15 0x0 \
    --stack_address 0x98EB5DD000 \
    --rflags 0x246 \
    --mxcsr 0x1FC00001FA0 \
    --filename ~/Downloads/enigma/haspemul.dll
    #--filename ~/Desktop/enigma/surprise.dll
