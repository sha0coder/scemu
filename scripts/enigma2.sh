#!/bin/bash

set -x

export RUST_BACKTRACE=1
export RUST_LOG=info

cargo run --release \
    --target x86_64-apple-darwin \
    -- \
    --filename ~/Downloads/enigma/surprise.dll \
    --maps ./maps64 \
    --64bits \
    --trace_start 0xD950920 \
    --trace /tmp/output.csv \
    --memory \
    --mxcsr 0x1FC00001FA0 \
    --stack_address 0x32C6FE000 \
    --exit 0xD95092E \
    --base 0x7FFBFA260000 \
    --entry 0x7FFBFB295FF0 \
    --rax 0x7FFBFB295FF0 \
    --rbx 0x7FFE0385 \
    --rcx 0x7FFBFA260000 \
    --rdx 0x1 \
    --rsp 0x32C6FE378 \
    --rbp 0x32C6FE6B8 \
    --rsi 0x1 \
    --rdi 0x7FFE0384 \
    --r8 0x0 \
    --r9 0x0 \
    --r10 0xA440AE23305F3A70 \
    --r11 0x32C6FE3E8 \
    --r12 0x7FFBFB295FF0 \
    --r13 0x120136C63F0 \
    --r14 0x7FFBFA260000 \
    --r15 0x0 \
    --rflags 0x344 
