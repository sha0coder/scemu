#!/usr/bin/env python3

# python3 -m venv .venv
# source .venv/bin/activate
# pip install maturin
# maturin develop --release -m pymwemu/Cargo.toml

import pymwemu
import os

emu = pymwemu.init64()
emu.load_maps('./maps64/')
emu.load_binary(os.path.join(os.path.expanduser('~'), 'Desktop', 'enigma', 'surprise.dll'))

emu.set_verbose(0)
emu.set_reg('rdx', 1)
#emu.spawn_console_at_pos(227871000)
try:
    emu.run()
except Exception as e:
    print(f"Error during emulation: {e}")
finally:
    emu.spawn_console()
