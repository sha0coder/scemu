#!/usr/bin/env python3

# run python3 installer from python.org
# copy python.exe to python3.exe in C:\Users\Brandon\AppData\Local\Programs\Python\Python313\
# add to GitBash path
# python3 -m venv .venv
# source .venv/Scripts/activate
# pip install maturin
# maturin build --release -m pymwemu/Cargo.toml
# pip install --force-reinstall /c/Users/Brandon/.cargo/.target/wheels/pymwemu-0.9.5-cp313-cp313-win_amd64.whl 
# .venv/Scripts/python.exe scripts/enigma-protector.py

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
