#!/usr/bin/env python3

"""
# run python3 installer from python.org
# copy python.exe to python3.exe in C:\Users\Brandon\AppData\Local\Programs\Python\Python313\
python3 -m venv .venv
# on windows
source .venv/Scripts/activate
# on macos
source .venv/bin/activate
pip install maturin
# on windows
python3 -m maturin build --release -m ./pymwemu/Cargo.toml
# on macos
python3 -m maturin build --release --target x86_64-apple-darwin -m ./pymwemu/Cargo.toml
# on windows
python3 -m pip install --force-reinstall ~/.cargo/target/wheels/pymwemu-0.9.6-cp313-cp313-win_amd64.whl
# on macos
python3 -m pip install --force-reinstall ~/.cargo/target/wheels/pymwemu-0.9.6-cp313-cp313-macosx_10_12_x86_64.whl
# ./scripts/enigma-protector.py
"""


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
