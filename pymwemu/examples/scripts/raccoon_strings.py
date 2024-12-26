import pymwemu
import sys

emu = pymwemu.init32()
emu.load_maps('/home/sha0/src/mwemu/maps32/')
emu.load_binary('mw/raccoon.bin')


raccoon_decrypt_strings = 0x0404924

emu.set_verbose(2)
#emu.spawn_console_at_pos(6)
#emu.enable_console()


strings = []

emu.set_reg('eip', raccoon_decrypt_strings)
while emu.step():

    if emu.get_reg('eip') >= 0x040b488:
        break

    opcode = emu.read_byte(emu.get_reg('eip'))
    if opcode == 0x6a:  # emu.get_prev_mnemonic()  
        decrypted_ptr = emu.get_reg('eax')
        decrypted = emu.read_string(decrypted_ptr)
        strings.append(f'{hex(decrypted_ptr)}: {decrypted}')


for s in list(set(strings)):
    if s:
        print(s)

#emu.show_allocs()

