import pymwemu
import sys

emu = pymwemu.init32()
emu.load_maps('/home/sha0/src/mwemu/maps32/')
emu.load_binary('/home/sha0/src/demo/mw/dbmm_unpacked.dll')
emu.enable_banzai_mode()

danabot_crypt_decrypt_aes256 = 0x022D61B8

pt = emu.alloc("pt", 1024)+8
emu.write_string(pt, "lskdfñalsdf")

pubkey = emu.alloc("pubkey", 1024)+8
emu.write_spaced_bytes(pubkey, "AA BB 3F 1B 2C")

seed = emu.alloc("seed", 100)+8
emu.write_string(seed, "lksdjfasdf")


emu.set_reg("eax", 1)
emu.set_reg("edx", pt)
emu.set_reg("ecx", pubkey)

emu.set_verbose(3)
emu.call32( danabot_crypt_decrypt_aes256, [seed] )




