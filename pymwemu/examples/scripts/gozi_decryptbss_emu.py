import pymwemu
import sys

emu = pymwemu.init32()
emu.load_maps('/home/sha0/src/mwemu/maps32/')  # Load 32bits dependncies: kernel32, winnet etc 
emu.load_binary('../modules/gozi_main_module.bin')  # PE32 load 




#dll = emu.load_map('dll_hdr', 'gozi_main_module.bin', 1)
# load disk file to emulator memory

gozi_start = 0x1001B728 # function called from DllMain
hInstDll = 0x10000000  # gozi base address
lpReserved = 0


# skip unimplemented apis, and continue emulation thanks to knowing the number of params.
emu.enable_banzai_mode()
emu.banzai_add('ConvertStringSecurityDescriptorToSecurityDescriptorA', 4)
emu.banzai_add('_strupr', 1)
emu.banzai_add('NtOpenProcess', 4)
emu.banzai_add('NtOpenProcessToken', 3)
emu.banzai_add('NtQueryInformationToken', 5)
emu.banzai_add('memcpy', 3)
emu.banzai_add('IsWow64Process', 2)
emu.banzai_add('lstrcpy', 3)

'''
# calculating key
emu.set_verbose(3)
emu.stack_push32(lpReserved)
emu.stack_push32(hInstDll)
emu.stack_push32(1)
emu.set_reg('eip', gozi_start)
emu.run(0x1001a550)
emu.spawn_console()
'''


# Decrypt BSS

emu.set_verbose(3)
try:
    emu.call32(gozi_start, [hInstDll, lpReserved])
except:
    pass


# dump BSS

print()
print('First and bigger alloc is bss decrypted:')
emu.show_allocs()
emu.save_all_allocs('/tmp/')
print('allocs saved to /tmp/')
emu.spawn_console()
sys.exit(1)




