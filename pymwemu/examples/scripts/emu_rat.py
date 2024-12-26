from unsigned import Unsigned32 as u32
import pymwemu
import sys

emu = pymwemu.init64()
emu.load_maps('/Users/jesus/src/mwemu/maps64/')
emu.load_binary('msedge_exe_PID1530_codechunk_225DB910000_x64.dll')


comm_protocol = 0x225db9138e0

emu.set_verbose(0)
count = 0

def encode_command(number, increment=3):
    byte_array = number.to_bytes((number.bit_length() + 7) // 8 or 1, byteorder='big')
    transformed_bytes = bytes((b + increment) & 0xFF for b in byte_array)
    return int.from_bytes(transformed_bytes, byteorder='big')


def GetUserNameA():
    retaddr = emu.stack_pop64()
    print('GetUserNameA')
    emu.write_string(emu.get_reg('rcx'), 'baremetal\x00')
    emu.write_qword(emu.get_reg('rdx'), 9)
    emu.set_reg('rax', emu.get_reg('rcx'))

def recv():
    global is_first
    retaddr = emu.stack_pop64()
    rip = emu.get_reg('rip')
    rcx = emu.get_reg('rcx')
    rdx = emu.get_reg('rdx')
    r8 = emu.get_reg('r8')
    cmd = 0x03030305
    print(f'{rip:x}: recv({rcx}, {rdx:x}, {r8}) --> {cmd}')
    emu.write_dword(rdx, cmd)
    emu.set_reg('rax', 4)

def send():
    retaddr = emu.stack_pop64()
    rip = emu.get_reg('rip')
    rcx = emu.get_reg('rcx')
    rdx = emu.get_reg('rdx')
    r8 = emu.get_reg('r8')
    content = emu.read_bytes(rdx, r8)
    print(f'{rip:x}: send({rcx}, {rdx:x}, {r8}) --> {content}')
    emu.set_reg('rax', r8)

emu.set_reg('rip', comm_protocol)
while True:
    addr, name = emu.run_until_apicall()
    if name == 'getusernamea':
        GetUserNameA()
    elif name =='recv':
        recv()
    elif name == 'send':
        send()
    elif name == 'shutdown':
        sys.exit(1)
    else:
        emu.handle_winapi(addr)


