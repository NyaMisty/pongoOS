#!/usr/bin/python2
import sys
import itertools
import struct
# bash -c "echo 6175746F626F6F740000200000000000 | xxd -ps -r | cat $(BUILD)/Pongo.bin <(dd if=/dev/zero bs=1 count="$$(((8 - ($$($(STAT) $(BUILD)/Pongo.bin) % 8)) % 8))") /dev/stdin $(BUILD)/checkra1n-kpf-pongo > $@"
# output pongoBin mod1 mod1_command mod1_sleep ... modn modn_command modn_sleep

def get_padding(l):
    return (8 - (l % 8)) % 8

def parse_num(n):
    return int(n, 16) if n.startswith('0x') else int(n)

def signal_last(it):
    iterable = iter(it)
    ret_var = next(iterable)
    for val in iterable:
        yield False, ret_var
        ret_var = val
    yield True, ret_var

with open(sys.argv[1], 'wb') as f:
    with open(sys.argv[2], "rb") as pongoBin:
        pongoBuf = pongoBin.read()
        f.write(pongoBuf)
        pongoLen = len(pongoBuf)
        del pongoBuf
        # "$(( (8 - ($(stat Pongo.bin) % 8)) % 8 ))"
        paddingLen = get_padding(pongoLen)
        f.write(b'\x00' * paddingLen)
        f.write('6175746F626F6F740000200000000000'.decode('hex'))
    
    grouper = lambda x, n: [x[i:i+n] for i in range(0, len(x), n)] 
    for isLast, mod in signal_last(grouper(sys.argv[3:], 3)):
        with open(mod[0], "rb") as moduleBin:
            moduleBuf = moduleBin.read()
            moduleLen = len(moduleBuf)
            paddingLen = get_padding(moduleLen)
        totalLen = moduleLen + paddingLen if not isLast else 0xffffffff
        f.write(struct.pack("8s24sQQ", 'autobmod', mod[1], parse_num(mod[2]), totalLen)) # header
        f.write(moduleBuf)
        f.write(b'\x00' * paddingLen)
