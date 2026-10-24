#!/bin/sh
# Write the xz streams that the tests of hereticus-unpack decode: a payload
# of the calls and jumps that each branch filter of xz rewrites, with random
# targets and random bytes between, compressed with each filter.
set -eu
cd "$(dirname "$0")"
python3 - <<'PYTHON'
import random
import struct

random.seed(7)
out = bytearray()
for _ in range(256):
    # x86: `call` and `jmp` with a near offset, after some other bytes.
    out += random.randbytes(random.randrange(3))
    out += bytes([random.choice([0xE8, 0xE9])]) + random.randbytes(3) + bytes([random.choice([0, 0xFF])])
    # A32 `bl`, A64 `bl` and `adrp`, T32 `bl`, PowerPC `bl`, SPARC `call`.
    while len(out) % 4:
        out += b"\0"
    out += struct.pack("<I", 0xEB000000 | random.getrandbits(24))
    out += struct.pack("<I", 0x94000000 | random.getrandbits(26))
    out += struct.pack("<I", 0x90000000 | random.getrandbits(5) | (random.getrandbits(2) << 29) | (random.randrange(-0x20000, 0x20000) & 0x7FFFF) << 5)
    out += struct.pack("<HH", 0xF000 | random.getrandbits(11), 0xF800 | random.getrandbits(11))
    out += struct.pack(">I", 0x48000001 | random.getrandbits(24) << 2)
    out += struct.pack(">I", 0x40000000 | random.getrandbits(22))
open("payload.bin", "wb").write(out)
PYTHON
for filter in x86 powerpc arm armthumb arm64 sparc; do
    xz --format=xz --check=crc32 "--$filter" --lzma2=preset=0 --stdout payload.bin > "$filter.xz"
done
xz --format=xz --check=crc32 --arm=start=4096 --lzma2=preset=0 --stdout payload.bin > arm-start.xz
gzip -9 -n --stdout payload.bin > payload.gz
zstd -19 -q --stdout payload.bin > payload.zst
