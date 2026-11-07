"""Wrap a raw image in an ELF file with one segment, linked at a base.

Usage: wrap.py IMAGE OUTPUT arm|mips|mipsbe BASE

radiff2 has no option for the address that a raw image loads at, and
reads it at zero, where the calls of a kernel point at nothing. An ELF file
says where its segment loads. This one has one segment that holds the whole
image, readable, writable and executable, and no sections. Its entry point
is the base, where radare2 puts the entry of a raw image: with no entry
point, `aaa` finds no function.
"""

import struct
import sys

# The machine, the byte order and the flags that each architecture of the
# kernels needs: EF_ARM_EABI_VER5 on ARM, so that the code reads as EABI.
MACHINES = {
    "arm": (40, "<", 0x0500_0000),
    "mips": (8, "<", 0),
    "mipsbe": (8, ">", 0),
}

HEADER_SIZE = 52
SEGMENT_SIZE = 32
# The image starts on a page, as a loader needs the offset of a segment to
# agree with its address modulo the page.
PAGE = 0x1000
PT_LOAD = 1
PF_RWX = 7
ET_EXEC = 2


def wrap(image, machine, order, flags, base):
    """The ELF file that loads `image` at `base`."""
    offset = PAGE
    identity = b"\x7fELF" + bytes([1, 1 if order == "<" else 2, 1]) + bytes(9)
    header = identity + struct.pack(
        order + "HHIIIIIHHHHHH",
        ET_EXEC, machine, 1, base, HEADER_SIZE, 0, flags,
        HEADER_SIZE, SEGMENT_SIZE, 1, 40, 0, 0)
    segment = struct.pack(
        order + "IIIIIIII",
        PT_LOAD, offset, base, base, len(image), len(image), PF_RWX, PAGE)
    padding = bytes(offset - len(header) - len(segment))
    return header + segment + padding + image


def main():
    source, target, arch, base = sys.argv[1:]
    machine, order, flags = MACHINES[arch]
    with open(source, "rb") as file:
        image = file.read()
    with open(target, "wb") as file:
        file.write(wrap(image, machine, order, flags, int(base, 0)))


if __name__ == "__main__":
    main()
