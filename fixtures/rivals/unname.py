"""Remove every symbol that a shared library defines, as if it had no exports.

Usage: unname.py LIBRARY OUTPUT

`llvm-strip` keeps .dynsym, as a shared library needs it to load, so a
stripped library still names and places each function it exports. This
writes a copy whose defined dynamic symbols are null entries, and whose
.dynstr holds zeros in place of their names. The symbols that the library
imports stay, as they do in a stripped executable, and so do the strings that
.dynamic and the version sections read.

A relocation that stores the address of a removed symbol becomes a relative
one that stores the same address, as a linker writes it for a symbol that the
library does not export. Thus a table of pointers to functions keeps its
pointers, with bit 0 of each Thumb function. The copy is for the analysis of
a tool, not for a loader.
"""

import struct
import sys

SHT_RELA = 4
SHT_NOBITS = 8
SHT_REL = 9
SHT_DYNSYM = 11
SHT_DYNAMIC = 6
SHT_GNU_VERDEF = 0x6FFFFFFD
SHT_GNU_VERNEED = 0x6FFFFFFE
SHN_UNDEF = 0

# The tags of .dynamic whose value is an offset in .dynstr.
STRING_TAGS = {1, 14, 15, 29}  # DT_NEEDED, DT_SONAME, DT_RPATH, DT_RUNPATH

EM_386 = 3
EM_MIPS = 8
EM_PPC = 20
EM_PPC64 = 21
EM_ARM = 40
EM_X86_64 = 62
EM_AARCH64 = 183

# For each machine of the backports: its relative relocation, the relocations
# that store a symbol plus an addend, and those that store the symbol alone.
RELOCATIONS = {
    EM_ARM: (23, {2}, {21, 22}),  # R_ARM_RELATIVE; ABS32; GLOB_DAT, JUMP_SLOT
    EM_AARCH64: (1027, {257}, {1025, 1026}),  # R_AARCH64_RELATIVE; ABS64; ...
    EM_MIPS: (3, {2, 3}, set()),  # R_MIPS_REL32 with no symbol; 32, REL32
    EM_X86_64: (8, {1}, {6, 7}),  # R_X86_64_RELATIVE; 64; GLOB_DAT, JUMP_SLOT
    EM_386: (8, {1}, {6, 7}),  # R_386_RELATIVE; 32; GLOB_DAT, JMP_SLOT
    EM_PPC: (22, {1}, {20, 21}),  # R_PPC_RELATIVE; ADDR32; GLOB_DAT, JMP_SLOT
    EM_PPC64: (22, {38}, {20, 21}),  # R_PPC64_RELATIVE; ADDR64; GLOB_DAT, JMP_SLOT
}


class Elf:
    """The fields of an ELF file that this script reads, in its own layout."""

    def __init__(self, data):
        if data[:4] != b"\x7fELF":
            raise ValueError("not an ELF file")
        self.wide = data[4] == 2
        self.order = "<" if data[5] == 1 else ">"
        self.data = data
        self.machine, = self.unpack("H", 0x12)
        if self.wide:
            shoff, = self.unpack("Q", 0x28)
            shentsize, shnum = self.unpack("HH", 0x3A)
        else:
            shoff, = self.unpack("I", 0x20)
            shentsize, shnum = self.unpack("HH", 0x2E)
        self.sections = [self.section(shoff + at * shentsize) for at in range(shnum)]

    def unpack(self, form, offset):
        return struct.unpack_from(self.order + form, self.data, offset)

    def section(self, offset):
        if self.wide:
            _, kind, _, _, start, size, link, _, _, entsize = self.unpack("IIQQQQIIQQ", offset)
        else:
            _, kind, _, _, start, size, link, _, _, entsize = self.unpack("IIIIIIIIII", offset)
        _, _, _, address, _, _, _, _, _, _ = self.unpack(
            "IIQQQQIIQQ" if self.wide else "IIIIIIIIII", offset)
        return {"type": kind, "address": address, "offset": start, "size": size, "link": link,
                "entsize": entsize}

    def symbols(self, section):
        """Each symbol of `section`: its index, where its entry is, its name,
        its value and its section."""
        start, step = section["offset"], section["entsize"]
        for index, at in enumerate(range(start, start + section["size"], step)):
            if self.wide:
                name, _, _, shndx, value = self.unpack("IBBHQ", at)
            else:
                name, value, _, _, _, shndx = self.unpack("IIIBBH", at)
            yield index, at, name, value, shndx

    def file_offset(self, address):
        """Where the byte that is linked at `address` is in the file."""
        for section in self.sections:
            if section["type"] == SHT_NOBITS or section["address"] == 0:
                continue
            if section["address"] <= address < section["address"] + section["size"]:
                return address - section["address"] + section["offset"]
        raise ValueError(f"no section holds {address:#x}")

    def relocations(self, section):
        """Each relocation of `section`: where its entry is, the address it
        stores at, its symbol, its type and its addend, None for REL."""
        explicit = section["type"] == SHT_RELA
        if self.wide:
            form = "QQq" if explicit else "QQ"
        else:
            form = "IIi" if explicit else "II"
        for at in range(section["offset"], section["offset"] + section["size"], section["entsize"]):
            fields = self.unpack(form, at)
            info = fields[1]
            symbol, kind = (info >> 32, info & 0xFFFFFFFF) if self.wide else (info >> 8, info & 0xFF)
            if self.wide and self.machine == EM_MIPS:
                raise ValueError("64-bit MIPS packs its relocations in another way")
            yield at, fields[0], symbol, kind, fields[2] if explicit else None

    def dynamic_strings(self, section):
        """The .dynstr offsets that the entries of .dynamic hold."""
        form = "qQ" if self.wide else "iI"
        step = struct.calcsize(form)
        for at in range(section["offset"], section["offset"] + section["size"], step):
            tag, value = self.unpack(form, at)
            if tag in STRING_TAGS:
                yield value

    def version_strings(self, section):
        """The .dynstr offsets that a verneed or a verdef section holds."""
        at = section["offset"]
        while True:
            if section["type"] == SHT_GNU_VERNEED:
                _, count, name, aux, following = self.unpack("HHIII", at)
                yield name
                entry = at + aux
                for _ in range(count):
                    _, _, _, name, step = self.unpack("IHHII", entry)
                    yield name
                    entry += step
            else:
                _, _, _, count, _, aux, following = self.unpack("HHHHIII", at)
                entry = at + aux
                for _ in range(count):
                    name, step = self.unpack("II", entry)
                    yield name
                    entry += step
            if following == 0:
                return
            at += following


def string_end(data, start):
    return data.index(b"\0", start)


def pack_word(elf, value):
    return struct.pack(elf.order + ("Q" if elf.wide else "I"), value % (1 << (64 if elf.wide else 32)))


def make_relative(elf, out, dynsym, values):
    """Turn each relocation that stores the address of a symbol of `values`
    into a relative one that stores the same address."""
    relative, with_addend, alone = RELOCATIONS[elf.machine]
    width = 8 if elf.wide else 4
    for section in elf.sections:
        if section["type"] not in (SHT_REL, SHT_RELA) or elf.sections[section["link"]] is not dynsym:
            continue
        for at, address, symbol, kind, addend in elf.relocations(section):
            if symbol not in values or kind not in with_addend | alone:
                continue
            if addend is None:
                # Only an implicit addend lives in the word, which an
                # explicit one can leave in .bss, as on PowerPC.
                word = elf.file_offset(address)
                stored, = elf.unpack("Q" if elf.wide else "I", word)
                target = values[symbol] + (stored if kind in with_addend else 0)
                out[word:word + width] = pack_word(elf, target)
                # With symbol 0, the info word of a relocation is its type.
                out[at + width:at + 2 * width] = pack_word(elf, relative)
            else:
                target = values[symbol] + (addend if kind in with_addend else 0)
                out[at + width:at + 2 * width] = pack_word(elf, relative)
                out[at + 2 * width:at + 3 * width] = pack_word(elf, target)


def unname(data):
    elf = Elf(data)
    if elf.machine not in RELOCATIONS:
        raise ValueError(f"machine {elf.machine} is not one of the backports")
    out = bytearray(data)
    for dynsym in [s for s in elf.sections if s["type"] == SHT_DYNSYM]:
        strings = elf.sections[dynsym["link"]]
        kept = set()
        removed = set()
        values = {}
        for index, at, name, value, shndx in elf.symbols(dynsym):
            if shndx == SHN_UNDEF:
                kept.add(name)
            else:
                removed.add(name)
                values[index] = value
                out[at:at + dynsym["entsize"]] = bytes(dynsym["entsize"])
        make_relative(elf, out, dynsym, values)
        for section in elf.sections:
            if section["link"] != dynsym["link"]:
                continue
            if section["type"] == SHT_DYNAMIC:
                kept.update(elf.dynamic_strings(section))
            elif section["type"] in (SHT_GNU_VERNEED, SHT_GNU_VERDEF):
                kept.update(elf.version_strings(section))

        # Names can share a tail, so a byte stays when a kept name holds it.
        base = strings["offset"]
        keep = bytearray(strings["size"])
        for name in kept:
            end = string_end(data, base + name) - base
            keep[name:end] = b"\1" * (end - name)
        for name in removed - {0}:
            for at in range(base + name, string_end(data, base + name)):
                if not keep[at - base]:
                    out[at] = 0
    return bytes(out)


def main():
    source, target = sys.argv[1:]
    with open(source, "rb") as file:
        data = file.read()
    with open(target, "wb") as file:
        file.write(unname(data))


if __name__ == "__main__":
    main()
