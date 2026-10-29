"""Copy an ELF without what follows its loadable segments (debug info,
symbols, section headers): what a loader reads, and nothing else.

    python3 -I strip-elf.py IN OUT
"""

import struct
import sys

src, dst = sys.argv[1], sys.argv[2]
data = bytearray(open(src, "rb").read())
if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
    sys.exit(f"{src}: not a 64-bit little-endian ELF")
phoff, = struct.unpack_from("<Q", data, 0x20)
phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
end = phoff + phentsize * phnum
for i in range(phnum):
    p_type, _, p_offset, _, _, p_filesz = struct.unpack_from("<IIQQQQ", data, phoff + i * phentsize)
    if p_type == 1:  # PT_LOAD
        end = max(end, p_offset + p_filesz)
# No section headers: e_shoff, then e_shentsize, e_shnum, e_shstrndx.
struct.pack_into("<Q", data, 0x28, 0)
struct.pack_into("<HHH", data, 0x3A, 0, 0, 0)
open(dst, "wb").write(data[:end])
