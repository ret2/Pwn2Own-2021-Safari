# this script avoids depending on binutils
# and replaces `gobjcopy -O binary -j .text infile outfile`
# to copy out the .text section
# since its also only used for generated shellcode which shouldnt
# contain data sections, it additionally errors if any are present
import struct, sys

if len(sys.argv) != 3:
    print("usage: python3 %s infile outfile"%sys.argv[0])
    print("copies text section of infile to outfile")
    exit(1)

infile = sys.argv[1]
outfile = sys.argv[2]

LC_SEGMENT_64 = 0x19

raw = open(infile,"rb").read()

ncmds = struct.unpack_from("<I", raw, 0x10)[0]
off = 0x20
text = None
for i in range(ncmds):
    if struct.unpack_from("<I", raw, off)[0] == LC_SEGMENT_64:
        nsects = struct.unpack_from("<I", raw, off+0x40)[0]
        for j in range(nsects):
            sectname = struct.unpack_from("16s", raw, off+0x48+0x50*j)[0]
            segname = struct.unpack_from("16s", raw, off+0x48+0x50*j+0x10)[0]
            if sectname != b"__text".ljust(16, b"\0") and sectname != b"__unwind_info".ljust(16, b"\0"):
                raise Exception("bad section %s, check your source code for GLOB/static/etc"%sectname)
            if sectname == b"__text".ljust(16, b"\0") and segname == b"__TEXT".ljust(16, b"\0"):
                size = struct.unpack_from("<Q", raw, off+0x48+0x50*j+0x28)[0]
                offset = struct.unpack_from("<I", raw, off+0x48+0x50*j+0x30)[0]
                text = raw[offset:offset+size]
    off += struct.unpack_from("<I", raw, off+4)[0] # cmdsize

if text is None:
    print("couldnt find text section")
    exit(1)

open(outfile,"wb").write(text)
