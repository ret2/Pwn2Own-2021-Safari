# set pipefail so piped commands' errors arent ignored
SHELL = /bin/bash -o pipefail

SCFLAGS = -Wall -c -Os -fno-stack-protector -mno-sse -fno-unwind-tables -fno-exceptions

.PHONY: eop
eop: ksc
	clang eop.c eop_common.c -o eop -Wall -Os -framework IOKit -framework CoreFoundation

.PHONY: ksc
ksc:
	clang kernel_sc.c -o kernel_sc.o $(SCFLAGS)
	ld kernel_sc.o -o kernel_sc -dylib
	python3 objcopy.py kernel_sc kernel_sc.bin
	(echo GLOB && xxd -i kernel_sc.bin) | grep -v len > kernel_sc.h
	rm kernel_sc.o kernel_sc kernel_sc.bin
