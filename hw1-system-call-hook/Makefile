CC      := gcc
CFLAGS  := -fPIC -Wall -Wextra -O0 -g
LDFLAGS := -shared -lc -ldl -nostartfiles -lbfd -lopcodes -lcapstone
ASM     := nasm
ASM_SRCS := $(wildcard *.asm)
ASM_OBJS := $(ASM_SRCS:.asm=.o)
BINS     := $(ASM_SRCS:.asm=.bin)
HEADERS  := $(BINS:.bin=_blob.h)

all: libzpoline.so.1 libzpoline.so.2 libzpoline.so logger.so libex3hook.so

%.o: %.asm
	$(ASM) -f elf64 $< -o $@

%.bin: %.o
	objcopy -O binary $< $@

%_blob.h: %.bin
	xxd -i $< > $@

test.so: test.c test.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

logger.so: logger.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

libex3hook.so: libex3hook.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

libzpoline.so: zpoline.c syscall_hook.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

libzpoline.so.2: zpoline2.c syscall_hook2.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

libzpoline.so.1: zpoline1.c print_blob.h
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	rm -f libzpoline.so.1 libzpoline.so.2 libzpoline.so syscall_hook.o logger.so

test:
	LD_PRELOAD=./libzpoline.so.1 ./ex1 