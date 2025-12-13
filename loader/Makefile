
CC = clang
CXX = clang++
LD = clang

TARGETS = loader
OBJS = loader.o entry.o sot.o deobfuscate.o

CFLAGS = -fPIC -c -O3 -g
LDFLAGS = -pie -Wl,-e,_emain -Wl,--no-gc-sections -lz
ASFLAGS = -c -g

all: $(TARGETS)

inner:
	../bin/divider $(T) $(KEY)
	sync
	../bin/hexer $$(find . -type f -name "*.bin" -exec printf "%s " {} +)
	rm -f *.bin

loader: $(OBJS) inner
	$(LD) $(LDFLAGS) -o loader $(wildcard *.o)
	objcopy --strip-all loader ../bin/$$(basename $(T))
	chmod u+x ../bin/$$(basename $(T))

loader.o: loader.c
	$(CC) $(CFLAGS) -o $@ $<

sot.o: sot.c
	$(CC) $(CFLAGS) -o $@ $<

deobfuscate.o: deobfuscate.c
	$(CC) $(CFLAGS) -o $@ $<

entry.o: entry.S
	$(AS) $(ASFLAGS) -o $@ $<

clean:
	rm -f $(TARGETS) $(OBJS) *.o *.bin


.PHONY: all clean run loader inner $(MODULES)