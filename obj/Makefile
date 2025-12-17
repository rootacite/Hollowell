
CC = clang
CXX = clang++
LD = clang

TARGETS = obj

defconfig: all

all: $(TARGETS)

obj:
	cd ../obj
	../bin/divider $(T) $(KEY)
	sync
	../bin/hexer $$(find . -type f -name "*.bin" -exec printf "%s " {} +)
	rm -f *.bin


clean:
	rm -f $(TARGETS) $(OBJS) *.o *.bin


.PHONY: all clean obj $(MODULES)