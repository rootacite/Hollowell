
CC = clang
CXX = clang++
LD = clang

TARGETS = obj

defconfig: all

all: $(TARGETS)

obj:
	mkdir -p /tmp/hollow
	cp ../bin/divider /tmp/hollow
	cp ../bin/hexer /tmp/hollow

	/tmp/hollow/divider /tmp/hollow  $(T) $(KEY)
	/tmp/hollow/hexer $$(find /tmp/hollow -type f -name "*.bin" -exec printf "%s " {} +)
	rm -f /tmp/hollow/*


clean:
	rm -f $(TARGETS) $(OBJS) *.o *.bin


.PHONY: all clean obj $(MODULES)