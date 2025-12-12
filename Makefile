
MODULES = loader

CC = clang
CXX = clang++
CARGO = cargo

TARGETS = loader
T = ../bin/ssh

defconfig: all

all: $(TARGETS)

dirs:
	mkdir -p bin

bin: dirs
	$(CARGO) build -j 28
	cp /bin/ssh ./bin/
	cp /tmp/rust-target-hwel/x86_64-unknown-linux-gnu/debug/hexer ./bin/
	cp /tmp/rust-target-hwel/x86_64-unknown-linux-gnu/debug/divider ./bin/

loader: bin
	$(MAKE) -C loader all

clean:
	@echo "--- Cleaning submodules ---"; for dir in $(MODULES); do $(MAKE) -C $$dir clean; done
	rm -f bin/*

.PHONY: all clean run dirs bin loader $(MODULES)
