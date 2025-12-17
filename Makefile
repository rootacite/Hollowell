
MODULES = obj loader-rs

CC = clang
CXX = clang++
CARGO = cargo

TARGETS = loader

defconfig: all

all: $(TARGETS)

framework: bin

dirs:
	mkdir -p bin
	mkdir -p obj

bin: dirs
	$(CARGO) build -j 28
	cp /tmp/rust-target-hwel/x86_64-unknown-linux-gnu/debug/hexer ./bin/
	cp /tmp/rust-target-hwel/x86_64-unknown-linux-gnu/debug/divider ./bin/

loader: bin
	$(MAKE) -C obj all
	$(MAKE) -C loader-rs all

clean:
	$(CARGO) clean
	@echo "--- Cleaning submodules ---"; for dir in $(MODULES); do $(MAKE) -C $$dir clean; done
	rm -f bin/*

.PHONY: all clean run dirs bin loader framework $(MODULES)
