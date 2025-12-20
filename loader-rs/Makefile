
CARGO = cargo

TARGETS = chain

defconfig: all

all: $(TARGETS)

chain:
	$(CARGO) build -j 28 -q
	cp /tmp/rust-target-hwel-chain/x86_64-unknown-linux-gnu/debug/chain ../bin/

clean:
	rm -f ../bin/chain
	$(CARGO) clean

.PHONY: chain all clean run dirs bin loader framework $(MODULES)