
# Hollowell: A Scalable ELF Compression & Obfuscation Shell

**Hollowell** is a sophisticated user-mode ELF packer designed to protect binaries from static analysis. It dissects a target ELF executable into encrypted, compressed chunks and embeds them into a "Loader Stub." At runtime, the loader reconstructs the original binary entirely in memory, resolves dependencies, performs relocations, and transfers control to the Original Entry Point (OEP).

-----

## Core Features

* **Granular Dissection:** Unlike simple packers that encrypt the whole file, Hollowell splits the ELF into its functional components: ELF Header, Program Headers, and individual `PT_LOAD` segments.
* **Dual-Layer Protection:** \* **Compression:** Gzip (via `zlib`) to reduce the footprint and break signature-based detection.
    * **Obfuscation:** XOR-based stream cipher using SHA-256 derived keys to prevent static string/code extraction.
* **Reflective Memory Loading:** The target binary never touches the disk in its original form. The loader maps segments using `mmap` and `mprotect`.
* **Dynamic Linking Support:** A custom `sot` (Shared Object Table) management system handles `DT_NEEDED` libraries and performs manual symbol relocations (`R_X86_64_64`, `GLOB_DAT`, `JUMP_SLOT`, etc.).
* **Environment Transparency:** Patching of the **Auxiliary Vector (auxv)** ensures the loaded binary can correctly identify its own program headers and entry point.

-----

## Technical Architecture

The project is divided into three main components:

### 1\. The Divider (Rust)

The "Pre-processor." It uses the `goblin` crate to parse the target ELF.

* It extracts the `Ehdr` and `Phdrs`.
* It identifies all `PT_LOAD` segments.
* Each part is Gzipped and XOR-obfuscated with a user-provided seed.
* **Output:** Multiple `.bin` files (e.g., `ehdr.bin`, `0x400000.bin`).

### 2\. The Hexer (Rust)

The "Serializer." It converts binary blobs into C source code.

* It takes the `.bin` files and generates a C file containing `static const unsigned char` arrays.
* It generates an `iter_chunks` function, allowing the C Loader to iterate through embedded resources without knowing their count or names at compile time.

### 3\. The Loader (C & Assembly)

The "Stub." This is the engine that executes the protected payload.

* **`entry.S`**: A low-level entry point (`_emain`) that captures `argc`, `argv`, `envp`, and the `auxv` from the stack before passing them to the C logic.
* **`loader.c`**:
    1.  Iterates through embedded chunks to find the decryption seed.
    2.  Deobfuscates and decompresses the ELF/Program headers.
    3.  Allocates memory for the target binary and maps segments.
    4.  Loads required shared libraries via `dlopen`.
    5.  Resolves symbols and processes **RELA** and **RELR** relocations.
    6.  Fixes the `auxv` to point to the new memory-mapped headers.
    7.  Jumps to the OEP.

-----

## Quick Start

### Prerequisites

* **Arch Linux** (Recommended)
* `clang`, `make`, `cargo`
* `zlib` development headers

### Build the Toolchain

```bash
# Build the Rust divider and hexer
make bin
```

### Pack a Target Binary

To pack a simple binary (e.g., `/usr/bin/ls`) with the seed "my\_secret\_key":

```bash
# Inside the loader directory
make T=/usr/bin/ls KEY=my_secret_key
```

This will:

1.  Run `divider` on `ls`.
2.  Run `hexer` to convert `ls` chunks into code.
3.  Compile the `loader` with the embedded `ls` payload.

### Run

```bash
./loader/loader [arguments]
```

-----

## Extension & Development

Hollowell is designed to be highly scalable. Here are suggested directions for expansion:

* **Anti-Analysis:** Add `ptrace` checks or timing loops in `entry.S` to detect debuggers.
* **Advanced Obfuscation:** Replace the XOR cipher with a more robust algorithm like AES-GCM or implement Control Flow Flattening (CFF) during the `hexer` phase.
* **Polymorphism:** Modify the `hexer` to generate slightly different C code structures each time to change the Loader's signature.
* **TLS Support:** Implement Thread Local Storage (TLS) initialization in the loader to support complex C++ applications.

-----