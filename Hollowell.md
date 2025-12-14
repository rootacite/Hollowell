# Project Dump

- Root: `/home/acite/Deeppin/Hollowell`
- Generated: 2025-12-14 20:42:11

## Table of Contents

| # | Path | Size (bytes) | Modified | Status |
|---:|------|-------------:|----------|--------|
| 1 | `Cargo.lock` | 7585 | 2025-12-13 12:58:34 | skipped (ignored) |
| 2 | `Cargo.toml` | 321 | 2025-12-13 12:58:34 | included |
| 3 | `LICENSE` | 34523 | 2025-12-13 00:41:17 | skipped (ignored) |
| 4 | `Makefile` | 531 | 2025-12-13 13:55:24 | included |
| 5 | `README.md` | 4130 | 2025-12-13 15:16:22 | skipped (ignored) |
| 6 | `bin/divider` | 11808896 | 2025-12-14 20:36:05 | skipped (binary) |
| 7 | `bin/gnome-calculator` | 276768 | 2025-12-14 20:36:05 | skipped (binary) |
| 8 | `bin/hexer` | 5088200 | 2025-12-14 20:36:05 | skipped (binary) |
| 9 | `divider/README.md` | 2151 | 2025-12-13 13:14:06 | included |
| 10 | `divider/divider.rs` | 2693 | 2025-12-13 13:33:47 | included |
| 11 | `divider/elf.rs` | 3640 | 2025-12-11 22:54:59 | skipped (ignored) |
| 12 | `hexer/hexer.rs` | 5552 | 2025-12-14 19:05:55 | included |
| 13 | `loader/0x0.o` | 260560 | 2025-12-14 20:36:05 | skipped (binary) |
| 14 | `loader/Makefile` | 839 | 2025-12-14 20:04:07 | included |
| 15 | `loader/deobfuscate.c` | 4099 | 2025-12-14 20:02:14 | included |
| 16 | `loader/deobfuscate.h` | 706 | 2025-12-14 19:32:56 | included |
| 17 | `loader/deobfuscate.o` | 13816 | 2025-12-14 20:36:05 | skipped (binary) |
| 18 | `loader/entry.S` | 1070 | 2025-12-14 03:34:11 | included |
| 19 | `loader/entry.o` | 2504 | 2025-12-14 20:36:05 | skipped (binary) |
| 20 | `loader/loader` | 301000 | 2025-12-14 20:36:05 | skipped (binary) |
| 21 | `loader/loader.c` | 5390 | 2025-12-14 20:11:18 | included |
| 22 | `loader/loader.h` | 268 | 2025-12-14 19:32:03 | included |
| 23 | `loader/loader.o` | 17472 | 2025-12-14 20:36:05 | skipped (binary) |
| 24 | `loader/relocation.c` | 6761 | 2025-12-14 20:18:29 | included |
| 25 | `loader/relocation.h` | 180 | 2025-12-14 19:31:36 | included |
| 26 | `loader/relocation.o` | 14080 | 2025-12-14 20:36:05 | skipped (binary) |
| 27 | `loader/sot.c` | 2128 | 2025-12-14 19:11:32 | included |
| 28 | `loader/sot.h` | 351 | 2025-12-13 02:39:29 | included |
| 29 | `loader/sot.o` | 8480 | 2025-12-14 20:36:05 | skipped (binary) |

---

## File Contents

### Cargo.toml

- Size: 321 bytes
- Modified: 2025-12-13 12:58:34

```text
[package]
name = "Hollowell"
version = "0.1.0"
edition = "2024"

[dependencies]
anyhow = "1.0.100"
flate2 = "1.1.5"
goblin = "0.10.4"
memmap2 = "0.9.9"
ouroboros = "0.18.5"
plain = "0.2.3"
sha2 = "0.10.9"

[[bin]]
name = "divider"
path = "divider/divider.rs"

[[bin]]
name = "hexer"
path = "hexer/hexer.rs"

[workspace]


```

### Makefile

- Size: 531 bytes
- Modified: 2025-12-13 13:55:24

```text

MODULES = loader

CC = clang
CXX = clang++
CARGO = cargo

TARGETS = loader

defconfig: all

all: $(TARGETS)

framework: bin

dirs:
	mkdir -p bin

bin: dirs
	$(CARGO) build -j 28
	cp /tmp/rust-target-hwel/x86_64-unknown-linux-gnu/debug/hexer ./bin/
	cp /tmp/rust-target-hwel/x86_64-unknown-linux-gnu/debug/divider ./bin/

loader: bin
	$(MAKE) -C loader all

clean:
	@echo "--- Cleaning submodules ---"; for dir in $(MODULES); do $(MAKE) -C $$dir clean; done
	rm -f bin/*

.PHONY: all clean run dirs bin loader framework $(MODULES)

```

### divider/README.md

- Size: 2151 bytes
- Modified: 2025-12-13 13:14:06

```text
# ELF Divider

A command-line utility written in Rust to dissect an ELF (Executable and Linkable Format) file into its core components: the ELF Header, the Program Headers, and all `PT_LOAD` segments. Each resulting component is compressed using Gzip and then obfuscated using a simple XOR cipher derived from a user-provided seed.

This tool is useful for **binary analysis**, **malware packing/unpacking research**, and **reverse engineering** workflows where isolating and securely storing ELF components is necessary.

## Features

* **ELF Dissection:** Accurately extracts the ELF Header (`Ehdr`), Program Headers (`Phdrs`), and all `PT_LOAD` segments.
* **Gzip Compression:** Each extracted component is compressed to reduce file size.
* **XOR Obfuscation:** A simple stream cipher based on SHA-256 is used to obfuscate the compressed data, requiring a key (`seed`) for later recovery.

## How it Works

The utility processes the input ELF file and performs the following steps:

1.  **Parsing:** Uses the `goblin` crate (implicitly, through the `ExecuteLinkFile::prase` method) to locate the positions and sizes of the ELF Header, Program Headers, and `PT_LOAD` segments.
2.  **Extraction & Compression:**
    * The raw bytes of the ELF Header are extracted and written to `ehdr.bin`.
    * The raw bytes of the Program Headers are extracted and written to `phdr.bin`.
    * Each `PT_LOAD` segment (based on `p_offset` and `p_filesz`) is extracted and written to a file named after its virtual address (`0x...bin`).
    * **Crucially:** Before writing, the raw component data is compressed using **Gzip**.
3.  **Obfuscation:**
    * The `confuse_data` function is applied to the **compressed** data.
    * A 32-byte XOR key is generated by taking the **SHA-256 hash** of the provided `seed` string.
    * The compressed data is then XORed byte-by-byte with the SHA-256 key, cycling the key every 32 bytes (`data[i] = data[i] ^ key[i % 32]`).
4.  **Writing:** The final compressed and obfuscated data is written to the corresponding output file.

## Usage

### Prerequisites

* Rust toolchain installed.

### Build

```bash
cargo build --release
```

### divider/divider.rs

- Size: 2693 bytes
- Modified: 2025-12-13 13:33:47

```text
mod elf;

use anyhow::*;
use std::io::Write;
use std::mem::size_of;
use std::{env, fs};
use std::ops::DerefMut;
use flate2::Compression;
use flate2::write::GzEncoder;

use plain::Plain;
use sha2::{Digest, Sha256};
use crate::elf::ExecuteLinkFile;

#[repr(transparent)]
pub struct Header(goblin::elf::Header);
unsafe impl Plain for Header {}

#[allow(unused)]
const SUCC: &str = "\x1b[32m[+]\x1b[0m";
#[allow(unused)]
const FAIL: &str = "\x1b[31m[-]\x1b[0m";
#[allow(unused)]
const ALER: &str = "\x1b[31m[!]\x1b[0m";
#[allow(unused)]
const INFO: &str = "\x1b[34m[*]\x1b[0m";

fn confuse_data(data: &mut [u8], seed: &str) -> Result<()>
{
    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());
    let key = hasher.finalize();

    fs::write("seed.bin", key.as_slice())?;

    for i in 0..data.len() {
        let b = data[i] ^ key[i % 32];
        data[i] = b;
    }

    Ok(())
}

fn write_compressed(path: &str, content: &[u8], seed: &str) -> Result<()> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(content)?;
    let mut compressed = encoder.finish()?;

    confuse_data(compressed.deref_mut(), seed)?;
    fs::write(path, compressed)?;
    Ok(())
}

fn main() -> Result<()> {
    let arg = env::args().into_iter().collect::<Vec<String>>();
    if arg.len() < 3 {
        return Err(anyhow!(
            "Insufficient parameters. \nUsage: divider <file> <seed>. \n<file>: The ELF file you want to divide. \n<seed>: The confuse key."
        ));
    }

    let elf_path = arg[1].clone();
    let elf_parser =
        ExecuteLinkFile::prase(&elf_path).expect(&format!("{FAIL} Is this really a elf ??"));
    let elf_data = fs::read(elf_path)?;

    let b_ehdr = &elf_data[0..size_of::<Header>()];
    write_compressed("ehdr.bin", &b_ehdr, &arg[2])?;
    println!("{SUCC} Wrote {} bytes to ehdr.bin", b_ehdr.len());

    let off_phdr = elf_parser.borrow_elf().header.e_phoff as usize;
    let sz_phdr = elf_parser.borrow_elf().header.e_phnum as usize
        * elf_parser.borrow_elf().header.e_phentsize as usize;
    let b_phdr = &elf_data[off_phdr..off_phdr + sz_phdr];
    write_compressed("phdr.bin", &b_phdr, &arg[2])?;
    println!("{SUCC} Wrote {} bytes to phdr.bin", b_phdr.len());

    for p in elf_parser
        .get_loads()
        .expect(&format!("{FAIL} An elf file without PT_LOADs ?"))
    {
        let b_load = &elf_data[p.p_offset as usize..(p.p_offset + p.p_filesz) as usize];
        write_compressed(&format!("{:#0x}.bin", p.p_vaddr), b_load, &arg[2])?;
        println!(
            "{SUCC} Wrote {} bytes to {:#0x}.bin",
            b_load.len(),
            p.p_vaddr
        );
    }

    Ok(())
}

```

### hexer/hexer.rs

- Size: 5552 bytes
- Modified: 2025-12-14 19:05:55

```text
use anyhow::Result;
use anyhow::anyhow;
use std::io::ErrorKind;
use std::process::Command;
use std::{env, fs, io, path};

fn get_filename_without_extension<P: AsRef<path::Path>>(path: P) -> Result<String> {
    let path = path.as_ref();

    if !path.exists() {
        return Err(anyhow!("File does not exist: {:?}", path));
    }

    if !path.is_file() {
        return Err(anyhow!("Path is not a file: {:?}", path));
    }

    path.file_stem()
        .and_then(|stem| stem.to_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("Unable to extract filename from path: {:?}", path))
}

fn get_filepath<P: AsRef<path::Path>>(path: P) -> Result<String> {
    let p = path.as_ref();

    if !p.exists() {
        return Err(anyhow!(
            "Path '{}' does not exist or is inaccessible.",
            p.display()
        ));
    }

    match p.parent() {
        Some(parent_path) => match parent_path.to_str() {
            Some(s) => Ok(s.to_string()),
            None => Err(anyhow!(
                "Parent path '{}' contains invalid non-UTF-8 characters.",
                parent_path.display()
            )),
        },
        None => Err(anyhow!(
            "Path '{}' cannot retrieve parent directory.",
            p.display()
        )),
    }
}

fn compile_target(name: &str) -> Result<(), io::Error> {
    let input_file = format!("{}.c", name);
    let output_file = format!("{}.o", name);

    let output = Command::new("clang")
        .arg("-c")
        .arg(&input_file)
        .arg("-o")
        .arg(&output_file)
        .output();

    match output {
        Ok(output) => {
            if output.status.success() {
                // Command succeeded
                Ok(())
            } else {
                // Command executed but returned non-zero exit code (e.g., compile error)
                eprintln!("Clang compilation failed for {}.", name);
                eprintln!("Exit Code: {:?}", output.status.code());
                eprintln!("Stderr:\n{}", String::from_utf8_lossy(&output.stderr));
                Err(io::Error::new(
                    ErrorKind::Other,
                    format!(
                        "Clang compilation failed for {} with exit code: {:?}",
                        name,
                        output.status.code()
                    ),
                ))
            }
        }
        Err(e) => {
            // IO Error (e.g., clang not found)
            if e.kind() == ErrorKind::NotFound {
                eprintln!(
                    "Error: 'clang' executable not found. Ensure it is installed and in $PATH."
                );
            } else {
                eprintln!("IO error while executing command: {:?}", e);
            }
            Err(e)
        }
    }
}

pub fn parse_hex_to_u64(hex_str: &str) -> Result<u64, std::num::ParseIntError> {
    let processed_str = if hex_str.starts_with("0x") || hex_str.starts_with("0X") {
        &hex_str[2..]
    } else {
        hex_str
    };

    u64::from_str_radix(processed_str, 16)
}

fn main() -> Result<()> {
    let mut arg = env::args().into_iter().collect::<Vec<String>>();
    if arg.len() < 2 {
        return Err(anyhow!("No operation object."));
    }

    arg.remove(0);

    let first_input = &arg[0];
    let name = get_filename_without_extension(first_input)?;
    let output_path = format!("{}/{}.c", get_filepath(first_input)?, name);
    let mut c_code: String = "".to_string();

    c_code.push_str(
        r#"
struct ChunkInfo {
    unsigned char *data;
    unsigned long size;
    char* name;
    unsigned long vdata;
};"#,
    );

    let mut iter_fun = r#"
typedef struct ChunkInfo ChunkInfo_t;
typedef int(*chunk_callback)(const ChunkInfo_t*, void*);

int iter_chunks(chunk_callback cb, void* data)
{
    ChunkInfo_t chunks[] = {
"#
    .to_string();

    c_code.push_str("\n\n");

    for f in &arg {
        let symbol_name = get_filename_without_extension(&f)?;
        let bin_data = fs::read(f)?;

        c_code.push_str(&format!("static const unsigned char _{}[] = {}", symbol_name, "{"));

        for b in bin_data.iter() {
            c_code.push_str(&format!("{:#0x}, ", b));
        }

        c_code.push_str("}; \n");
        c_code.push_str(&format!(
            "static const unsigned long _{}_size = {:#0x}; \n",
            symbol_name,
            bin_data.len()
        ));

        c_code.push_str(&format!(
            "static const char* _{}_name = \"{}\"; \n",
            symbol_name, symbol_name
        ));
        c_code.push_str(&format!(
            "static const unsigned long _{}_vdata = {:#0x}; \n",
            symbol_name,
            parse_hex_to_u64(&symbol_name).unwrap_or_else(|_| 0)
        ));

        iter_fun.push_str(&format!(
            "{} .data = (unsigned char*)&_{}, .size = {:#0x}, .name = (char*)_{}_name, .vdata = {:#0x} {}",
            "        {",
            symbol_name,
            bin_data.len(),
            symbol_name,
            parse_hex_to_u64(&symbol_name).unwrap_or_else(|_| 0),
            "}, \n"
        ));
    }

    iter_fun.push_str(
        &r#"
    };
    int chunks_count = #$PLACEHOLDER$#;

    for (int i = 0; i < chunks_count; i += 1) {
        int r = cb(&chunks[i], data);
        if (r == 0) return 1;
    }

    return 0;
}
    "#
        .replace("#$PLACEHOLDER$#", &format!("{}", arg.len())),
    );
    c_code.push_str(&iter_fun);
    
    

    fs::write(&output_path, c_code.as_bytes())?;

    compile_target(&name)?;
    fs::remove_file(&output_path)?;

    Ok(())
}

```

### loader/Makefile

- Size: 839 bytes
- Modified: 2025-12-14 20:04:07

```text

CC = clang
CXX = clang++
LD = clang

TARGETS = loader
OBJS = loader.o entry.o sot.o deobfuscate.o relocation.o

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

relocation.o: relocation.c
	$(CC) $(CFLAGS) -o $@ $<

entry.o: entry.S
	$(AS) $(ASFLAGS) -o $@ $<

clean:
	rm -f $(TARGETS) $(OBJS) *.o *.bin


.PHONY: all clean run loader inner $(MODULES)
```

### loader/deobfuscate.c

- Size: 4099 bytes
- Modified: 2025-12-14 20:02:14

```text

#include "deobfuscate.h"

#include <stdlib.h>
#include <string.h>
#include <zlib.h>

// ................Embedded..................
struct ChunkInfo {
    unsigned char *data;
    unsigned long size;
    char* name;
    unsigned long vdata;
};

typedef struct ChunkInfo ChunkInfo_t;
typedef int(*chunk_callback)(const ChunkInfo_t*, void*);

extern int iter_chunks(chunk_callback cb, void*);

struct cb_io {
    char* name;
    uint64_t vdata;
    const unsigned char *addr;
    uint64_t size;
};
// ............................................


static int cb_find_vdata(const ChunkInfo_t *ci, void *data) {
    struct cb_io *r = data;

    if (ci->vdata == r->vdata) {
        r->addr = ci->data;
        r->size = ci->size;
        return 0;
    }

    return 1;
}

static int cb_find_name(const ChunkInfo_t *ci, void *data) {
    struct cb_io *r = data;

    if (strcmp(ci->name, r->name) == 0) {
        r->addr = ci->data;
        r->size = ci->size;
        return 0;
    }

    return 1;
}

static void deobfuscate_at(const uint8_t* seed, const uint8_t* deobfuscated, uint8_t* buffer, const size_t size) {
    for (int i = 0; i < size; i++) {
        buffer[i] = deobfuscated[i] ^ seed[i % 32];
    }
}

static size_t decompress_gzip(const uint8_t *compressed_data, const size_t compressed_len, uint8_t **decompressed_data) {
    z_stream strm = {0};

    strm.next_in = (Bytef *)compressed_data;
    strm.avail_in = (uInt)compressed_len;

    if (inflateInit2(&strm, 16 + MAX_WBITS) != Z_OK) {
        return 0;
    }

    size_t out_capacity = compressed_len * 2 + 1024;
    uint8_t *out_ptr = (uint8_t *)malloc(out_capacity);
    if (!out_ptr) {
        inflateEnd(&strm);
        return 0;
    }

    int ret;
    size_t total_out = 0;

    do {
        if (total_out >= out_capacity) {
            size_t new_capacity = out_capacity * 2;
            uint8_t *new_ptr = (uint8_t *)realloc(out_ptr, new_capacity);
            if (!new_ptr) {
                free(out_ptr);
                inflateEnd(&strm);
                return 0;
            }
            out_ptr = new_ptr;
            out_capacity = new_capacity;
        }

        strm.next_out = out_ptr + total_out;
        strm.avail_out = (uInt)(out_capacity - total_out);

        ret = inflate(&strm, Z_NO_FLUSH);

        total_out = strm.total_out;

        if (ret == Z_MEM_ERROR || ret == Z_DATA_ERROR) {
            free(out_ptr);
            inflateEnd(&strm);
            return 0;
        }
    } while (ret != Z_STREAM_END);

    inflateEnd(&strm);

    *decompressed_data = out_ptr;
    return total_out;
}

size_t get_chunk_by_name(_in const char *name, _out uint8_t **ppData, _in const uint8_t *seed) {
    if (!name || !ppData)
        return 0;

    struct cb_io r = { .name = (char*)name, .addr = 0 };
    const int found = iter_chunks(cb_find_name, &r);
    if (!found)
        return 0;

    if (!seed) {
        *ppData = (uint8_t*)r.addr;
        return r.size;
    }

    uint8_t *compressed_buffer = malloc(r.size);
    if (!compressed_buffer)
        return 0;

    deobfuscate_at(seed, r.addr, compressed_buffer, r.size);

    uint8_t *buffer = NULL;
    const size_t buffer_size = decompress_gzip(compressed_buffer, r.size, &buffer);
    free(compressed_buffer);

    if (!buffer_size)
        return 0;

    *ppData = buffer;

    return buffer_size;
}

size_t get_chunk_by_vdata(_in uint64_t vdata, _out uint8_t **ppData, _in const uint8_t *seed) {
    if (!ppData)
        return 0;

    struct cb_io r = { .vdata = vdata, .addr = 0 };
    const int found = iter_chunks(cb_find_vdata, &r);
    if (!found)
        return 0;

    if (!seed) {
        *ppData = (uint8_t*)r.addr;
        return r.size;
    }

    uint8_t *compressed_buffer = malloc(r.size);
    if (!compressed_buffer)
        return 0;

    deobfuscate_at(seed, r.addr, compressed_buffer, r.size);

    uint8_t *buffer = NULL;
    const size_t buffer_size = decompress_gzip(compressed_buffer, r.size, &buffer);
    free(compressed_buffer);

    if (!buffer_size)
        return 0;

    *ppData = buffer;

    return buffer_size;
}

```

### loader/deobfuscate.h

- Size: 706 bytes
- Modified: 2025-12-14 19:32:56

```text

#pragma once

#include <stddef.h>
#include <stdint.h>
#include "loader.h"

#define CHUNK_SIZE 16384

/**
 *
 * @param name chunk name
 * @param ppData output pointer to data, needs to free
 * @param seed the deobfuscate seed, set to NULL to return raw data
 * @return size of data, returns 0 when fail
 */
size_t get_chunk_by_name(_in const char *name, _out uint8_t **ppData, _in const uint8_t *seed);


/**
 *
 * @param vdata chunk vdata
 * @param ppData output pointer to data, needs to free
 * @param seed the deobfuscate seed, set to NULL to return raw data
 * @return size of data, returns 0 when fail
 */
size_t get_chunk_by_vdata(_in uint64_t vdata, _out uint8_t **ppData, _in const uint8_t *seed);
```

### loader/entry.S

- Size: 1070 bytes
- Modified: 2025-12-14 03:34:11

```text

# entry.S

.global _emain
.global main
.hidden main

.section .data, "aw", @progbits
_envp:
.8byte 0
_auxv:
.8byte 0
_pargc:
.8byte 0

.text

_emain:
    pushq   %rdi
    pushq   %rsi
    pushq   %rcx
    pushq   %rdx

    addq    $32, %rsp

    movq    %rsp, _pargc(%rip)
    movq    %rsp, %rdi
    movq    (%rdi), %rdi
    incq    %rdi
    imulq   $8, %rdi, %rdi
    movq    %rsp, %rsi
    addq    $8, %rsi
    addq    %rdi, %rsi
    movq    %rsi, _envp(%rip)

    subq    $32, %rsp
.Lauxv_loop:
    movq    (%rsi), %rdi
    test    %rdi, %rdi
    je     .Lauxv
    addq    $8, %rsi
    jmp    .Lauxv_loop

.Lauxv:
    addq    $8, %rsi
    movq    %rsi, _auxv(%rip)

    pushq   %rbp
    movq    %rsp, %rbp

    sub     $16, %rsp
    andq    $0xfffffffffffffff0, %rsp
    movq    _auxv(%rip), %rdi
    call    loader

    movq    %rbp, %rsp
    popq    %rbp

    popq    %rdx
    popq    %rcx
    popq    %rsi
    popq    %rdi

    test    %rax, %rax
    je      .Lexit
    jmp     *%rax

.Lexit:
    mov     $60, %rax
    mov     $0, %rdi
    syscall

main:
    ret

```

### loader/loader.c

- Size: 5390 bytes
- Modified: 2025-12-14 20:11:18

```text

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <link.h>

#include <stdlib.h>

#include "loader.h"
#include "deobfuscate.h"
#include "relocation.h"

static const char* SUCC = "\x1b[32m[+]\x1b[0m";
static const char* INFO = "\x1b[34m[*]\x1b[0m";

static uint8_t *seed = NULL;

static void do_parse_auxv(Elf64_auxv_t* auxv, Elf64_auxv_t* auxv_table[]) {
    printf("%s Current pid = %d\n", INFO, getpid());
    for (int i = 0; auxv[i].a_type != AT_NULL; i++) {
        auxv_table[auxv[i].a_type] = &auxv[i];
    }
}

static int do_load_segment(
    void* base,
    const Elf64_Phdr* p
    )
{
    if (p->p_type != PT_LOAD)
        return 0;

    const uint64_t load_base = (uint64_t)base + p->p_vaddr;
    uint8_t *buffer = NULL;
    const size_t buffer_size = get_chunk_by_vdata(p->p_vaddr, &buffer, seed);
    if (!buffer || !buffer_size)
        return 1;

    memcpy((void*)load_base, buffer, buffer_size);
    free(buffer);

    printf("%s Segment(vaddr = %lx, memsz = %lx) loaded to %lx\n", SUCC, p->p_vaddr, p->p_memsz, load_base);

    const uint64_t load_page = load_base & ~0xfffULL;
    uint64_t page_size = p->p_memsz + (load_base & 0xfffULL);
    uint8_t prot = 0;
    if (p->p_flags & PF_X)
        prot |= PROT_EXEC;
    if (p->p_flags & PF_W)
        prot |= PROT_WRITE;
    if (p->p_flags & PF_R)
        prot |= PROT_READ;

    page_size += 0x1000ULL;
    page_size &= ~0xfffULL;

    mprotect((void*)load_page, page_size, prot);
    printf("%s Protect of %lu page(s) at %lx adjusted to %d. \n", SUCC, page_size / 0x1000, load_page, prot);

    return 0;
}

uint64_t do_load(
    _in const Elf64_Ehdr* ehdr,
    _in const Elf64_Phdr* phdr,
    _out Elf64_Dyn **dynamic
    ) {
    uint64_t image_size = 0;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        const Elf64_Phdr* p = &phdr[i];

        if (p->p_type == PT_LOAD && p->p_vaddr + p->p_memsz >= image_size)
            image_size = p->p_vaddr + p->p_memsz;
    }

    image_size += 0x1000ULL;
    image_size &= ~0xfffULL;
    printf("%s Image size determined to %lx\n", INFO, image_size);

    void *image_base = mmap(NULL, image_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    printf("%s Image base address determined to %p\n", INFO, image_base);

    *dynamic = image_base;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        const Elf64_Phdr* p = &phdr[i];
        if (p->p_type == PT_DYNAMIC) {
            *dynamic = (Elf64_Dyn*)((uint64_t)*dynamic + p->p_vaddr);
            printf("%s Dynamic address determined to %lx\n", INFO, (uint64_t)*dynamic);
            continue; // PT_DYNAMIC is covered by a PT_LOAD, so continue here.
        }
        if (do_load_segment(image_base, p))
            return 0;
    }

    return (uint64_t)image_base;
}

JumpSlot loader(Elf64_auxv_t* auxv) {
    Elf64_auxv_t* auxv_table[100] = { NULL };
    do_parse_auxv(auxv, auxv_table);

    uint64_t sz = get_chunk_by_name("seed", &seed, NULL);
    if (!seed || !sz)
        return NULL;

    // Origin Ehdr
    Elf64_Ehdr* ehdr = NULL;
    sz = get_chunk_by_name("ehdr", (uint8_t**)&ehdr, seed);
    if (!ehdr || !sz)
        return NULL;

    // Origin Phdr
    Elf64_Phdr* phdr = NULL;
    sz = get_chunk_by_name("phdr", (uint8_t**)&phdr, seed);
    if (!phdr || !sz)
        return NULL;

    // Load segments
    Elf64_Dyn *dynamic = NULL;
    Elf64_Dyn *dynamic_table[50] = { NULL };
    const uint64_t inner_base = do_load(ehdr, phdr, &dynamic);
    if (!inner_base)
        return NULL;

    if (!do_relocate(inner_base, dynamic, dynamic_table))
        return NULL;
    
    const uint64_t oep = ehdr->e_entry + inner_base;

    if (auxv_table[AT_PHDR])
    {
        auxv_table[AT_PHDR]->a_un.a_val = (uint64_t)phdr;
        auxv_table[AT_PHENT]->a_un.a_val = ehdr->e_phentsize;
        auxv_table[AT_PHNUM]->a_un.a_val = ehdr->e_phnum;
    }

    if (auxv_table[AT_ENTRY])
    {
        auxv_table[AT_ENTRY]->a_un.a_val = oep;
    }

    for (struct link_map *lm = _r_debug.r_map; lm != NULL; lm = lm->l_next) {
        if (lm->l_name == NULL || lm->l_name[0] == '\0') {
            lm->l_addr = inner_base;
            lm->l_ld = dynamic;

            // link_map + 0x40 is ElfW(Dyn) *l_info, but this is internal to the dynamic linker.
            // Considering a cleaner approach.

            // Pseudocode code of __libc_start_main:
            // v12 = rtld_global;
            // v13 = rtld_global[20];
            // if ( v13 )
            // {
            //     v19 = environ;
            //     ((void (__fastcall *)(_QWORD, char **, _QWORD, void (*)(void), void (*)(void)))(*rtld_global + *(_QWORD *)(v13 + 8)))(
            //       (unsigned int)argc,
            //       ubp_av,
            //       environ,
            //       init,
            //       fini);
            //     v11 = v19;
            // }

            // __libc_start_main uses _rtld_global_ptr to get the main module's link_map,
            // then computes init functions from its data.
            // We must adjust this struct's data

            uint64_t* l_info = (uint64_t*)((uint8_t*)lm + 0x40);
            for (int i = 0; i < 40; i++) { // Iter to 40 to avoid DT_GNU_HASH_RED
                if (dynamic_table[i])
                    l_info[i] = (uint64_t)dynamic_table[i];
            }
        }
    }

    free(ehdr);
    return (void*)oep;
}
```

### loader/loader.h

- Size: 268 bytes
- Modified: 2025-12-14 19:32:03

```text

#pragma once
#include <elf.h>

#define _in
#define _out

uint64_t do_load(
    _in const Elf64_Ehdr* ehdr,
    _in const Elf64_Phdr* phdr,
    _out Elf64_Dyn **dynamic
    );

struct DtHashDummy {
    uint32_t nbucket;
    uint32_t nchain;
};

typedef void* JumpSlot;
```

### loader/relocation.c

- Size: 6761 bytes
- Modified: 2025-12-14 20:18:29

```text

#include "relocation.h"
#include "sot.h"
#include "loader.h"

#define _GNU_SOURCE

#include <stdio.h>
#include <elf.h>
#include <string.h>
#include <sys/mman.h>
#include <dlfcn.h>

#include <stdlib.h>

static const char* FAIL = "\x1b[31m[-]\x1b[0m";
static const char* INFO = "\x1b[34m[*]\x1b[0m";

static void do_rela_reloc(
    const uint64_t base,
    const Elf64_Rela *rela,
    const size_t count,
    const Elf64_Sym *dynsym,
    const uint64_t dynstr
    )
{
    for (int i = 0; i < count ; i++)
    {
        uint32_t sym_index = (rela[i].r_info >> 32) & 0xffffffff;
        const char* sym_name = (const char *)(dynstr + dynsym[sym_index].st_name);
        uint64_t sym_value = 0;
        uint64_t sym_sz = dynsym[sym_index].st_size;

        switch (rela[i].r_info & 0xffffffff)
        {
            case R_X86_64_64:
                sym_value = sot_symbol_lookup(sym_name);
                *(uint64_t*)(rela[i].r_offset + base) = sym_value + rela[i].r_addend;
                break;
            case R_X86_64_GLOB_DAT:
            case R_X86_64_JUMP_SLOT:
                sym_value = sot_symbol_lookup(sym_name);
                *(uint64_t*)(rela[i].r_offset + base) = sym_value;
                break;
            case R_X86_64_COPY:
                sym_value = sot_symbol_lookup(sym_name);
                memcpy((void*)(rela[i].r_offset + base), (void*)sym_value, sym_sz);
                break;
            case R_X86_64_RELATIVE:
                *(uint64_t*)(rela[i].r_offset + base) = base + rela[i].r_addend;
                break;
            default:
                break;
        }
    }
}

static void do_relr_reloc(
    const uint64_t base,
    const Elf64_Relr *relr,
    const size_t count
    )
{
    const size_t bits = (sizeof(Elf64_Relr) * 8) - 1; /* 63 on ILP64/typical x86_64 */
    uint64_t *where = NULL;

    for (size_t i = 0; i < count; ++i) {
        Elf64_Relr entry = relr[i];

        if ((entry & 1u) == 0) {
            uintptr_t addr = (uintptr_t)base + (uintptr_t)entry;
            where = (uint64_t *)addr;
            *where = *where + base;
            ++where;
        } else if (where) {
            uint64_t bitmap = (uint64_t)(entry >> 1);
            for (size_t b = 0; b < bits; ++b) {
                if (bitmap & 1u) {
                    where[b] = where[b] + base;
                }
                bitmap >>= 1;
            }

            where += bits;
        }
    }
}

static void do_parse_dynamic(
    const uint64_t base,
    Elf64_Dyn *dynamic,
    Elf64_Dyn *dynamic_table[]
    )
{
    for (int i = 0; dynamic[i].d_tag != DT_NULL; i++) {
        switch (dynamic[i].d_tag) {
            case DT_PLTGOT:
            case DT_HASH:
            case DT_GNU_HASH:
            case DT_STRTAB:
            case DT_SYMTAB:
            case DT_RELA:
            case DT_RELR:
            case DT_REL:
            case DT_JMPREL:
            case DT_VERDEF:
            case DT_VERNEED:
            case DT_VERSYM:
                dynamic[i].d_un.d_ptr += base;
                break;
            default:
                break;
        }

        if (dynamic[i].d_tag >= 50) {
            if (dynamic[i].d_tag == DT_GNU_HASH) {
                dynamic_table[DT_GNU_HASH_RED] = &dynamic[i];
            }
            continue;
        }

        dynamic_table[dynamic[i].d_tag] = &dynamic[i];
    }
}

static size_t gnu_hash_sym_count(
    const void *gnu_hash_base
    )
{
    if (!gnu_hash_base) return 0;

    const unsigned char *p = gnu_hash_base;
    const uint32_t *u32 = (const uint32_t *)p;

    uint32_t nbucket    = u32[0];
    uint32_t symoffset  = u32[1];
    uint32_t bloom_size = u32[2];

    const unsigned char *after_header = p + 4 * 4 + (size_t)bloom_size * 8;
    const uint32_t *buckets = (const uint32_t *)after_header;
    const uint32_t *chain = buckets + nbucket;

    uint32_t max_index = 0;
    int found_any = 0;

    for (uint32_t i = 0; i < nbucket; ++i) {
        uint32_t idx = buckets[i];
        if (idx == 0) continue;

        uint32_t cur = idx;
        while (1) {
            if (cur < symoffset) {
                break;
            }
            size_t chain_idx = (size_t)(cur - symoffset);
            uint32_t h = chain[chain_idx];
            if (cur > max_index) max_index = cur;
            found_any = 1;
            if (h & 1U) break; /* end of this bucket's chain */
            ++cur;
        }
    }

    if (!found_any) {
        return 0;
    }

    return (size_t)max_index + 1;
}

static int do_load_dependencies(
    const Elf64_Dyn *dynamic,
    Elf64_Dyn *dynamic_table[]
) {
    for (int i = 0; dynamic[i].d_tag != DT_NULL; i++) {
        if (dynamic[i].d_tag == DT_NEEDED) {
            const uint64_t p_str = dynamic[i].d_un.d_ptr + dynamic_table[DT_STRTAB]->d_un.d_ptr;
            printf("%s Found DT_NEEDED %s\n", INFO, (char*)p_str);

            void *dh = dlopen((char*)p_str, RTLD_NOW | RTLD_GLOBAL);
            if (dh == NULL) {
                printf("%s Fail to load: %s\n", FAIL, (char*)p_str);
                return 0;
            }

            sot_so_add(dh);
        }
    }

    return 1;
}

static void do_parse_load_symbols(
    const uint64_t image_base,
    Elf64_Dyn *dynamic_table[]
) {
    uint32_t n_sym = 0;
    if (dynamic_table[DT_HASH]) {
        n_sym = ((struct DtHashDummy*)dynamic_table[DT_HASH]->d_un.d_ptr)->nchain;
    } else if (dynamic_table[DT_GNU_HASH_RED]) {
        n_sym = gnu_hash_sym_count((void*)dynamic_table[DT_GNU_HASH_RED]->d_un.d_ptr);
    }

    const Elf64_Sym *dynsym = (const Elf64_Sym*)dynamic_table[DT_SYMTAB]->d_un.d_ptr;
    for (int i = 0; i < n_sym; i++) {
        if (dynsym[i].st_shndx != SHN_UNDEF) {
            lst_ls_add(dynsym[i].st_value + image_base, (const char *)(dynamic_table[DT_STRTAB]->d_un.d_ptr + dynsym[i].st_name));
        }
    }
}

int do_relocate(
    _in const uint64_t image_base,
    _in _out Elf64_Dyn *dynamic,
    _out Elf64_Dyn *dynamic_table[]
) {

    do_parse_dynamic(image_base, dynamic, dynamic_table);
    if (!do_load_dependencies(dynamic, dynamic_table))
        return 0;

    do_parse_load_symbols(image_base, dynamic_table);

    if (dynamic_table[DT_RELA])
        do_rela_reloc(
            image_base,
            (const Elf64_Rela*)dynamic_table[DT_RELA]->d_un.d_ptr,
            dynamic_table[DT_RELASZ]->d_un.d_val / dynamic_table[DT_RELAENT]->d_un.d_val,
            (const Elf64_Sym*)dynamic_table[DT_SYMTAB]->d_un.d_ptr,
            dynamic_table[DT_STRTAB]->d_un.d_ptr);

    if (dynamic_table[DT_RELR])
        do_relr_reloc(
            image_base,
            (const Elf64_Relr*)dynamic_table[DT_RELR]->d_un.d_ptr,
            dynamic_table[DT_RELRSZ]->d_un.d_val / dynamic_table[DT_RELRENT]->d_un.d_val);

    return 1;
}

```

### loader/relocation.h

- Size: 180 bytes
- Modified: 2025-12-14 19:31:36

```text

#pragma once
#include "loader.h"

#define DT_GNU_HASH_RED 49

int do_relocate(
    _in uint64_t image_base,
    _in _out Elf64_Dyn *dynamic,
    _out Elf64_Dyn *dynamic_table[]
);
```

### loader/sot.c

- Size: 2128 bytes
- Modified: 2025-12-14 19:11:32

```text

#define _GNU_SOURCE

#include <stdlib.h>
#include <elf.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <link.h>

#include "sot.h"

static struct SharedObjectTable sot_head = { .next = NULL };
static struct LocalSymbolTable  lst_head = { .next = NULL };

static struct SharedObjectTable* sot_get_end() {
    struct SharedObjectTable* sot = &sot_head;

    while (sot->next != NULL) {
        sot = sot->next;
    }

    return sot;
}

static struct LocalSymbolTable* lst_get_end() {
    struct LocalSymbolTable* lst = &lst_head;

    while (lst->next != NULL) {
        lst = lst->next;
    }

    return lst;
}

void sot_so_add(void *hDl) {
    struct SharedObjectTable* sot = malloc(sizeof(struct SharedObjectTable));

    struct link_map* map;
    if (dlinfo(hDl, RTLD_DI_LINKMAP, &map) == 0) {
        sot->name = map->l_name;
        sot->hDl = hDl;
        sot->next = NULL;
    }

    struct SharedObjectTable* end = sot_get_end();
    end->next = sot;
}

void lst_ls_add(uint64_t value, const char *name) {
    struct LocalSymbolTable* lst = malloc(sizeof(struct LocalSymbolTable));

    lst->name = name;
    lst->value = value;
    lst->next = NULL;

    struct LocalSymbolTable* end = lst_get_end();
    end->next = lst;
}

// ReSharper disable once CppDeclaratorNeverUsed
static uint64_t lst_symbol_lookup(const char *name) {
    struct LocalSymbolTable* lst = lst_head.next;

    while (lst != NULL) {
        if (strcmp(lst->name, name) == 0) {
            return lst->value;
        }

        lst = lst->next;
    }

    return 0;
}

uint64_t sot_symbol_lookup(const char *name) {
    // uint64_t sym = lst_symbol_lookup(name);
    // FIXME: If symbol versions are not considered,
    // FIXME: prioritize searching for potentially incorrect symbols in the local symbol table
    // if (sym)
    //     return sym;

    uint64_t sym = 0;
    struct SharedObjectTable* sot = sot_head.next;
    while (sot != NULL) {
        void *ds = dlsym(sot->hDl, name);
        if (ds) {
            sym = (uint64_t)ds;
            return sym;
        }
        sot = sot->next;
    }

    return 0;
}

```

### loader/sot.h

- Size: 351 bytes
- Modified: 2025-12-13 02:39:29

```text

#pragma once

struct SharedObjectTable {
    void* hDl;
    const char* name;
    struct SharedObjectTable* next;
};

struct LocalSymbolTable {
    uint64_t value;
    const char* name;
    struct LocalSymbolTable* next;
};

void sot_so_add(void *hDl);
void lst_ls_add(uint64_t value, const char *name);
uint64_t sot_symbol_lookup(const char *name);

```


-----

## Summary

- Total files scanned: 29
- Included text files: 15
- Skipped binary files: 10
- Skipped ignored files: 4
- Unreadable files: 0
- Truncated files (per-file cap): 0
