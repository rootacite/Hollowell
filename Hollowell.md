# Project Dump

- Root: `/home/acite/Deeppin/Hollowell`
- Generated: 2025-12-21 02:26:09

## Table of Contents

| # | Path | Size (bytes) | Modified | Status |
|---:|------|-------------:|----------|--------|
| 1 | `Cargo.lock` | 29762 | 2025-12-20 07:02:27 | skipped (ignored) |
| 2 | `Cargo.toml` | 614 | 2025-12-20 07:02:25 | included |
| 3 | `LICENSE` | 34523 | 2025-12-13 00:41:17 | skipped (ignored) |
| 4 | `Makefile` | 591 | 2025-12-18 13:36:24 | included |
| 5 | `README.md` | 2239 | 2025-12-18 12:56:24 | skipped (ignored) |
| 6 | `divider.rs` | 5065 | 2025-12-21 02:11:58 | included |
| 7 | `hexer.rs` | 4757 | 2025-12-18 13:02:18 | included |
| 8 | `lib/asm.rs` | 5235 | 2025-12-21 02:12:01 | included |
| 9 | `lib/auxiliary.rs` | 5300 | 2025-12-20 23:06:59 | included |
| 10 | `lib/chunk.rs` | 6675 | 2025-12-19 00:25:29 | included |
| 11 | `lib/elf.rs` | 3774 | 2025-12-18 13:10:01 | included |
| 12 | `lib/elfdef.rs` | 8154 | 2025-12-18 16:31:49 | included |
| 13 | `lib/hollowell.rs` | 151 | 2025-12-19 01:24:53 | included |
| 14 | `lib/map.rs` | 7716 | 2025-12-18 13:31:49 | included |
| 15 | `lib/processes.rs` | 16719 | 2025-12-20 20:24:14 | included |
| 16 | `loader-rs/Cargo.lock` | 34847 | 2025-12-20 07:02:28 | skipped (ignored) |
| 17 | `loader-rs/Cargo.toml` | 545 | 2025-12-20 07:02:25 | included |
| 18 | `loader-rs/Makefile` | 281 | 2025-12-18 13:36:28 | included |
| 19 | `loader-rs/build.rs` | 73 | 2025-12-19 01:11:07 | included |
| 20 | `loader-rs/chain.rs` | 2602 | 2025-12-20 21:26:53 | included |
| 21 | `loader-rs/debug.rs` | 1891 | 2025-12-20 19:57:53 | included |
| 22 | `loader-rs/hollowgen.rs` | 10823 | 2025-12-19 01:12:37 | included |
| 23 | `loader-rs/relocation.rs` | 4354 | 2025-12-19 21:53:39 | included |
| 24 | `loader-rs/stagger.rs` | 25120 | 2025-12-21 02:25:55 | included |
| 25 | `loader-rs/tui.rs` | 3846 | 2025-12-20 20:25:17 | included |
| 26 | `obj/Makefile` | 406 | 2025-12-18 18:17:21 | included |

---

## File Contents

### Cargo.toml

- Size: 614 bytes
- Modified: 2025-12-20 07:02:25

```text
[package]
name = "hollowell"
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

nix = { version = "0.30.1", features = ["fs", "process", "ptrace", "uio"] }
iced-x86 = { version = "1.21.0", features = ["code_asm"] }
once_cell = "1.21.3"
rand = "0.10.0-rc.5"
log = "0.4.29"
env_logger = "0.11.8"
ratatui = "0.29.0"

[[bin]]
name = "divider"
path = "divider.rs"

[[bin]]
name = "hexer"
path = "hexer.rs"

[lib]
name = "hollowell"
path = "lib/hollowell.rs"

[workspace]
members = [
    "."
]

```

### Makefile

- Size: 591 bytes
- Modified: 2025-12-18 13:36:24

```text

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

```

### divider.rs

- Size: 5065 bytes
- Modified: 2025-12-21 02:11:58

```text

use anyhow::*;
use goblin::elf::section_header::{SHF_EXECINSTR, SHT_NOBITS, SHT_NOTE, SHT_NULL};

use std::mem::size_of;
use std::{env, fs};
use hollowell::{elf, elfdef};
use hollowell::asm::Assembly;
use hollowell::chunk::{hash_sha256, write_compressed, Chunk};
use hollowell::elfdef::Header;
use hollowell::auxiliary::Flatten;
use rand::Rng;

#[allow(unused)]
const SUCC: &str = "\x1b[32m[+]\x1b[0m";
#[allow(unused)]
const FAIL: &str = "\x1b[31m[-]\x1b[0m";
#[allow(unused)]
const ALER: &str = "\x1b[33m[!]\x1b[0m";
#[allow(unused)]
const INFO: &str = "\x1b[34m[*]\x1b[0m";

fn write_base(elf_data: &[u8], elf_parser: &elf::ExecuteLinkFile, seed: &str, out: &str) -> Result<()>
{
    let b_ehdr = &elf_data[0..size_of::<Header>()];
    write_compressed(&format!("{}/ehdr.bin", out), &b_ehdr, seed)?;
    log::info!("{SUCC} Wrote {} bytes to ehdr.bin", b_ehdr.len());

    let off_phdr = elf_parser.borrow_elf().header.e_phoff as usize;
    let sz_phdr = elf_parser.borrow_elf().header.e_phnum as usize
        * elf_parser.borrow_elf().header.e_phentsize as usize;
    let b_phdr = &elf_data[off_phdr..off_phdr + sz_phdr];
    write_compressed(&format!("{}/phdr.bin", out), &b_phdr, seed)?;
    log::info!("{SUCC} Wrote {} bytes to phdr.bin", b_phdr.len());

    Ok(())
}

fn write_chunk_table(tab: &[Chunk], seed: &str, out: &str) -> Result<()>
{
    let b_tab = tab.flatten();
    write_compressed(&format!("{}/ct.bin", out), &b_tab, seed)?;
    log::info!("{SUCC} Wrote {} bytes to ct.bin", b_tab.len());
    Ok(())
}

fn write_chunks(elf_data: &[u8], tab: &[Chunk], seed: &str, out: &str) -> Result<()>
{
    for i in tab
    {
        if i.chunk_type != SHT_NOBITS && i.vaddr != 0
        {
            let bytes = &elf_data[i.o_offset as usize..i.o_offset as usize + i.size as usize];
            write_compressed(&format!("{}/{:#0x}.bin", out, i.vaddr), bytes, seed)?;
            log::info!("{SUCC} Wrote {} bytes to {}", bytes.len(), &format!("{:#0x}.bin", i.vaddr));
        }
    }

    Ok(())
}

fn split_instructions(elf_data: &[u8], sec: &elfdef::SectionHeader, tab: &mut Vec<Chunk>) -> Result<()>
{
    let bytes = &elf_data[sec.sh_offset as usize..sec.sh_offset as usize + sec.sh_size as usize];
    let mut ip = 0u64;
    let mut decoder = Assembly::new(&bytes);
    let mut rng = rand::rng();

    loop {
        let b = decoder.next_branch()?;
        let r = rng.random_range(0..100);

        if r < 5 || b >= bytes.len()
        {
            let entry = Chunk {
                name_hash: [0u8; 32],
                vaddr: sec.sh_addr + ip,
                chunk_type: sec.sh_type,
                size: b as u64 - ip,
                flags: sec.sh_flags,
                align: sec.sh_addralign,
                link: sec.sh_link,
                info: sec.sh_info,
                entsize: sec.sh_entsize,
                o_offset: sec.sh_offset + ip,
            };
            
            tab.push(entry);
            ip = b as u64;
            if ip >= bytes.len() as u64
            {
                break Ok(());
            }
        }
    }
}

fn generate_chunks(elf_data: &[u8], secs: &[elfdef::SectionHeader]) -> Result<Vec<Chunk>>
{
    let mut tab = Vec::<Chunk>::new();

    for i in secs.iter() {
        if i.sh_flags & SHF_EXECINSTR as u64 == 0
        {
            let mut entry = Chunk {
                name_hash: [0u8; 32],
                vaddr: i.sh_addr,
                chunk_type: i.sh_type,
                size: i.sh_size,
                flags: i.sh_flags,
                align: i.sh_addralign,
                link: i.sh_link,
                info: i.sh_info,
                entsize: i.sh_entsize,
                o_offset: i.sh_offset,
            };
            entry.name_hash.copy_from_slice(hash_sha256(i.sh_name.as_bytes()).as_slice());

            tab.push(entry);
        }
        else
        {
            split_instructions(elf_data, i, &mut tab)?;
        }
    }

    Ok(tab)
}

fn main() -> Result<()> {
    let arg = env::args().into_iter().collect::<Vec<String>>();
    if arg.len() < 4 {
        return Err(anyhow!(
            "Insufficient parameters. \nUsage: divider <output> <file> <seed>. \n<file>: The ELF file you want to divide. \n<seed>: The confuse key."
        ));
    }

    let output_path = arg[1].clone();
    let elf_path = arg[2].clone();
    let seed = arg[3].clone();
    let elf_parser = elf::ExecuteLinkFile::prase(&elf_path).expect(&format!("{FAIL} Is this really a elf ??"));
    let elf_data = fs::read(elf_path)?;

    let key = hash_sha256(&seed.as_bytes());
    fs::write(format!("{}/seed.bin", output_path), key.as_slice())?;
    write_base(&elf_data, &elf_parser, &seed, &output_path)?;

    let secs = elf_parser.get_sec_table()?;
    let secs = secs
        .into_iter().filter(|x| x.sh_type != SHT_NULL && x.sh_type != SHT_NOTE)
        .collect::<Vec<elfdef::SectionHeader>>();

    let ct = generate_chunks(&elf_data, &secs)?;

    write_chunk_table(&ct, &seed, &output_path)?;
    write_chunks(&elf_data, &ct, &seed, &output_path)?;

    Ok(())
}

```

### hexer.rs

- Size: 4757 bytes
- Modified: 2025-12-18 13:02:18

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

    let output_path = "hexer.c";
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
            parse_hex_to_u64(&symbol_name).unwrap_or_else(|_| u64::MAX)
        ));

        iter_fun.push_str(&format!(
            "{} .data = (unsigned char*)&_{}, .size = {:#0x}, .name = (char*)_{}_name, .vdata = {:#0x} {}",
            "        {",
            symbol_name,
            bin_data.len(),
            symbol_name,
            parse_hex_to_u64(&symbol_name).unwrap_or_else(|_| u64::MAX),
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

    compile_target("hexer")?;
    fs::remove_file(&output_path)?;

    Ok(())
}

```

### lib/asm.rs

- Size: 5235 bytes
- Modified: 2025-12-21 02:12:01

```text

// asm.rs

use anyhow::{Context, Result};
use iced_x86::{code_asm::*, BlockEncoder, BlockEncoderOptions, BlockEncoderResult, Decoder, DecoderOptions, FlowControl, Formatter, GasFormatter, Instruction, InstructionBlock};
use crate::map::MemoryMap;

use ratatui::{
    style::{Style, Color, Modifier},
    text::{Span},
};
use ratatui::prelude::Line;

pub fn assemble<F>(addr: u64, op: F) -> Result<Vec<u8>>
where
    F: Fn(&mut CodeAssembler) -> Result<()>,
{
    let mut asm = CodeAssembler::new(64)?;
    _ = op(&mut asm);
    Ok(asm.assemble(addr)?)
}

pub trait InstructionFormat {
    fn fmt_line(&self, formatter: &mut dyn Formatter) -> Result<String>;
    fn fmt_line_default(&self) -> Result<String>;
}

impl InstructionFormat for Instruction {
    fn fmt_line(&self, formatter: &mut dyn Formatter) -> Result<String> {
        let mut asm_str = String::new();
        formatter.format(self, &mut asm_str);

        Ok(format!(
            "\x1b[33m{}\x1b[0m",
            asm_str
        ))
    }

    fn fmt_line_default(&self) -> Result<String> {
        let mut fmt = GasFormatter::new();

        self.fmt_line(&mut fmt)
    }
}

pub struct Assembly
{
    data: Vec<u8>,
    offset: usize,
}

impl Assembly
{
    pub fn new(data: &[u8]) -> Self
    {
        Self { data: data.to_owned(), offset: 0 }
    }

    fn decode_one(&self) -> Result<Instruction>
    {
        let mut end = self.offset + 15;
        if end > self.data.len() {
            end = self.data.len();
        }

        let code_bytes = &self.data[self.offset..end];

        let decoder = iced_x86::Decoder::with_ip(64, code_bytes, self.offset as u64, DecoderOptions::FORCE_RESERVED_NOP);
        let instructions: Vec<Instruction> = decoder.into_iter().collect();

        Ok(instructions.first().context("No instruction found")?.clone())
    }
    pub fn set_ip(&mut self, ip: usize)
    {
        self.offset = ip;
    }

    pub fn next_branch(&mut self) -> Result<usize>
    {
        loop {
            let instruction = self.decode_one()?;
            self.offset += instruction.len();

            let b = match instruction.flow_control() {
                FlowControl::Interrupt | FlowControl::Next => false,
                _ => true
            };

            if b || self.offset >= self.data.len() {
                break Ok(self.offset);
            }
        }
    }

    pub fn instruction_relocate(addr: usize, data: &[u8], new_addr: u64) -> Result<BlockEncoderResult>
    {
        let decoder = Decoder::with_ip(64, data, addr as u64, DecoderOptions::NONE);
        let instructions: Vec<_> = decoder.into_iter().collect();

        let block = InstructionBlock::new(&instructions, new_addr);
        let options = BlockEncoderOptions::RETURN_RELOC_INFOS;

        let result = BlockEncoder::encode(64, block, options)
            .map_err(|e| format!("BlockEncoder failed: {}", e))
            .ok()
            .context("BlockEncoder failed")?;

        Ok(result)
    }

    pub fn byte_offset_to_ip(&mut self, offset: usize) -> Result<usize>
    {
        let mut ip = 0usize;
        loop {
            let instruction = self.decode_one()?;
            self.offset += instruction.len();

            let co = instruction.ip();

            if co == offset as u64 {
                return Ok(ip);
            }

            ip += 1;


            if self.offset >= self.data.len() {
                break Ok(ip);
            }
        }
    }

    pub fn ip_to_byte_offset(&mut self, ip: usize) -> anyhow::Result<usize>
    {
        for _ in 0..ip {
            let instruction = self.decode_one()?;
            self.offset += instruction.len();

            if self.offset >= self.data.len() {
                return Ok(self.offset);
            }
        }

        Ok(self.offset)
    }
}

pub trait DynamicFormatter
{
    fn format(&self, ip: usize, map: &MemoryMap) -> String;
    fn format_tui(&self, ip: usize, map: &MemoryMap) -> Line<'_>;
}

impl DynamicFormatter for Instruction
{
    fn format(&self, ip: usize, map: &MemoryMap) -> String
    {
        let prefix = if self.ip() == ip as u64 {
            " \x1b[32mrip\x1b[0m "
        } else {
            "     "
        };

        let arrow = "\x1b[34m->\x1b[0m";

        format!(
            "{}{} {}:{:02} {}",
            prefix,
            arrow,
            map.format_address(self.ip() as usize),
            self.len(),
            self.fmt_line_default().unwrap_or_default()
        )
    }

    fn format_tui(&self, ip: usize, map: &MemoryMap) -> Line<'_> {
        let mut spans = Vec::new();

        if self.ip() == ip as u64 {
            spans.push(
                Span::styled(
                    " rip ",
                    Style::new().fg(Color::Green).add_modifier(Modifier::BOLD),
                )
            );
        } else {
            spans.push(Span::raw("     "));
        }

        spans.push(Span::styled("->", Style::new().fg(Color::Blue)));
        spans.push(Span::raw(" "));
        spans.push(Span::raw(format!(
            "{}:{:02} {}",
            map.format_address(self.ip() as usize),
            self.len(),
            self.fmt_line_default().unwrap_or_default()
        )));

        Line::from(spans)
    }
}

```

### lib/auxiliary.rs

- Size: 5300 bytes
- Modified: 2025-12-20 23:06:59

```text

use anyhow::{bail};
use goblin::elf::program_header::PT_LOAD;
use plain::{Plain};

use crate::elfdef::ProgramHeader;

#[allow(unused)]
const SUCC: &str = "\x1b[32m[+]\x1b[0m";
#[allow(unused)]
const FAIL: &str = "\x1b[31m[-]\x1b[0m";
#[allow(unused)]
const ALER: &str = "\x1b[31m[!]\x1b[0m";
#[allow(unused)]
const INFO: &str = "\x1b[34m[*]\x1b[0m";

#[derive(Debug, Clone)]
pub struct ChunkMeta
{
    pub address: u64,
    pub in_window: bool,
    pub fault_counter: u32,
    pub data: Vec<u8>
}

#[derive(Debug, Clone)]
pub struct ChunkMetaInMemory
{
    pub origin_address: u64,
    pub data: Vec<u8>,
    pub relocated: u64
}

pub trait ProgramHeaderExt {
    fn get_image_size(&self) -> usize;
    #[allow(unused)]
    fn locate(&self, address: usize) -> Option<&ProgramHeader>;
}

pub trait Flatten<T> {
    fn flatten(&self) -> Vec<u8>;
}

pub trait RandomLength {
    fn strlen(&self, addr: usize) -> usize;
}

impl ProgramHeaderExt for &[ProgramHeader]
{
    fn get_image_size(&self) -> usize
    {
        let mut image_size: u64 = 0;

        for i in self.iter()
        {
            if i.p_type == PT_LOAD && i.p_vaddr + i.p_memsz >= image_size {
                image_size = i.p_vaddr + i.p_memsz;
            }
        }

        image_size as usize
    }

    fn locate(&self, address: usize) -> Option<&ProgramHeader>
    {
        for i in self.iter()
        {
            if i.p_type == PT_LOAD
                && address >= i.p_vaddr as usize
                && address < (i.p_vaddr + i.p_memsz) as usize {
                return Some(i);
            }
        }

        None
    }
}

impl<T, B> Flatten<T> for B
    where
        T: Plain,
        B: AsRef<[T]>
{
    fn flatten(&self) -> Vec<u8>
    {
        let mut flattened: Vec<u8> = Vec::new();
        for i in self.as_ref().iter()
        {
            let mut b = unsafe { plain::as_bytes::<T>(&i) }.to_vec();
            flattened.append(&mut b);
        }

        flattened
    }
}

impl RandomLength for &[u8]
{
    fn strlen(&self, offset: usize) -> usize
    {
        let mut len: usize = 0;

        for i in offset..self.len()
        {
            if self.get(i) != Some(&b'\0')
            {
                len += 1;
            }
            else
            {
                break;
            }
        }

        len
    }
}

pub trait QuickConver {
    fn to<T>(&self) -> anyhow::Result<T>
    where
        T: Plain + Clone;
}

impl<B> QuickConver for B
where
    B: AsRef<[u8]>
{
    fn to<T>(&self) -> anyhow::Result<T>
    where
        T: Plain + Clone,
    {
        let e = plain::from_bytes::<T>(self.as_ref());
        match e {
            Ok(v) => {
                anyhow::Ok(v.to_owned())
            }
            Err(_) => {
                bail!("Failed to convert");
            }
        }
    }
}

pub trait BlockLocator
{
    fn find_block(&mut self, x: u64) -> Option<&mut ChunkMeta>;
    fn find_block_after(&mut self, x: u64) -> Option<&mut ChunkMeta>;
}

pub trait BlockLocatorInMemory {
    fn find_block_in_memory(&mut self, x: u64) -> Option<&mut ChunkMetaInMemory>;
    fn find_block_out_memory(&mut self, x: u64) -> Option<&mut ChunkMetaInMemory>;
    fn find_block_tail(&mut self, x: u64) -> Option<&mut ChunkMetaInMemory>;
}

impl<B> BlockLocator for B
where
    B: AsMut<[ChunkMeta]>
{
    fn find_block(&mut self, x: u64) -> Option<&mut ChunkMeta>
    {
        let mut l = 0usize;
        let mut r = self.as_mut().len();

        while l < r {
            let m = (l + r) / 2;
            if self.as_mut()[m].address <= x {
                l = m + 1;
            } else {
                r = m;
            }
        }

        if l == 0 {
            return None;
        }

        let h = &self.as_mut()[l - 1];
        if x < h.address + h.data.len() as u64 {
            Some(&mut self.as_mut()[l - 1])
        } else {
            None
        }
    }

    fn find_block_after(&mut self, x: u64) -> Option<&mut ChunkMeta>
    {
        let mut l = 0usize;
        let mut r = self.as_mut().len();

        while l < r {
            let m = (l + r) / 2;
            if self.as_mut()[m].address <= x {
                l = m + 1;
            } else {
                r = m;
            }
        }

        if l == 0 {
            return None;
        }

        let h = &self.as_mut()[l - 1];
        if x < h.address + h.data.len() as u64 {
            Some(&mut self.as_mut()[l])
        } else {
            None
        }
    }
}

impl<B> BlockLocatorInMemory for B
where
    B: AsMut<[ChunkMetaInMemory]>
{
    fn find_block_in_memory(&mut self, x: u64) -> Option<&mut ChunkMetaInMemory> {
        for i in self.as_mut() {
            if x >= i.relocated && x < i.relocated + i.data.len() as u64 {
                return Some(i);
            }
        }

        None
    }

    fn find_block_out_memory(&mut self, x: u64) -> Option<&mut ChunkMetaInMemory> {
        for i in self.as_mut() {
            if x == i.origin_address {
                return Some(i);
            }
        }

        None
    }

    fn find_block_tail(&mut self, x: u64) -> Option<&mut ChunkMetaInMemory> {
        for i in self.as_mut() {
            if x == i.relocated + i.data.len() as u64 {
                return Some(i);
            }
        }

        None
    }
}

```

### lib/chunk.rs

- Size: 6675 bytes
- Modified: 2025-12-19 00:25:29

```text

use std::ffi::{CStr, CString};
use std::io::{Read, Write};
use std::os::raw::{c_char, c_int, c_void};
use std::{fs, slice};
use std::ops::DerefMut;
use std::str::FromStr;
use anyhow::{bail};
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use goblin::elf32::section_header::SHT_NOBITS;
use plain::Plain;
use crate::elfdef;

use once_cell::sync::Lazy;
use sha2::{Digest, Sha256};

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Chunk {
    pub name_hash: [u8; 32],
    pub vaddr: u64,
    pub chunk_type: u32,
    pub size: u64,
    pub flags: u64,
    pub align: u64,
    pub link: u32,
    pub info: u32,
    pub entsize: u64,
    pub o_offset: u64
}

unsafe impl Plain for Chunk {}

type CUlong = u64;
type Bytes = Vec<u8>;
static SEED: Lazy<Vec<u8>> = Lazy::new(|| { get_seed().unwrap() });

static CHUNK_TABLE: Lazy<Vec<Chunk>> = Lazy::new(|| {
    plain::slice_from_bytes::<Chunk>(get_chunk_by_name("ct").unwrap().as_slice()).unwrap().to_vec()
});

#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct ChunkInfo {
    pub data: *mut u8,
    pub size: CUlong,
    pub name: *mut c_char,
    pub vdata: CUlong,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct CbIo {
    pub name: *mut c_char,
    pub vdata: u64,
    pub addr: *const u8,
    pub size: u64,
}

type ChunkCallback = extern "C" fn(
    chunk_info: *const ChunkInfo,
    user_data: *mut c_void,
) -> c_int;

unsafe extern "C" {
    fn iter_chunks(
        cb: ChunkCallback,
        user_data: *mut c_void,
    ) -> c_int;
}

extern "C" fn iter_by_name(chunk_info: *const ChunkInfo, user_data: *mut c_void) -> c_int
{
    let chunk_info: &ChunkInfo = unsafe { &*chunk_info };
    let user_data: &mut CbIo = unsafe { &mut *(user_data as *mut CbIo) };

    let name_str = unsafe { CStr::from_ptr(chunk_info.name).to_str().unwrap() };
    let target_name = unsafe { CStr::from_ptr(user_data.name).to_str().unwrap() };

    if target_name == name_str {
        user_data.addr = chunk_info.data;
        user_data.size = chunk_info.size;
        return 0;
    }
    1
}

extern "C" fn iter_by_vdata(chunk_info: *const ChunkInfo, user_data: *mut c_void) -> c_int
{
    let chunk_info: &ChunkInfo = unsafe { &*chunk_info };
    let user_data: &mut CbIo = unsafe { &mut *(user_data as *mut CbIo) };

    if chunk_info.vdata == user_data.vdata {
        user_data.addr = chunk_info.data;
        user_data.size = chunk_info.size;
        return 0;
    }
    1
}

fn decompress(compressed_data: &[u8]) -> anyhow::Result<Vec<u8>>
{
    let mut decoder = GzDecoder::new(compressed_data);

    let mut decompressed_data = Vec::new();
    decoder.read_to_end(&mut decompressed_data)?;

    anyhow::Ok(decompressed_data)
}

fn get_seed() -> anyhow::Result<Vec<u8>>
{
    let name_cstr = CString::from_str("seed")?;

    let mut cb = CbIo {
        name: name_cstr.as_ptr() as *mut c_char,
        vdata: 0,
        addr: std::ptr::null_mut(),
        size: 0,
    };

    let r = unsafe {
        iter_chunks(iter_by_name, &mut cb as *mut CbIo as *mut c_void)
    };

    if r == 1 {
        return anyhow::Ok(unsafe { slice::from_raw_parts(cb.addr, cb.size as usize) }.to_vec());
    }

    bail!("Unable to find seed");
}

pub fn get_chunk_by_name(name: &str) -> anyhow::Result<Vec<u8>>
{
    let name_cstr = CString::from_str(name)?;

    let mut cb = CbIo {
        name: name_cstr.as_ptr() as *mut c_char,
        vdata: 0,
        addr: std::ptr::null_mut(),
        size: 0,
    };

    let r = unsafe {
        iter_chunks(iter_by_name, &mut cb as *mut CbIo as *mut c_void)
    };

    if r == 1 {
        let mut b = unsafe { slice::from_raw_parts(cb.addr, cb.size as usize) }.to_vec();
        for i in 0..b.len()
        {
            b[i] ^= SEED[i % 32];
        }
        return anyhow::Ok(decompress(&b)?);
    }

    bail!("Unable to find chunk by name");
}

pub fn get_chunk_by_vdata(vdata: u64) -> anyhow::Result<Vec<u8>>
{
    let mut cb = CbIo {
        name: std::ptr::null_mut(),
        vdata,
        addr: std::ptr::null_mut(),
        size: 0,
    };

    let r = unsafe {
        iter_chunks(iter_by_vdata, &mut cb as *mut CbIo as *mut c_void)
    };

    if r == 1 {
        let mut b = unsafe { slice::from_raw_parts(cb.addr, cb.size as usize) }.to_vec();
        for i in 0..b.len()
        {
            b[i] ^= SEED[i % 32];
        }
        return anyhow::Ok(decompress(&b)?);
    }

    bail!("Unable to find chunk by name");
}

pub fn get_chunks_by_filter<F>(filter: F) -> Vec<(Chunk, Option<Bytes>)>
where F: Fn(&Chunk) -> bool
{
    CHUNK_TABLE.iter()
        .filter(|x| filter(x))
        .filter_map(|x| {
            let v = get_chunk_by_vdata(x.vaddr).ok();
            if let Some(v) = v {
                return Some((x.to_owned(), Some(v)));
            }
            if x.chunk_type == SHT_NOBITS
            {
                return Some((x.to_owned(), None));
            }
            return None;
        })
        .collect::<Vec<(Chunk, Option<Bytes>)>>()
}

pub fn get_ehdr() -> anyhow::Result<elfdef::Header>
{
    let ehdr_bytes = get_chunk_by_name("ehdr")?;
    let Ok(ehdr) = plain::from_bytes::<elfdef::Header>(&ehdr_bytes) else { bail!("Could not parse ELF header") };

    Ok(ehdr.clone())
}

pub fn get_phdr() -> anyhow::Result<Vec<elfdef::ProgramHeader>>
{
    let phdr_bytes = get_chunk_by_name("phdr")?;
    let Ok(phdr) = plain::slice_from_bytes::<elfdef::ProgramHeader>(&phdr_bytes) else { bail!("Could not parse Program header") };

    Ok(phdr.to_vec())
}

fn confuse_data(data: &mut [u8], seed: &str) -> anyhow::Result<()>
{
    let key = hash_sha256(&seed.as_bytes());

    for i in 0..data.len() {
        let b = data[i] ^ key[i % 32];
        data[i] = b;
    }

    anyhow::Ok(())
}

pub fn write_compressed(path: &str, content: &[u8], seed: &str) -> anyhow::Result<()>
{
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(content)?;
    let mut compressed = encoder.finish()?;

    confuse_data(compressed.deref_mut(), seed)?;
    fs::write(path, compressed)?;
    anyhow::Ok(())
}


pub fn hash_sha256(data: &[u8]) -> Vec<u8>
{
    let mut hasher = Sha256::new();
    hasher.update(data);
    let key: sha2::digest::generic_array::GenericArray<u8, sha2::digest::typenum::UInt<sha2::digest::typenum::UInt<sha2::digest::typenum::UInt<sha2::digest::typenum::UInt<sha2::digest::typenum::UInt<sha2::digest::typenum::UInt<sha2::digest::typenum::UTerm, sha2::digest::consts::B1>, sha2::digest::consts::B0>, sha2::digest::consts::B0>, sha2::digest::consts::B0>, sha2::digest::consts::B0>, sha2::digest::consts::B0>> = hasher.finalize();

    key.as_slice().to_owned()
}

```

### lib/elf.rs

- Size: 3774 bytes
- Modified: 2025-12-18 13:10:01

```text

// elf.rs

use std::collections::HashMap;
use anyhow::{Context, Result};
use goblin::elf::{Elf, ProgramHeader, program_header::PT_LOAD};
use memmap2::Mmap;
use std::fs::File;
use std::ops::Deref;
use goblin::elf::dynamic::DT_NEEDED;
use ouroboros::self_referencing;
use crate::elfdef;
use crate::elfdef::{get_shared_object_path, HashConverter, SectionHeader, SymbolTableEntry};

fn open_mem_map(path: &str) -> Result<Mmap> {
    let file = File::open(path)?;
    unsafe { Ok(Mmap::map(&file)?) }
}

#[self_referencing]
pub struct ExecuteLinkFile {
    pub data: Vec<u8>,

    #[borrows(data)]
    #[covariant]
    pub elf: Elf<'this>
}

impl ExecuteLinkFile {
    pub fn prase(path: &str) -> Result<Self>
    {
        let data = open_mem_map(path)?.deref().to_owned();
        let s = ExecuteLinkFileTryBuilder {
            data,
            elf_builder: |data_ref| {
                Elf::parse(&data_ref)
            }
        }.try_build()?;

        Ok(s)
    }

    pub fn get_loads(&self) -> Result<Vec<ProgramHeader>>
    {
        let loads = self.borrow_elf()
            .program_headers
            .iter()
            .filter_map(|ph| match ph.p_type {
                PT_LOAD => Some(ph.to_owned()),
                _ => None,
            })
            .collect::<Vec<ProgramHeader>>();

        Ok(loads)
    }

    pub fn get_dependencies(&self) -> Result<Vec<String>>
    {
        let mut r = Vec::<String>::new();

        if let Some(dynamic) = &self.borrow_elf().dynamic
        {
            for needed in dynamic.dyns.iter().filter(|x| x.d_tag == DT_NEEDED) {
                r.push(self.get_dyn_str(needed.d_val as usize)?);
            }
        }

        Ok(r)
    }

    pub fn get_dependencies_recursively(path: &str, set: &mut Vec<String>) -> Result<()>
    {
        if !set.contains(&path.to_string())
        {
            set.push(path.to_owned());
        } else {
            return Ok(());
        }

        let e = Self::prase(path)?;
        for dep in e.get_dependencies()?
        {
            Self::get_dependencies_recursively(&get_shared_object_path(&dep).context("failed to resolve.")?, set)?;
        }

        Ok(())
    }
    
    pub fn get_dynsym_table(&self) -> Result<HashMap<String, SymbolTableEntry>>
    {
        let dynstr = &self.borrow_elf().dynstrtab;

        let syms = self.borrow_elf().dynsyms.iter().map(|x| {
            elfdef::Sym {
                st_name: x.st_name as u32,
                st_info: x.st_info,
                st_other: x.st_other,
                st_shndx: x.st_shndx as u16,
                st_value: x.st_value,
                st_size: x.st_size,
            }
        }).map(|x| {
            x.as_entry_gtab(dynstr)
        }).collect::<Vec<SymbolTableEntry>>().as_hash_table();

        Ok(syms)
    }
    

    pub fn get_dyn_str(&self, location: usize) -> Result<String>
    {
        let str = self.borrow_elf()
            .dynstrtab
            .get_at(location)
            .context(format!("Could not get dynstr at location {}", location))?;

        Ok(str.to_owned())
    }

    pub fn get_sec_table(&self) -> Result<Vec<SectionHeader>>
    {
        let r = self.borrow_elf().section_headers.iter().
            map(|x| SectionHeader {
                sh_name: self.borrow_elf().shdr_strtab.get_at(x.sh_name).unwrap_or("").to_string(),
                sh_type: x.sh_type,
                sh_flags: x.sh_flags,
                sh_addr: x.sh_addr,
                sh_offset: x.sh_offset,
                sh_size: x.sh_size,
                sh_link: x.sh_link,
                sh_info: x.sh_info,
                sh_addralign: x.sh_addralign,
                sh_entsize: x.sh_entsize,
            })
            .collect::<Vec<SectionHeader>>();

        Ok(r)
    }
}

```

### lib/elfdef.rs

- Size: 8154 bytes
- Modified: 2025-12-18 16:31:49

```text

use std::collections::HashMap;
use std::ffi::{c_void, CStr, CString};
use std::ptr;

use goblin::elf64::header::SIZEOF_IDENT;
use nix::libc;
use nix::libc::{c_char, dlclose, dlopen, RTLD_LAZY};
use plain::Plain;
use crate::auxiliary::{Flatten, RandomLength};

#[derive(Clone, Debug)]
pub struct SectionHeader {
    pub sh_name: String,
    pub sh_type: u32,
    pub sh_flags: u64,
    pub sh_addr: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u64,
    pub sh_entsize: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Header {
    pub e_ident           : [u8; SIZEOF_IDENT],
    pub e_type            : u16,
    pub e_machine         : u16,
    pub e_version         : u32,
    pub e_entry           : u64,
    pub e_phoff           : u64,
    pub e_shoff           : u64,
    pub e_flags           : u32,
    pub e_ehsize          : u16,
    pub e_phentsize       : u16,
    pub e_phnum           : u16,
    pub e_shentsize       : u16,
    pub e_shnum           : u16,
    pub e_shstrndx        : u16,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct ProgramHeader {
    pub p_type  : u32,
    pub p_flags : u32,
    pub p_offset: u64,
    pub p_vaddr : u64,
    pub p_paddr : u64,
    pub p_filesz: u64,
    pub p_memsz : u64,
    pub p_align : u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Dyn {
    pub d_tag: u64,
    pub d_val: u64
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Rela {
    pub r_offset: u64,
    pub r_info: u64,
    pub r_addend: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Sym {
    pub st_name: u32,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: u16,
    pub st_value: u64,
    pub st_size: u64,
}


unsafe impl Plain for Header {}
unsafe impl Plain for ProgramHeader {}
unsafe impl Plain for Dyn {}
unsafe impl Plain for Rela {}
unsafe impl Plain for Sym {}

pub fn elf_hash(name: &[u8]) -> u32 {
    let mut h = 0u32;
    let mut g;

    for &byte in name {
        h = (h << 4).wrapping_add(byte as u32);
        g = h & 0xf000_0000;
        if g != 0 {
            h ^= g >> 24;
        }
        h &= !g;
    }
    h
}


pub struct DynamicHash
{
    nbucket: u32,
    nchain: u32,
    bucket: Vec<u32>,
    chain: Vec<u32>,
}

impl DynamicHash
{
    pub fn new() -> Self {
        DynamicHash {
            nbucket: 0,
            nchain: 0,
            bucket: vec![],
            chain: vec![],
        }
    }

    pub fn flush(&mut self, syms: &Vec<Sym>, dynstr: &Vec<u8>) {
        // number of symbols (nchain)
        let nsyms = syms.len();
        let nsyms_u32 = nsyms as u32;

        let nbuckets = if nsyms <= 1 {
            1usize
        } else {
            Self::next_prime(nsyms)
        } as u32;

        self.nbucket = nbuckets;
        self.nchain = nsyms_u32;
        self.bucket = vec![0u32; nbuckets as usize];
        self.chain = vec![0u32; nsyms]; // chain length equals symbol count

        // helper to read NUL-terminated name from dymstr safely
        fn read_name(dymstr: &[u8], offset: usize) -> &[u8] {
            if offset >= dymstr.len() {
                &[]
            } else {
                let slice = &dymstr[offset..];
                match slice.iter().position(|&b| b == 0) {
                    Some(len) => &slice[..len],
                    None => slice, // no terminating NUL, take rest
                }
            }
        }

        // Insert symbols into buckets. Start from index 1 (STN_UNDEF = 0 is reserved).
        for i in 1..nsyms {
            let sym = &syms[i];
            let name_off = sym.st_name as usize;
            let name = read_name(&dynstr, name_off);
            let h = elf_hash(name);
            let bi = (h % nbuckets) as usize;

            let idx = i as u32;
            // chain[idx] = bucket[bi];
            self.chain[idx as usize] = self.bucket[bi];
            // bucket[bi] = idx;
            self.bucket[bi] = idx;
        }
    }

    fn is_prime(n: usize) -> bool {
        if n < 2 {
            return false;
        }
        if n % 2 == 0 {
            return n == 2;
        }
        let mut i = 3usize;
        while i * i <= n {
            if n % i == 0 {
                return false;
            }
            i += 2;
        }
        true
    }

    /// Return the smallest prime >= n (n >= 0).
    fn next_prime(mut n: usize) -> usize {
        if n <= 2 {
            return 2;
        }
        if n % 2 == 0 {
            n += 1;
        }
        while !Self::is_prime(n) {
            n += 2;
        }
        n
    }
}

impl<T> Flatten<T> for DynamicHash {
    fn flatten(&self) -> Vec<u8> {
        let mut flat: Vec<u8> = Vec::new();

        flat.append(&mut unsafe { plain::as_bytes(&self.nbucket) }.to_vec());
        flat.append(&mut unsafe { plain::as_bytes(&self.nchain) }.to_vec());
        flat.append(&mut self.bucket.flatten());
        flat.append(&mut self.chain.flatten());

        flat
    }
}

#[derive(Clone, Debug)]
pub struct SymbolTableEntry {
    pub sym_name: Option<String>,
    pub sym_type: u8,
    pub sym_bind: u8,

    pub sym_visibility: u8,
    pub sym_ndx: u16,
    pub sym_value: u64,
    pub sym_size: u64,
}

impl Sym
{
    pub fn as_entry(&self, dynstr: &[u8]) -> SymbolTableEntry {
        let mut name: Option<String> = None;

        if self.st_name != 0
        {
            let len = dynstr.strlen(self.st_name as usize);
            let bytes = dynstr[self.st_name as usize..self.st_name as usize + len].to_vec();
            let cstr = CString::new(bytes).unwrap_or_default();
            name = cstr.into_string().ok();
        }

        SymbolTableEntry {
            sym_name: name,
            sym_type: self.st_info & 0b1111,
            sym_bind: (self.st_info >> 4) & 0b1111,
            sym_visibility: self.st_other,
            sym_ndx: self.st_shndx,
            sym_value: self.st_value,
            sym_size: self.st_size
        }
    }

    pub fn as_entry_gtab(&self, dynstr: &goblin::strtab::Strtab) -> SymbolTableEntry {
        let mut name: Option<String> = None;

        if let Some(str) = dynstr.get_at(self.st_name as usize)
        {
            name = Some(str.to_string());
        }

        SymbolTableEntry {
            sym_name: name,
            sym_type: self.st_info & 0b1111,
            sym_bind: (self.st_info >> 4) & 0b1111,
            sym_visibility: self.st_other,
            sym_ndx: self.st_shndx,
            sym_value: self.st_value,
            sym_size: self.st_size
        }
    }
}

pub trait HashConverter
{
    fn as_hash_table(&self) -> HashMap<String, SymbolTableEntry>;
}

impl<T> HashConverter for T
where 
    T: AsRef<[SymbolTableEntry]>
{
    fn as_hash_table(&self) -> HashMap<String, SymbolTableEntry>
    {
        let mut h = HashMap::<String, SymbolTableEntry>::new();

        for i in self.as_ref()
        {
            if let Some(name) = &i.sym_name {
                h.insert(name.clone(), i.clone());
            }
        }

        h
    }
}

#[repr(C)]
struct LinkMap {
    l_addr: usize,
    l_name: *mut c_char, // The absolute path is stored here
    l_ld: *mut c_void,
    l_next: *mut LinkMap,
    l_prev: *mut LinkMap,
}

pub fn get_shared_object_path(lib_name: &str) -> Option<String>
{
    let lib_c_str = CString::new(lib_name).ok()?;

    let handle = unsafe {
        dlopen(lib_c_str.as_ptr(), RTLD_LAZY)
    };

    let path_result = unsafe {
        let mut link_map_ptr: *mut LinkMap = ptr::null_mut();

        let result = libc::dlinfo(
            handle,
            libc::RTLD_DI_LINKMAP,
            &mut link_map_ptr as *mut _ as *mut c_void,
        );

        if result == 0 && !link_map_ptr.is_null() {
            let l_name = (*link_map_ptr).l_name;
            if !l_name.is_null() {
                let c_str = CStr::from_ptr(l_name);
                Some(c_str.to_string_lossy().into_owned())
            } else {
                None
            }
        } else {
            None
        }
    };

    unsafe {
        let _ = dlclose(handle);
    }

    path_result
}

pub const SHT_RELR: u32 = 19; 
```

### lib/hollowell.rs

- Size: 151 bytes
- Modified: 2025-12-19 01:24:53

```text

pub mod asm;
pub mod elf;
pub mod elfdef;
pub mod map;
pub mod processes;
pub mod auxiliary;
pub mod chunk;

pub fn init()
{
    env_logger::init();
}
```

### lib/map.rs

- Size: 7716 bytes
- Modified: 2025-12-18 13:31:49

```text
// map.rs

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use crate::elf::ExecuteLinkFile;

#[derive(Debug, Clone)]
pub struct ModuleMetadata {
    pub base_address: u64,
    pub short_name: String,
}

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub start_addr: u64,
    pub end_addr: u64,
    pub perms: String,
    pub offset: Option<u64>,
    pub dev: Option<String>,
    pub inode: Option<u64>,
    pub pathname: Option<String>,
}

impl MemoryRegion {
    pub fn parse(line: &str) -> Option<Self> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            return None;
        }

        let range_part = parts[0];
        let range_parts: Vec<&str> = range_part.split('-').collect();
        if range_parts.len() != 2 {
            return None;
        }
        let start_addr = u64::from_str_radix(range_parts[0], 16).ok()?;
        let end_addr = u64::from_str_radix(range_parts[1], 16).ok()?;

        let perms = parts[1].to_string();

        let offset = parts.get(2).and_then(|s| u64::from_str_radix(s, 16).ok());
        let dev = parts.get(3).map(|s| s.to_string());
        let inode = parts.get(4).and_then(|s| s.parse::<u64>().ok());
        let pathname = parts.get(5).map(|s| s.to_string());

        Some(Self {
            start_addr,
            end_addr,
            perms,
            offset,
            dev,
            inode,
            pathname,
        })
    }

    pub fn is_read_write(&self) -> bool {
        self.perms.starts_with("rw")
    }

    pub fn is_executable(&self) -> bool {
        self.perms.contains('x')
    }
}

#[derive(Debug, Clone)]
pub struct MemoryMap {
    regions: Vec<MemoryRegion>,
    module_cache: HashMap<String, ModuleMetadata>,
}

impl MemoryMap {
    pub fn new(lines: &Vec<&str>) -> Self {
        let regions: Vec<MemoryRegion> = lines
            .iter()
            .filter_map(|line| MemoryRegion::parse(line))
            .collect();

        let mut map = Self {
            regions,
            module_cache: HashMap::new(),
        };

        map.precompute_module_bases();
        map
    }

    fn precompute_module_bases(&mut self) {
        use std::collections::HashMap;

        let mut min_addr_map: HashMap<String, u64> = HashMap::new();
        for r in &self.regions {
            if let Some(ref path) = r.pathname {
                let entry = min_addr_map.entry(path.clone()).or_insert(u64::MAX);
                if r.start_addr < *entry {
                    *entry = r.start_addr;
                }
            }
        }

        for (path, min_addr) in min_addr_map {
            if path.starts_with('[') { continue; }

            let mut base_address = min_addr;

            let mut short_name = Path::new(&path)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or(&path)
                .replace(" (deleted)", "");

            let is_special = path.starts_with("/memfd:") || path.contains("(deleted)");

            if !is_special {
                if let Ok(elf) = ExecuteLinkFile::prase(&path) {
                    if let Ok(loads) = elf.get_loads() {
                        if let Some(first_load) = loads.iter().find(|p| p.is_executable()) {
                            if let Some(target_region) = self.regions.iter().find(|r| {
                                r.pathname.as_ref() == Some(&path) &&
                                    r.offset.unwrap_or(0) == first_load.p_offset
                            }) {
                                base_address = target_region.start_addr.saturating_sub(first_load.p_vaddr);
                            }
                        }
                    }
                }
            } else if path.starts_with("/memfd:") {
                if let Some(sub_name) = short_name.split(':').last() {
                    short_name = format!("memfd:{}", sub_name);
                }
            }

            self.module_cache.insert(path, ModuleMetadata {
                base_address,
                short_name,
            });
        }
    }

    pub fn find_region(&self, addr: u64) -> Option<&MemoryRegion> {
        let idx = self.regions.binary_search_by(|r| {
            if addr < r.start_addr {
                std::cmp::Ordering::Greater
            } else if addr >= r.end_addr {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        }).ok();

        idx.map(|i| &self.regions[i])
    }

    fn same_file<P: AsRef<Path>, Q: AsRef<Path>>(p1: P, p2: Q) -> std::io::Result<bool> {
        let m1 = fs::metadata(p1)?;
        let m2 = fs::metadata(p2)?;

        Ok(m1.dev() == m2.dev() && m1.ino() == m2.ino())
    }

    pub fn module_base_address(
        &self,
        module: &str, // Full path of module, like '/usr/lib/libc.so.6'
    ) -> Option<u64> {
        let elf = ExecuteLinkFile::prase(&module).ok()?;
        let loads = elf.get_loads().ok()?;
        let Some(first_load) = loads.iter().find(|p| p.is_executable()) else {
            return None;
        };

        let Some(map_item) = self
            .regions
            .iter()
            .filter(|x| {
                if let Some(pathname) = x.pathname.as_ref()
                {
                    if Self::same_file(pathname, module).unwrap_or(false)
                    {
                        return true;
                    }
                }
                false
            })
            .find(|r| {
                r.offset.unwrap_or(0) == first_load.p_offset && r.is_executable()
            })
        else {
            return None;
        };

        Some(map_item.start_addr - first_load.p_vaddr)
    }

    pub fn collect_module(&self, module: &str) -> Vec<MemoryRegion> {
        let r = self
            .regions
            .iter()
            .filter_map(|r| {
                if r.pathname.as_deref() == Some(module) {
                    Some(r.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<MemoryRegion>>();

        r
    }

    pub fn format_address(&self, addr: usize) -> String {
        let addr_u64 = addr as u64;

        if let Some(region) = self.find_region(addr_u64) {
            if let Some(ref path) = region.pathname {
                if let Some(meta) = self.module_cache.get(path) {
                    let offset = addr_u64 as i128 - meta.base_address as i128;
                    return self.format_with_offset(&meta.short_name, offset);
                }

                let name = Path::new(path).file_name().and_then(|s| s.to_str()).unwrap_or(path);
                let offset = addr_u64 - region.start_addr;
                return format!("{}+0x{:x}", name, offset);
            }
        }

        self.find_nearest_module(addr_u64)
            .unwrap_or_else(|| format!("0x{:x}", addr))
    }

    #[inline]
    fn format_with_offset(&self, name: &str, offset: i128) -> String {
        if offset >= 0 {
            format!("{}+0x{:x}", name, offset as u64)
        } else {
            format!("{}-0x{:x}", name, (-offset) as u64)
        }
    }

    fn find_nearest_module(&self, addr: u64) -> Option<String> {
        self.module_cache.values()
            .map(|meta| {
                let dist = (addr as i128 - meta.base_address as i128).abs();
                (dist, meta)
            })
            .min_by_key(|t| t.0)
            .map(|(_, meta)| {
                let offset = addr as i128 - meta.base_address as i128;
                self.format_with_offset(&meta.short_name, offset)
            })
    }
}

```

### lib/processes.rs

- Size: 16719 bytes
- Modified: 2025-12-20 20:24:14

```text
// processes.rs

use std::collections::HashMap;
use std::fs;

use anyhow::Result;
use anyhow::{Context, bail};
use nix::sys::uio::{RemoteIoVec, process_vm_readv, process_vm_writev};
use nix::unistd::Pid;

use crate::asm::{InstructionFormat, assemble};
use crate::map::MemoryMap;
use iced_x86::code_asm::{r8, r9, r10, rax, rdi, rdx, rsi};
use iced_x86::{Decoder, DecoderOptions, Instruction};
use nix::libc;
use nix::libc::user_regs_struct;
use nix::sys::ptrace;
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use std::io::{IoSlice, IoSliceMut};

use crate::chunk::Chunk;

#[allow(unused)]
const SUCC: &str = "\x1b[32m[+]\x1b[0m";
#[allow(unused)]
const FAIL: &str = "\x1b[31m[-]\x1b[0m";
#[allow(unused)]
const ALER: &str = "\x1b[33m[!]\x1b[0m";
#[allow(unused)]
const INFO: &str = "\x1b[34m[*]\x1b[0m";

type Bytes = Vec<u8>;

pub struct Process {
    pid: Pid,
    pub map: MemoryMap,
    pub history: HashMap<usize, usize>,
    modules_base: HashMap<String, usize>,
}

impl Process {
    pub fn new(pid: Pid) -> Result<Self>
    {
        let maps = fs::read_to_string(format!("/proc/{}/maps", pid))?;
        let map = MemoryMap::new(
            &maps
                .lines()
                .filter(|&line| !line.is_empty())
                .collect::<Vec<&str>>()
        );

        Ok(Self {
            pid,
            map,
            history: HashMap::new(),
            modules_base: HashMap::new(),
        })
    }

    pub fn getip(&self) -> Result<usize>
    {
        Ok(self.get_regs()?.rip as usize)
    }

    pub fn cont(&self) -> Result<()>
    {
        let rip = self.getip()?;
        ptrace::cont(self.pid, None)?;
        log::info!("{SUCC} Process {} continued from {}", self.pid, self.map.format_address(rip));
        Ok(())
    }

    pub fn step(&self) -> Result<WaitStatus>
    {
        ptrace::step(self.pid, None)?;
        Ok(Process::wait()?)
    }

    pub fn kill(&self) -> Result<()>
    {
        ptrace::kill(self.pid)?;
        Ok(())
    }

    pub fn stepover(&self) -> Result<WaitStatus>
    {
        let rip = self.getip()?;
        let inst = self.disassemble_one_at(rip)?;

        log::info!("{INFO} Prepare to cross {}:{:02} {}",
                        self.map.format_address(inst.ip() as usize),
                        inst.len(),
                        inst.fmt_line_default().unwrap_or_default()
                    );

        let ob = self.read(rip + inst.len(), 1)?;
        self.write(rip + inst.len(), &[0xccu8; 1])?;

        log::info!("{SUCC} Breakpoint at {}.", self.map.format_address(rip + inst.len()));

        self.cont()?;
        let w = Self::wait()?;
        self.write(rip + inst.len(), &ob)?;

        Ok(w)
    }

    pub fn wait() -> Result<WaitStatus>
    {
        let f = waitpid(None, Some(WaitPidFlag::WUNTRACED|WaitPidFlag::__WALL))?;

        match f {
            WaitStatus::Stopped(stopped_pid, signal) => {
                log::warn!("{ALER} PID {} stopped by signal: {:?}", stopped_pid, signal);
            }
            WaitStatus::Exited(exited_pid, status) => {
                log::warn!("{ALER} PID {} exited with status: {}", exited_pid, status);
            }
            WaitStatus::Signaled(signaled_pid, signal, core_dump) => {
                log::warn!(
                    "{ALER} PID {} killed by signal: {:?} (core dump: {})",
                    signaled_pid, signal, core_dump
                );
            }
            WaitStatus::Continued(continued_pid) => {
                log::warn!("{ALER} PID {} continued", continued_pid);
            }
            WaitStatus::StillAlive => {
                log::warn!("{ALER} Process still alive");
            }
            WaitStatus::PtraceEvent(stopped_pid, _, _) => {
                log::warn!("{ALER} PID {} stopped by PtraceEvent", stopped_pid);
            }
            _ => {}
        }

        Ok(f)
    }

    pub fn waitpid(pid: Pid) -> Result<WaitStatus>
    {
        let f = waitpid(pid, Some(WaitPidFlag::WUNTRACED))?;

        match f {
            WaitStatus::Stopped(stopped_pid, signal) => {
                log::warn!("{ALER} PID {} stopped by signal: {:?}", stopped_pid, signal);
            }
            WaitStatus::Exited(exited_pid, status) => {
                log::warn!("{ALER} PID {} exited with status: {}", exited_pid, status);
            }
            WaitStatus::Signaled(signaled_pid, signal, core_dump) => {
                log::warn!(
                    "{ALER} PID {} killed by signal: {:?} (core dump: {})",
                    signaled_pid, signal, core_dump
                );
            }
            WaitStatus::Continued(continued_pid) => {
                log::warn!("{ALER} PID {} continued", continued_pid);
            }
            WaitStatus::StillAlive => {
                log::warn!("{ALER} PID {} still alive", pid);
            }
            _ => {}
        }

        Ok(f)
    }

    pub fn get_pid(&self) -> Pid {
        self.pid.clone()
    }

    pub fn get_exe(&self) -> Result<String>
    {
        let r = fs::read_link(format!("/proc/{}/exe", self.pid))?
            .to_string_lossy()
            .into_owned();

        Ok(r)
    }

    pub fn get_map_str(&self) -> Result<String>
    {
        let r = fs::read_to_string(format!("/proc/{}/maps", self.pid))?;
        Ok(r)
    }

    pub fn read(&self, start_addr: usize, size: usize) -> Result<Vec<u8>>
    {
        let mut buffer = vec![0u8; size];
        let mut local_iov = [IoSliceMut::new(&mut buffer)];
        let remote_iov = [RemoteIoVec {
            base: start_addr,
            len: size,
        }];

        let bytes_read = process_vm_readv(self.pid, &mut local_iov, &remote_iov)?;
        if bytes_read == size {
            Ok(buffer)
        } else {
            buffer.truncate(bytes_read);
            Ok(buffer)
        }
    }

    pub fn write(&self, mut start_addr: usize, vdata: &[u8]) -> Result<usize>
    {
        let mut data = vdata.to_owned();

        let mut total_written = 0usize;
        while !data.is_empty() {
            let len = data.len();
            let local_iov = [IoSlice::new(data.as_mut_slice())];
            let remote_iov = [RemoteIoVec {
                base: start_addr,
                len,
            }];

            let written = process_vm_writev(self.pid, &local_iov, &remote_iov)?;

            if written == 0 {
                bail!(format!(
                    "process_vm_writev returned 0 (no progress) after writing {} bytes",
                    total_written
                ));
            }

            total_written += written;
            start_addr = start_addr.wrapping_add(written);
            data = data[written..].to_vec();
        }

        Ok(total_written)
    }

    pub fn get_regs(&self) -> Result<user_regs_struct> {
        Ok(ptrace::getregs(self.get_pid())?)
    }

    pub fn set_regs(&self, regs: &user_regs_struct) -> Result<()> {
        ptrace::setregs(self.get_pid(), *regs)?;
        Ok(())
    }

    pub fn flush_map(&mut self) -> Result<()>
    {
        let maps = fs::read_to_string(format!("/proc/{}/maps", self.pid))?;
        self.map = MemoryMap::new(
            &maps
                .lines()
                .filter(|&line| !line.is_empty())
                .collect::<Vec<&str>>()
        );

        Ok(())
    }

    pub fn module_base_address(&mut self, module: &str) -> Option<u64>
    {
        if let Some(base) = self.modules_base.get(module) {
            return Some(*base as u64);
        }

        let base = self.map.module_base_address(module)?;
        self.modules_base.insert(module.to_string(), base as usize);
        Some(base)
    }

    pub fn execute_once_inplace<F, F2>(
        &mut self,
        payload_builder: F,
        post_proc: F2,
    ) -> Result<user_regs_struct>
    where
        F: Fn(u64) -> Option<Vec<u8>>,
        F2: Fn(&user_regs_struct) -> (),
    {
        // Save context
        let regs = self.get_regs()?;
        let payload = payload_builder(regs.rip).context("payload build failed")?;

        let buffer = self.read(regs.rip as usize, payload.len() + 1)?;
        let instruction = [&payload as &[u8], &[0xccu8]].concat();

        self.write(regs.rip as usize, &instruction)?;
        log::info!("{SUCC} write instructions to {:#016x}", regs.rip);

        // Continue target
        self.cont()?;
        Self::wait()?;

        let r = self.get_regs()?;
        log::info!("{INFO} int3 at {:#016x}", r.rip);

        post_proc(&r);

        self.write(regs.rip as usize, &buffer)?;
        self.set_regs(&regs)?;
        Ok(r)
    }

    pub fn alloc_pages(&mut self, count: u64, permissions: u64) -> Result<u64>
    {
        // Alloc r-x private memory
        let r = self.execute_once_inplace(
            |addr| {
                let r = assemble(addr, |asm| {
                    asm.mov(rax, 9u64)?; // Syscall 9 (mmap)

                    asm.mov(rdi, 0u64)?; // Addr
                    asm.mov(rsi, 0x1000u64 * count)?; // Length, we alloc a page (4K)
                    asm.mov(rdx, permissions)?;
                    asm.mov(r10, (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64)?; // Private and anonymous
                    asm.mov(r8, -1i64)?; // Fd (-1 because we want anonymous)
                    asm.mov(r9, 0u64)?; // Offset

                    asm.syscall()?; // Syscall interrupt
                    Ok(())
                })
                .ok()?;

                Some(r)
            },
            |_| {},
        )?;

        Ok(r.rax as u64)
    }

    pub fn redirect(&self, rip: u64) -> Result<()> {
        let regs = self.get_regs()?;
        self.set_regs(&user_regs_struct { rip, ..regs })?;

        log::info!("{SUCC} Redirect the control flow to {}", self.map.format_address(rip as usize));

        Ok(())
    }

    pub fn redirect_relative(&self, offset: i32) -> Result<usize> {
        let mut regs = self.get_regs()?;

        if offset >= 0 {
            regs.rip += offset as u64;
        } else {
            let n = (-offset) as u64;
            regs.rip -= n;
        }
        self.set_regs(&user_regs_struct { rip: regs.rip, ..regs })?;

        log::info!("{SUCC} Redirect relatively the control flow to {}", self.map.format_address(regs.rip as usize));

        Ok(regs.rip as usize)
    }

    pub fn map_region(&self, base: usize, chunk: &Chunk, data: &Bytes) -> Result<()>
    {
        self.write(chunk.vaddr as usize + base, data)?;
        // println!(
        //     "{SUCC} Mapped section at base + {:#0x}, name hash = {}, {}, {}, ...",
        //     chunk.vaddr as usize, chunk.name_hash[0], chunk.name_hash[1], chunk.name_hash[2]
        // );
        Ok(())
    }

    pub fn disassemble<F, T>(&mut self, addr: usize, size: usize, callback: F) -> Result<T>
    where
        F: Fn(&mut Self, &[Instruction]) -> Result<T>,
    {
        let code_bytes = self.read(addr, size)?;
        let decoder = Decoder::with_ip(64, &code_bytes, addr as u64, DecoderOptions::NONE);
        let instructions: Vec<Instruction> = decoder.into_iter().collect();
        let result = callback(self, &instructions)?;
        Ok(result)
    }

    pub fn disassemble_one_at(&self, addr: usize) -> Result<Instruction>
    {
        let code_bytes = self.read(addr, 15)?;
        let decoder = Decoder::with_ip(64, &code_bytes, addr as u64, DecoderOptions::NONE);
        let instructions: Vec<Instruction> = decoder.into_iter().collect();

        Ok(instructions.first().context("Instruction decode failed")?.clone())
    }

    pub fn disassemble_block(&self, va: usize, data: &[u8], ip: usize) -> Result<()>
    {
        let decoder = Decoder::with_ip(64, data, va as u64, DecoderOptions::NONE);
        let instructions: Vec<Instruction> = decoder.into_iter().collect();
        let dmap = self.map.clone();
        let mut cc = 0;

        for inst in instructions
        {
            let prefix = if inst.ip() == ip as u64 {
                " \x1b[32mrip\x1b[0m "
            } else {
                "     "
            };

            let arrow = "\x1b[34m->\x1b[0m";

            log::info!(
                "{}{} <{:#04}> {}:{:02} {}",
                prefix,
                arrow,
                cc,
                dmap.format_address(inst.ip() as usize),
                inst.len(),
                inst.fmt_line_default().unwrap_or_default()
            );
            cc += 1;
        }

        Ok(())
    }

    pub fn disassemble_block_as_raw(&self, va: usize, data: &[u8]) -> Result<Vec<Instruction>>
    {
        let decoder = Decoder::with_ip(64, data, va as u64, DecoderOptions::NONE);
        let instructions: Vec<Instruction> = decoder.into_iter().collect();
        Ok(instructions)
    }

    pub fn disassemble_rip_log(&mut self) -> Result<()>
    {
        let regs = self.get_regs()?;
        let current_rip = self.get_regs()?.rip as usize;

        let mut start_addr = current_rip;

        for _ in 0..2 {
            if let Some(&prev_addr) = self
                .history
                .iter()
                .find(|(addr, len)| *addr + *len == start_addr)
                .map(|(k, _)| k)
            {
                start_addr = prev_addr;
            } else {
                break;
            }
        }

        let mut curr_addr = start_addr;
        let mut lines_printed = 0;
        let dmap = self.map.clone();

        while lines_printed < 5 {
            let (next_addr, success) = self.disassemble(curr_addr, 15, |s, insts| {
                if let Some(inst) = insts.first() {
                    let len = inst.len();

                    s.history.insert(curr_addr, len);

                    let prefix = if curr_addr == current_rip {
                        " \x1b[32mrip\x1b[0m "
                    } else {
                        "     "
                    };

                    let arrow = "\x1b[34m->\x1b[0m";

                    log::info!(
                        "{}{} {}:{:02} {}",
                        prefix,
                        arrow,
                        dmap.format_address(inst.ip() as usize),
                        inst.len(),
                        inst.fmt_line_default().unwrap_or_default()
                    );

                    return Ok((curr_addr + len, true));
                }
                Ok((0, false))
            })?;

            if !success || next_addr == 0 {
                break;
            }

            curr_addr = next_addr;
            lines_printed += 1;
        }

        log::info!("\x1b[90m{}\x1b[0m", "-".repeat(60));

        let gprs = [
            ("rax", regs.rax),
            ("rbx", regs.rbx),
            ("rcx", regs.rcx),
            ("rdx", regs.rdx),
            ("rsi", regs.rsi),
            ("rdi", regs.rdi),
            ("rbp", regs.rbp),
            ("rsp", regs.rsp),
            ("r8 ", regs.r8),
            ("r9 ", regs.r9),
            ("r10", regs.r10),
            ("r11", regs.r11),
            ("r12", regs.r12),
            ("r13", regs.r13),
            ("r14", regs.r14),
            ("r15", regs.r15),
        ];

        for chunk in gprs.chunks(4) {
            let row = chunk
                .iter()
                .map(|(name, val)| {
                    format!("\x1b[33m{}\x1b[0m: \x1b[36m0x{:016x}\x1b[0m", name, val)
                })
                .collect::<Vec<_>>()
                .join("  ");
            log::info!(" {}", row);
        }

        Ok(())
    }

    pub fn disassemble_rip_raw(&mut self) -> Result<Vec<Instruction>>
    {
        let mut r = Vec::<Instruction>::new();
        let current_rip = self.getip()?;

        let mut start_addr = current_rip;

        for _ in 0..2 {
            if let Some(&prev_addr) = self
                .history
                .iter()
                .find(|(addr, len)| *addr + *len == start_addr)
                .map(|(k, _)| k)
            {
                start_addr = prev_addr;
            } else {
                break;
            }
        }

        let mut curr_addr = start_addr;
        let mut lines_printed = 0;

        while lines_printed < 5 {
            let (next_addr, line) = self.disassemble(curr_addr, 15, |s, insts| {
                if let Some(inst) = insts.first() {
                    let len = inst.len();

                    s.history.insert(curr_addr, len);

                    return Ok((curr_addr + len, Some(inst.clone())));
                }
                Ok((0, None))
            })?;

            if let Some(line) = line {
                r.push(line);
            } else {
                break;
            }

            curr_addr = next_addr;
            lines_printed += 1;
        }
        Ok(r)
    }
}
```

### loader-rs/Cargo.toml

- Size: 545 bytes
- Modified: 2025-12-20 07:02:25

```text

[package]
name = "hollowchain"
version = "0.1.0"
edition = "2024"

[[bin]]
name = "chain"
path = "chain.rs"

[dependencies]
anyhow = "1.0.100"
goblin = "0.10.4"
plain = "0.2.3"
nix = { version = "0.30.1", features = ["fs", "process", "ptrace", "uio"] }
console = "0.16.2"

hollowell = { path = ".." }
libc = "0.2.178"
env_logger = "0.11.8"
once_cell = "1.21.3"
log = "0.4.29"
rand = "0.10.0-rc.5"
crossbeam-channel = "0.5.15"
crossterm = "0.29.0"
ratatui = "0.29.0"
iced-x86 = "1.21.0"
ansi-to-tui = "7.0.0"


[workspace]
members = [
    "."
]

```

### loader-rs/Makefile

- Size: 281 bytes
- Modified: 2025-12-18 13:36:28

```text

CARGO = cargo

TARGETS = chain

defconfig: all

all: $(TARGETS)

chain:
	$(CARGO) build -j 28
	cp /tmp/rust-target-hwel-chain/x86_64-unknown-linux-gnu/debug/chain ../bin/

clean:
	rm -f ../bin/chain
	$(CARGO) clean

.PHONY: chain all clean run dirs bin loader framework $(MODULES)
```

### loader-rs/build.rs

- Size: 73 bytes
- Modified: 2025-12-19 01:11:07

```text

fn main() {
    println!("cargo:rustc-link-arg={}", "../obj/hexer.o");
}
```

### loader-rs/chain.rs

- Size: 2602 bytes
- Modified: 2025-12-20 21:26:53

```text

mod hollowgen;
mod relocation;
mod stagger;
mod tui;
mod debug;

use std;
use std::convert::Infallible;
use std::env;
use std::ffi::{CStr, CString};

use std::os::fd::{AsFd};
use anyhow::{Result};
use std::os::unix::ffi::OsStrExt;
use std::io::Write;
use crate::tui::UI;

#[allow(unused)]
const SUCC: &str = "\x1b[32m[+]\x1b[0m";
#[allow(unused)]
const FAIL: &str = "\x1b[31m[-]\x1b[0m";
#[allow(unused)]
const ALER: &str = "\x1b[31m[!]\x1b[0m";
#[allow(unused)]
const INFO: &str = "\x1b[34m[*]\x1b[0m";

fn fexecve_with_current_argv_env<Fd: AsFd>(fd: Fd) -> nix::Result<Infallible>
{

    let argv_c: Result<Vec<CString>, std::ffi::NulError> = env::args_os()
        .map(|os| CString::new(os.as_os_str().as_bytes()))
        .collect();
    let argv_c = argv_c.map_err(|_| nix::Error::from(nix::errno::Errno::EINVAL))?;
    let argv_refs: Vec<&CStr> = argv_c.iter().map(|s| s.as_c_str()).collect();

    let envp_c: Result<Vec<CString>, std::ffi::NulError> = env::vars_os()
        .map(|(k, v)| {
            // create NAME=VALUE as bytes
            let mut kv = Vec::with_capacity(k.as_os_str().len() + 1 + v.as_os_str().len());
            kv.extend_from_slice(k.as_os_str().as_bytes());
            kv.push(b'=');
            kv.extend_from_slice(v.as_os_str().as_bytes());
            CString::new(kv)
        })
        .collect();
    let envp_c = envp_c.map_err(|_| nix::Error::from(nix::errno::Errno::EINVAL))?;
    let envp_refs: Vec<&CStr> = envp_c.iter().map(|s| s.as_c_str()).collect();

    nix::unistd::fexecve(fd, &argv_refs, &envp_refs)
}

fn main() -> Result<()> {
    let mut builder = env_logger::Builder::new();
    builder.format(|buf, record| {
        writeln!(buf, "<{}> {}",
                 record.target(),
                 record.args()
        )
    });
    builder.filter_level(log::LevelFilter::Debug);

    let logger = builder.build();
    log::set_boxed_logger(Box::new(logger))?;

    log::set_max_level(log::LevelFilter::Debug);

    let mut hollow = stagger::HollowStage::build()?;

    hollow.do_relocate = !match env::var("HC_DONT_RELOCATE") {
        Ok(_) => true,
        Err(_) => false,
    };

    hollow.debug.debug = match env::var("HC_DEBUG") {
        Ok(_) => true,
        Err(_) => false,
    };

    hollow.tui = match env::var("HC_TUI") {
        Ok(_) => {
            hollow.debug.debug = true;
            hollow.debug.tui = true;
            log::set_max_level(log::LevelFilter::Off);
            Some(UI::new()?)
        },
        Err(_) => None,
    };

    hollow.startup()?;
    hollow.prepare()?;
    hollow.staging()?;

    Ok(())
}
```

### loader-rs/debug.rs

- Size: 1891 bytes
- Modified: 2025-12-20 19:57:53

```text
use iced_x86::Instruction;
use hollowell::auxiliary::{ChunkMeta, ChunkMetaInMemory};
use hollowell::processes::Process;

use anyhow::{Result};

pub struct HollowStageDebug
{
    // Debug fields
    pub focused_origin: Vec<Instruction>,
    pub focused_relocated: Vec<Instruction>,
    pub ips: (usize, usize), // Ip in origin chunk, Ip in relocated chunk
    pub ins_number: usize,

    pub debug: bool,
    pub tui: bool,
    pub major: Option<Process>,

    pub clear: bool,

    pub focused_near: Vec<Instruction>,
}

impl HollowStageDebug {
    pub fn debug_flush_block(&mut self, o: &ChunkMeta, r: &ChunkMetaInMemory, ip: (usize, usize), n: usize) -> Result<()>
    {
        if !self.debug {
            return Ok(());
        }

        if let Some(major) = &mut self.major {
            if self.tui
            {
                self.focused_origin = major.disassemble_block_as_raw(o.address as usize, &o.data)?;
                self.focused_relocated = major.disassemble_block_as_raw(r.relocated as usize, &r.data)?;
                self.ips = ip;
                self.ins_number = n;
                self.clear = true;

                self.focused_near = major.disassemble_rip_raw()?;
                return Ok(());
            }

            if self.debug
            {
                major.disassemble_block(o.address as usize, &o.data, ip.0)?;
                log::info!("------------------------------------------------------");
                major.disassemble_block(r.relocated as usize, &r.data, ip.1)?;
            }
        }

        Ok(())
    }

    pub fn debug_flush_ip(&mut self, ip: (usize, usize), n: usize) -> Result<()>
    {
        self.ips = ip;
        self.ins_number = n;
        if let Some(major) = &mut self.major
        {
            self.clear = true;
            self.focused_near = major.disassemble_rip_raw()?;
        }

        Ok(())
    }
}
```

### loader-rs/hollowgen.rs

- Size: 10823 bytes
- Modified: 2025-12-19 01:12:37

```text

use std::collections::HashMap;
use std::ffi::CString;
use goblin::elf::header::{EM_X86_64, ET_DYN};
use goblin::elf::program_header::{PF_R, PF_W, PT_DYNAMIC, PT_INTERP, PT_LOAD, PT_PHDR};
use hollowell::elfdef;
use std::mem::size_of;
use std::str::FromStr;
use goblin::elf32::dynamic::DT_NEEDED;
use goblin::elf::dynamic::{DT_HASH, DT_NULL, DT_RELA, DT_RELAENT, DT_RELASZ, DT_STRSZ, DT_STRTAB, DT_SYMENT, DT_SYMTAB};
use hollowell::auxiliary::Flatten;
use hollowell::elfdef::DynamicHash;

type Bytes = Vec<u8>;

#[allow(unused)]
const SUCC: &str = "\x1b[32m[+]\x1b[0m";
#[allow(unused)]
const FAIL: &str = "\x1b[31m[-]\x1b[0m";
#[allow(unused)]
const ALER: &str = "\x1b[31m[!]\x1b[0m";
#[allow(unused)]
const INFO: &str = "\x1b[34m[*]\x1b[0m";

pub struct HollowGenerator {
    ehdr: elfdef::Header,
    phdr: Vec<elfdef::ProgramHeader>,
    dynamic: Vec<elfdef::Dyn>,
    interp: Option<CString>,
    dynstr: Bytes,
    rela: Vec<(elfdef::Rela, u32)>,
    syms: Vec<elfdef::Sym>,
    hash: elfdef::DynamicHash,
    segments: Vec<(Bytes, usize, u32, u32)>,
    entry: (u64, u32),
    building_hash: HashMap<String, u32>,
}

impl HollowGenerator {
    fn align_upwards(value: u64) -> u64
    {
        if value & 0xfff == 0 {
            value
        } else {
            (value + 0x1000) & (!0xfff)
        }
    }

    pub fn new_x86_64() -> Self
    {
        let ehdr = elfdef::Header {
            e_ident: [0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            e_type: ET_DYN,
            e_machine: EM_X86_64,
            e_version: 1,
            e_entry: 0, // set later
            e_phoff: 64,
            e_shoff: 0, // not used
            e_flags: 0, // not used
            e_ehsize: 64,
            e_phentsize: 56,
            e_phnum: 0, // set later
            e_shentsize: 64, // not used
            e_shnum: 0, // not used
            e_shstrndx: 0, // not used
        };

        let phdr_phdr = elfdef::ProgramHeader {
            p_type: PT_PHDR,
            p_flags: PF_R | PF_W,
            p_offset: 64,
            p_vaddr: 64,
            p_paddr: 64,
            p_filesz: 0,
            p_memsz: 0,
            p_align: 0x8,
        };

        let phdr_dyn = elfdef::ProgramHeader {
            p_type: PT_DYNAMIC,
            p_flags: PF_R | PF_W,
            p_offset: 0,
            p_vaddr: 0,
            p_paddr: 0,
            p_filesz: 0,
            p_memsz: 0,
            p_align: 0x8,
        };

        let phdr_header_load = elfdef::ProgramHeader {
            p_type: PT_LOAD,
            p_flags: PF_R | PF_W,
            p_offset: 0,
            p_vaddr: 0,
            p_paddr: 0,
            p_filesz: 0,
            p_memsz: 0,
            p_align: 0x1000,
        };

        HollowGenerator {
            ehdr,
            phdr: vec![phdr_phdr, phdr_dyn, phdr_header_load],
            dynamic: vec![],
            interp: None,
            dynstr: vec![0u8],
            rela: vec![],
            syms: vec![elfdef::Sym {
                st_name: 0,
                st_info: 0,
                st_other: 0,
                st_shndx: 0,
                st_value: 0,
                st_size: 0,
            }],
            hash: elfdef::DynamicHash::new(),
            segments: vec![],
            entry: (0, 0),
            building_hash: HashMap::new(),
        }
    }

    pub fn add_interp(&mut self, interp: &str)
    {
        let clean_interp = interp.trim_end_matches('\0');
        let cstr = CString::from_str(clean_interp).unwrap();

        self.interp = Some(cstr);
    }

    pub fn add_dynamic(&mut self, dynamic: elfdef::Dyn)
    {
        self.dynamic.push(dynamic);
    }

    pub fn add_segment(&mut self, segment: Bytes, size: usize, flags: u32, index: u32)
    {
        self.segments.push((segment, size, flags, index));
    }

    pub fn add_dependencies(&mut self, name: &CString)
    {
        let loc = self.dynstr.len();
        self.dynstr.append(&mut name.as_bytes_with_nul().to_vec());

        self.add_dynamic(elfdef::Dyn {
            d_tag: DT_NEEDED,
            d_val: loc as u64,
        });
    }

    #[allow(unused)]
    pub fn add_sym(&mut self, mut sym: elfdef::Sym, name: &CString)
    {
        let loc = self.dynstr.len();
        self.building_hash.insert(name.to_str().unwrap().to_string(), self.syms.len() as u32);

        self.dynstr.append(&mut name.as_bytes_with_nul().to_vec());

        sym.st_name = loc as u32;

        self.syms.push(sym);
    }

    #[allow(unused)]
    pub fn add_rela(&mut self, refer_segment: u32, offset: u64, symbol_info: Option<&str>, type_info: u32, addend: u32)
    {
        let mut symbol_index: u64 = 0;

        if let Some(symbol_info) = symbol_info {
            symbol_index = self.building_hash[&symbol_info.to_string()] as u64;
        }

        self.rela.push((elfdef::Rela {
            r_offset: offset,
            r_info: symbol_index << 32 | type_info as u64,
            r_addend: addend as u64,
        }, refer_segment));
    }

    pub fn set_entry(&mut self, offset: u64, refer_segment: u32)
    {
        self.entry = (offset, refer_segment);
    }

    pub fn build(mut self) -> Vec<u8>
    {
        let mut tobe_written = HashMap::<u64, Bytes>::new();
        let dyn_addr;
        let mut current = 64u64; // End of ehdr, start of phdr
        log::info!("{INFO} Header is at {:#0x}", 0);
        log::info!("{INFO} Program Header is at {:#0x}", 64);

        // 3 => A PT_PHDR, A PT_DYNAMIC, A PT_LOAD (Header cover)
        let mut phnum = 3 + self.segments.len();
        if self.interp.is_some() {
            phnum += 1;
        }

        let phsize = self.ehdr.e_phentsize as u64 * phnum as u64;
        self.ehdr.e_phnum = phnum as u16;
        self.phdr[0].p_filesz = phsize;
        self.phdr[0].p_memsz = phsize;

        current += phsize; // End of phdr, start of dyn

        // custom dynamic + DT_NULL + RELA related (3) + HASH + SYMTAM(2) + STRTAB(2)
        let dyn_size = (self.dynamic.len() as u64 + 1 + 4 + 1 + 2 + 2) * size_of::<elfdef::Dyn>() as u64;

        log::info!("{INFO} Dynamic Segment is at {:#0x}", current);
        dyn_addr = current;
        self.phdr[1].p_offset = current;
        self.phdr[1].p_vaddr = current;
        self.phdr[1].p_paddr = current;
        self.phdr[1].p_filesz = dyn_size;
        self.phdr[1].p_memsz = dyn_size;
        current += dyn_size; // End of dyn, start of interp

        if let Some(interp) = self.interp {
            log::info!("{INFO} Interp String is at {:#0x}", current);
            let interp_bytes = interp.as_bytes_with_nul().to_vec();
            self.phdr.push(elfdef::ProgramHeader {
                p_type: PT_INTERP,
                p_flags: PF_R | PF_W,
                p_offset: current,
                p_vaddr: current,
                p_paddr: current,
                p_filesz: interp_bytes.len() as u64,
                p_memsz: interp_bytes.len() as u64,
                p_align: 0x1,
            });
            tobe_written.insert(current, interp_bytes.clone());
            current += interp_bytes.len() as u64; // End of interp, start of rela
        }


        self.dynamic.push(elfdef::Dyn {
            d_tag: DT_RELAENT,
            d_val: 24,
        });

        self.dynamic.push(elfdef::Dyn {
            d_tag: DT_RELASZ,
            d_val: 24 * self.rela.len() as u64,
        });

        self.dynamic.push(elfdef::Dyn {
            d_tag: DT_RELA,
            d_val: current,
        });

        log::info!("{INFO} Rela table is at {:#0x}", current);
        let rela_addr = current;
        current += 24 * self.rela.len() as u64; // End of rela, start of dynsym

        self.dynamic.push(elfdef::Dyn {
            d_tag: DT_SYMENT,
            d_val: 24,
        });

        self.dynamic.push(elfdef::Dyn {
            d_tag: DT_SYMTAB,
            d_val: current,
        });

        log::info!("{INFO} Symbol table is at {:#0x}", current);
        tobe_written.insert(current, self.syms.flatten());
        current += 24 * self.syms.len() as u64;

        self.dynamic.push(elfdef::Dyn {
            d_tag: DT_STRTAB,
            d_val: current,
        });
        self.dynamic.push(elfdef::Dyn {
            d_tag: DT_STRSZ,
            d_val: self.dynstr.len() as u64,
        });

        log::info!("{INFO} Dynamic String table is at {:#0x}", current);
        tobe_written.insert(current, self.dynstr.clone());
        current += self.dynstr.len() as u64; // End of dynstr, start of custom segments

        self.hash.flush(&self.syms, &self.dynstr);

        self.dynamic.push(elfdef::Dyn {
            d_tag: DT_HASH,
            d_val: current,
        });

        log::info!("{INFO} Hash table is at {:#0x}", current);
        let hash_table_bytes = <DynamicHash as Flatten<DynamicHash>>::flatten(&self.hash);
        tobe_written.insert(current, hash_table_bytes.clone());
        current += hash_table_bytes.len() as u64;

        self.dynamic.push(elfdef::Dyn {
            d_tag: DT_NULL,
            d_val: 0,
        });
        tobe_written.insert(dyn_addr, self.dynamic.flatten());

        self.phdr[2].p_filesz = current;
        self.phdr[2].p_memsz = current;

        current = Self::align_upwards(current);
        let mut fp = current;

        for (bytes, memsz, flags, index) in self.segments.iter()
        {
            for (rela, refer) in &mut self.rela
            {
                if *refer == *index
                {
                    rela.r_offset += current;
                }
            }
            
            if *index == self.entry.1 {
                self.ehdr.e_entry = self.entry.0 + current;
            }

            self.phdr.push(elfdef::ProgramHeader {
                p_type: PT_LOAD,
                p_flags: *flags,
                p_offset: current,
                p_vaddr: current,
                p_paddr: current,
                p_filesz: bytes.len() as u64,
                p_memsz: *memsz as u64,
                p_align: 0x1000,
            });

            tobe_written.insert(current, bytes.clone());
            current += *memsz as u64;
            fp += bytes.len() as u64;
            current = Self::align_upwards(current);
            fp = Self::align_upwards(fp);
        }
        
        tobe_written.insert(0, unsafe { plain::as_bytes(&self.ehdr).to_vec() });
        tobe_written.insert(64u64, self.phdr.flatten());
        tobe_written.insert(rela_addr, self.rela.iter().map(|x| x.0).collect::<Vec<elfdef::Rela>>().flatten());

        let mut r = vec![0u8; fp as usize];

        for block in tobe_written
        {
            let addr = block.0;
            let bytes = &block.1;

            r[addr as usize..addr as usize + bytes.len()].copy_from_slice(bytes);
        }

        r
    }
}
```

### loader-rs/relocation.rs

- Size: 4354 bytes
- Modified: 2025-12-19 21:53:39

```text

use goblin::elf::reloc::{R_X86_64_64, R_X86_64_GLOB_DAT, R_X86_64_JUMP_SLOT, R_X86_64_COPY, R_X86_64_RELATIVE};

use hollowell::elfdef::{Rela, SymbolTableEntry};
use hollowell::processes::Process;
use crate::stagger::SymbolResolvable;

use anyhow::{Result};
use hollowell::auxiliary::QuickConver;

type Relr = u64;

#[allow(unused)]
const SUCC: &str = "\x1b[32m[+]\x1b[0m";
#[allow(unused)]
const FAIL: &str = "\x1b[31m[-]\x1b[0m";
#[allow(unused)]
const ALER: &str = "\x1b[31m[!]\x1b[0m";
#[allow(unused)]
const INFO: &str = "\x1b[34m[*]\x1b[0m";

pub trait Relocator
{
    fn do_rela_reloc<T>(&mut self, base: usize, rela: &[Rela], resolver: &T, syms: &[SymbolTableEntry]) -> Result<()>
    where
        T: SymbolResolvable;

    fn do_relr_reloc(&mut self, base: usize, relr: &[Relr]) -> Result<()>;
}

impl Relocator for Process {
    fn do_rela_reloc<T>(&mut self, base: usize, rela: &[Rela], resolver: &T, syms: &[SymbolTableEntry]) -> Result<()>
    where
        T: SymbolResolvable
    {
        for i in rela {
            let sym_index = (i.r_info >> 32) as usize;
            let sym = match syms.get(sym_index) {
                Some(s) => s,
                None => continue,
            };

            if let Some(sym_name) = &sym.sym_name {
                let rel_type = (i.r_info & 0xffffffff) as u32;

                match rel_type {
                    R_X86_64_64 => {
                        match resolver.resolve_symbol(self, sym_name) {
                            Some((_, value)) => {
                                let w = value + i.r_addend as usize;
                                self.write(i.r_offset as usize + base, unsafe { plain::as_bytes(&w) })?;
                            }
                            None => log::error!("{FAIL} Failed to resolve symbol {}, Symbol Bind = {}.", sym_name, sym.sym_bind),
                        }
                    }
                    R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT => {
                        match resolver.resolve_symbol(self, sym_name) {
                            Some((_, value)) => {
                                let w = value;
                                self.write(i.r_offset as usize + base, unsafe { plain::as_bytes(&w) })?;
                            }
                            None => log::error!("{FAIL} Failed to resolve symbol {}, Symbol Bind = {}.", sym_name, sym.sym_bind),
                        }
                    }
                    R_X86_64_COPY => {
                        match resolver.resolve_symbol(self, sym_name) {
                            Some((_, value)) => {
                                let bytes = self.read(value, sym.sym_size as usize)?;
                                self.write(i.r_offset as usize + base, &bytes)?;
                            }
                            None => log::error!("{FAIL} Failed to resolve symbol {}, Symbol Bind = {}.", sym_name, sym.sym_bind),
                        }
                    }
                    R_X86_64_RELATIVE => {
                        let value = base + i.r_addend as usize;
                        self.write(i.r_offset as usize + base, unsafe { plain::as_bytes(&value) })?;
                        log::info!("{SUCC} Relative base+{:#0x}, wrote to base+{:#0x}", i.r_addend, i.r_offset);
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    fn do_relr_reloc(&mut self, base: usize, relr: &[Relr]) -> Result<()>
    {
        const BITS: u64 = 63;
        let mut va: u64 = 0;

        for i in relr {
            if (i & 1u64) == 0 {
                let addr = base + (*i as usize);
                let append = self.read(addr, 8)?.to::<usize>()? + base;
                self.write(addr, unsafe { plain::as_bytes(&append) })?;
                va = addr as u64 + 8u64;
            } else if va != 0 {
                let mut bitmap = i >> 1;
                for b in 0..BITS {
                    if (bitmap & 1u64) != 0u64 {
                        let append = self.read((va + b * 8) as usize, 8)?.to::<usize>()? + base;
                        self.write((va + b * 8) as usize, unsafe { plain::as_bytes(&append) })?;
                    }
                    bitmap >>= 1;
                }

                va += BITS * 8u64;
            }
        }

        Ok(())
    }
}
```

### loader-rs/stagger.rs

- Size: 25120 bytes
- Modified: 2025-12-21 02:25:55

```text
use anyhow::{Context, Result, bail};
use console::{Key, Term};
use goblin::elf::dynamic::{
    DT_FINI, DT_FINI_ARRAY, DT_FINI_ARRAYSZ, DT_FLAGS, DT_FLAGS_1, DT_INIT, DT_INIT_ARRAY,
    DT_INIT_ARRAYSZ, DT_NEEDED,
};
use goblin::elf::program_header::{PF_R, PF_W, PF_X};
use goblin::elf::reloc::R_X86_64_RELATIVE;
use goblin::elf::section_header::{
    SHF_ALLOC, SHN_UNDEF, SHT_DYNAMIC, SHT_DYNSYM, SHT_FINI_ARRAY, SHT_INIT_ARRAY, SHT_NOBITS,
    SHT_PROGBITS, SHT_RELA,
};
use goblin::elf::sym::{STB_GLOBAL, STT_FUNC, STT_GNU_IFUNC, STT_NOTYPE, STT_OBJECT, STT_TLS};
use goblin::elf32::section_header::SHF_EXECINSTR;
use std::collections::HashMap;
use std::ffi::CString;

use hollowell::elfdef::{Dyn, Rela, SHT_RELR, SymbolTableEntry, get_shared_object_path};
use nix::sys::memfd::{MFdFlags, memfd_create};
use nix::sys::ptrace;
use nix::sys::ptrace::Options;
use nix::sys::signal::Signal;
use nix::sys::signal::Signal::{SIGILL, SIGSEGV, SIGTRAP};
use nix::sys::wait::WaitStatus;
use nix::unistd::{ForkResult, Pid, Whence, lseek, write};
use rand::Rng;

use crate::fexecve_with_current_argv_env;
use crate::hollowgen::HollowGenerator;
use crate::relocation::Relocator;
use crate::tui::UI;
use hollowell::asm::{Assembly, assemble};
use hollowell::auxiliary::{BlockLocator, BlockLocatorInMemory, ChunkMeta, ChunkMetaInMemory, ProgramHeaderExt, QuickConver, RandomLength};
use hollowell::chunk::{Chunk, get_ehdr};
use hollowell::chunk::{get_chunks_by_filter, get_phdr, hash_sha256};
use hollowell::elf::ExecuteLinkFile;
use hollowell::elfdef;
use hollowell::processes::Process;

use crate::debug::HollowStageDebug;

type Relr = u64;
type Bytes = Vec<u8>;

#[allow(unused)]
const SUCC: &str = "\x1b[32m[+]\x1b[0m";
#[allow(unused)]
const FAIL: &str = "\x1b[31m[-]\x1b[0m";
#[allow(unused)]
const ALER: &str = "\x1b[31m[!]\x1b[0m";
#[allow(unused)]
const INFO: &str = "\x1b[34m[*]\x1b[0m";

const WINDOW_SIZE: u32 = u32::MAX;

pub struct HollowStage {
    pub data: Vec<u8>,
    pub deps: Vec<(String, HashMap<String, SymbolTableEntry>)>,
    pub rela: Vec<Rela>,
    pub relr: Vec<Relr>,
    pub syms: Vec<SymbolTableEntry>,
    pub chunks: Vec<(Chunk, Option<Bytes>)>,

    pub procs: HashMap<i32, Process>,
    pub major: Pid,
    pub instruction_blocks: Vec<ChunkMeta>,
    pub window: Vec<ChunkMetaInMemory>,
    pub tui: Option<UI>,

    pub instruction_area: (u64, u64),
    pub debug: HollowStageDebug,
    pub do_relocate: bool
}

impl HollowStage {
    pub fn allocate_randomly(
        instruction_area: (u64, u64),
        blocks: &[(u64, u64)],
        request_size: u64,
    ) -> Option<u64> {
        let (area_start, area_end) = instruction_area;
        if request_size == 0 || area_end <= area_start {
            return None;
        }

        let available_space = area_end - area_start;
        if request_size > available_space {
            return None;
        }

        let max_start_addr = area_end - request_size;

        let mut rng = rand::rng();
        const MAX_RETRIES: usize = 32;

        for _ in 0..MAX_RETRIES {
            // 1. Randomly propose a candidate address
            // complexity: O(1)
            let mut candidate = rng.random_range(area_start..=max_start_addr);
            candidate &= !0xfu64;

            if !Self::is_overlapping(candidate, request_size, blocks) {
                return Some(candidate);
            }
        }

        None
    }

    #[inline]
    fn is_overlapping(candidate: u64, size: u64, blocks: &[(u64, u64)]) -> bool {
        let candidate_end = candidate + size;

        for &(b_addr, b_size) in blocks {
            let b_end = b_addr + b_size;

            if candidate < b_end && candidate_end > b_addr {
                return true;
            }
        }
        false
    }

    pub fn build() -> Result<Self>
    {
        let phdr = get_phdr()?;

        let mut builder = HollowGenerator::new_x86_64();
        let image_size = phdr.as_slice().get_image_size();

        let mut deps: Vec<String> = Vec::new();
        let mut rela: Vec<Rela> = Vec::new();
        let mut relr: Vec<Relr> = Vec::new();
        let mut syms: Vec<SymbolTableEntry> = Vec::new();
        let mut chunks: Vec<(Chunk, Option<Bytes>)> = Vec::new();

        if let Some((_, Some(interp))) =
            get_chunks_by_filter(|x| hash_sha256(".interp".as_bytes()) == x.name_hash).first()
        {
            let interp_str = String::from_utf8(interp.to_vec())?;
            builder.add_interp(&interp_str);
        }

        if let Some((_, Some(dynamic))) =
            get_chunks_by_filter(|x| x.chunk_type == SHT_DYNAMIC).first()
            && let Some((_, Some(dynstr))) =
                get_chunks_by_filter(|x| hash_sha256(".dynstr".as_bytes()) == x.name_hash).first()
        {
            if let Some((_, Some(dynsym))) =
                get_chunks_by_filter(|x| x.chunk_type == SHT_DYNSYM).first()
            {
                let slice_syms = plain::slice_from_bytes::<elfdef::Sym>(&dynsym)
                    .ok()
                    .context("failed to parse plain dynamic")?;

                syms = slice_syms
                    .iter()
                    .map(|x| x.as_entry(&dynstr))
                    .collect::<Vec<SymbolTableEntry>>();
            }

            let dynamic = plain::slice_from_bytes::<Dyn>(&dynamic)
                .ok()
                .context("failed to parse plain dynamic")?;

            for d in dynamic.iter() {
                match d.d_tag {
                    DT_NEEDED => {
                        let len = dynstr.as_slice().strlen(d.d_val as usize);
                        let bytes = dynstr[d.d_val as usize..d.d_val as usize + len].to_vec();
                        let cstr = CString::new(bytes)?;
                        deps.push(cstr.to_str()?.to_string());
                        builder.add_dependencies(&cstr);
                    }
                    DT_INIT | DT_FINI | DT_INIT_ARRAY | DT_FINI_ARRAY | DT_INIT_ARRAYSZ
                    | DT_FINI_ARRAYSZ | DT_FLAGS | DT_FLAGS_1 => {
                        builder.add_dynamic(Dyn {
                            d_tag: d.d_tag,
                            d_val: d.d_val,
                        });
                    }
                    _ => {}
                }
            }
        }

        for (_, r) in get_chunks_by_filter(|x| x.chunk_type == SHT_RELA) {
            if let Some(br) = r {
                let cr = plain::slice_from_bytes::<Rela>(&br)
                    .ok()
                    .context("failed to parse plain rela")?;
                for d in cr.iter() {
                    rela.push(d.to_owned());
                }
            }
        }

        for (_, r) in get_chunks_by_filter(|x| x.chunk_type == SHT_RELR) {
            if let Some(br) = r {
                let cr = plain::slice_from_bytes::<Relr>(&br)
                    .ok()
                    .context("failed to parse plain rela")?;
                for d in cr.iter() {
                    relr.push(d.to_owned());
                }
            }
        }

        for (v, r) in get_chunks_by_filter(|x| {
            matches!(
                x.chunk_type,
                SHT_PROGBITS | SHT_NOBITS | SHT_INIT_ARRAY | SHT_FINI_ARRAY
            ) && (x.flags & (SHF_ALLOC as u64) != 0)
        }) {
            chunks.push((v, r));
        }

        builder.add_segment(vec![0xcc; 16], image_size * 2, PF_R | PF_W | PF_X, 0);

        builder.set_entry(0x8, 0);
        builder.add_rela(0, 0, None, R_X86_64_RELATIVE, 0);

        let mut recursive_deps = Vec::<String>::new();

        deps = deps
            .iter()
            .filter_map(|x| get_shared_object_path(&x))
            .collect::<Vec<String>>();

        for dep in &deps {
            ExecuteLinkFile::get_dependencies_recursively(&dep, &mut recursive_deps)?;
        }

        recursive_deps = recursive_deps
            .iter()
            .filter(|x| !deps.contains(&x))
            .map(|x| x.to_string())
            .collect::<Vec<String>>();

        deps.append(&mut recursive_deps);

        let dk = deps
            .iter()
            .filter_map(|x| {
                if let Some(e) = ExecuteLinkFile::prase(&x).ok()
                    && let Some(s) = e.get_dynsym_table().ok()
                {
                    let s = s
                        .into_iter()
                        .filter(|x| (*x).1.sym_ndx != SHN_UNDEF as u16)
                        .collect();

                    return Some((x.to_owned(), s));
                }

                None
            })
            .collect::<Vec<_>>();

        anyhow::Ok(HollowStage {
            data: builder.build(),
            deps: dk,
            rela,
            relr,
            syms,
            chunks,
            procs: HashMap::new(),
            major: Pid::from_raw(0),
            instruction_blocks: Vec::new(),
            window: Vec::new(),
            tui: None,
            instruction_area: (u64::MAX, 0),
            do_relocate: true,

            debug: HollowStageDebug {
                focused_origin: vec![],
                focused_relocated: vec![],
                ips: (0, 0),
                debug: false,
                tui: false,
                ins_number: 0,
                clear: false,
                focused_near: vec![],
                major: None
            },
        })
    }

    pub fn startup(&mut self) -> Result<Pid> {
        let hollow_mem = memfd_create("hollow", MFdFlags::empty())?;
        write(&hollow_mem, &self.data)?;
        lseek(&hollow_mem, 0, Whence::SeekSet)?;

        let child = match unsafe { nix::unistd::fork() }? {
            ForkResult::Parent { child } => child,
            ForkResult::Child => {
                ptrace::traceme()?;
                fexecve_with_current_argv_env(hollow_mem)?;

                Pid::from_raw(0)
            }
        };

        Process::waitpid(child)?;

        ptrace::setoptions(child, Options::PTRACE_O_TRACECLONE)?;

        self.major = child;
        self.debug.major = Some(Process::new(child)?);
        Ok(child)
    }

    pub fn prepare(&mut self) -> Result<()> {
        let ehdr = get_ehdr()?;

        let mut proc = Process::new(self.major)?;
        log::info!("{SUCC} Opened process {}", self.major);
        proc.cont()?;
        Process::wait()?;

        let regs = proc.get_regs()?;

        let sbase = regs.rip - 1 - 8;
        let base = proc.read((regs.rip - 1 - 8) as usize, 8)?.to::<u64>()?;
        log::info!(
            "{SUCC} Hollow process load main module at {:#0x}, Base is {:#0x}",
            base,
            base
        );

        for i in self.chunks.iter() {
            if let (s, Some(b)) = i
                && s.vaddr >= (sbase - base)
            {
                if s.flags & SHF_EXECINSTR as u64 == 0 {
                    proc.map_region(base as usize, &s, b)?;
                } else {
                    let sa = base as usize + s.vaddr as usize;

                    if sa as u64 <= self.instruction_area.0 {
                        self.instruction_area.0 = sa as u64;
                    }

                    if sa + s.size as usize > self.instruction_area.1 as usize {
                        self.instruction_area.1 = sa as u64 + s.size;
                    }

                    proc.write(sa, &vec![0xccu8; s.size as usize])?;
                    self.instruction_blocks.push(ChunkMeta {
                        address: sa as u64,
                        fault_counter: 0,
                        in_window: false,
                        data: b.to_vec(),
                    });
                }
            }
        }

        self.instruction_blocks
            .sort_by(|a, b| a.address.cmp(&b.address));

        if let Err(_) = proc.disassemble_rip_log() {
            log::error!("{FAIL} Failed to disassemble rip.");
        }

        proc.flush_map()?;
        proc.do_rela_reloc(base as usize, &self.rela, &self.deps, &self.syms)?;
        proc.do_relr_reloc(base as usize, &self.relr)?;

        let phdr = get_phdr()?;
        let image_size = phdr.as_slice().get_image_size();

        let dp = sbase + image_size as u64;
        self.instruction_area.0 = dp;
        self.instruction_area.1 = dp + image_size as u64;
        proc.write(dp as usize, &vec![0xccu8; image_size])?;

        proc.redirect(base + ehdr.e_entry)?;
        self.procs.insert(self.major.as_raw(), proc);

        Ok(())
    }

    fn swap_chunk(&mut self) -> Result<()> {
        if self.window.len() > WINDOW_SIZE as usize {
            let r = self.window[0].to_owned();
            self.window.remove(0);

            if let Some(m) = self.instruction_blocks.find_block(r.origin_address) {
                m.in_window = false;
                self.procs[&self.major.as_raw()].write(r.relocated as usize, &vec![0xccu8; r.data.len()])?;
                self.procs[&self.major.as_raw()].write(m.address as usize, &vec![0xccu8; m.data.len()])?;
            }
        }

        Ok(())
    }

    fn cross_chunk(&mut self, rip: usize, tid: i32) -> Result<()>
    {
        if let Some(k) = self.instruction_blocks.find_block(rip as u64) {
            log::debug!("{INFO} {} trapped in origin chunk {}", tid, self.procs[&tid].map.format_address(k.address as usize));
            // If rip trapped in a known chunk
            // We consider whether it has not been loaded
            // or has been loaded but repositioned
            if k.in_window {
                // Chunk has already been loaded, but relocated
                if let Some(v) = self.window.find_block_out_memory(k.address) {
                    log::debug!("{INFO} Chunk {} has already been loaded at {}",
                        self.procs[&tid].map.format_address(k.address as usize),
                        self.procs[&tid].map.format_address(v.relocated as usize));
                    let mut origin = Assembly::new(&k.data);
                    let mut relocated = Assembly::new(&v.data);

                    let nip = origin.byte_offset_to_ip(rip - k.address as usize)?;
                    let r_offset = relocated.ip_to_byte_offset(nip)?;

                    self.procs[&tid].redirect(v.relocated + r_offset as u64)?;
                    self.debug.debug_flush_block(&k, &v, (rip, v.relocated as usize + r_offset), nip)?;

                    // Insert stub code
                    let stub = assemble(rip as u64, |asm| {
                        asm.jmp(v.relocated + r_offset as u64)?;
                        Ok(())
                    })?;
                    if rip + stub.len() < k.address as usize + k.data.len()
                    {
                        self.procs[&tid].write(rip, &stub)?;
                    }
                } else {
                    bail!("Trapped in in-window thunks, but can't find in window. ");
                }
            }
            else {
                // Chunk has not been loaded, swap it to memory
                let mut c = ChunkMetaInMemory {
                    data: vec![],
                    relocated: k.address,
                    origin_address: k.address,
                };

                k.fault_counter += 1;
                k.in_window = true;

                let ra = Self::allocate_randomly(
                    self.instruction_area,
                    &self.window.iter().map(|x| (x.relocated, x.data.len() as u64)).collect::<Vec<_>>(),
                    k.data.len() as u64 * 2,
                );

                if self.do_relocate && let Some(a) = ra {
                    let r = Assembly::instruction_relocate(
                        k.address as usize,
                        &k.data,
                        a,
                    )?.code_buffer;

                    c.relocated = a;
                    c.data = r;

                    log::info!("{SUCC} {} Bytes of instruction relocated to {} from {}",
                        k.data.len(),
                        self.procs[&tid].map.format_address(a as usize),
                        self.procs[&tid].map.format_address(k.address as usize));
                } else {
                    c.relocated = k.address;
                    c.data = k.data.to_vec();
                }

                self.procs[&tid].write(c.relocated as usize, &c.data)?;

                let mut origin = Assembly::new(&k.data);
                let mut relocated = Assembly::new(&c.data);

                let nip = origin.byte_offset_to_ip(rip - k.address as usize)?;
                let r_offset = relocated.ip_to_byte_offset(nip)?;
                let relocated_ip = c.relocated as usize + r_offset;

                self.procs[&tid].redirect(relocated_ip as u64)?;
                self.debug.debug_flush_block(&k, &c, (rip, relocated_ip), nip)?;

                self.window.push(c);
            }
        }
        else if let Some(vv) = self.window.find_block_tail(rip as u64)
            && let Some(k) = self.instruction_blocks.find_block_after(vv.origin_address)
        {
            log::debug!("{INFO} {} trapped after relocated chunk {}", tid, self.procs[&tid].map.format_address(vv.relocated as usize));
            let mut c = ChunkMetaInMemory {
                data: vec![],
                relocated: k.address,
                origin_address: k.address,
            };

            k.fault_counter += 1;
            k.in_window = true;

            let ra = Self::allocate_randomly(
                self.instruction_area,
                &self.window.iter().map(|x| (x.relocated, x.data.len() as u64)).collect::<Vec<_>>(),
                k.data.len() as u64 * 2,
            );

            if self.do_relocate && let Some(a) = ra {
                let r = Assembly::instruction_relocate(
                    k.address as usize,
                    &k.data,
                    a,
                )?.code_buffer;

                c.relocated = a;
                c.data = r;

                log::info!("{SUCC} {} Bytes of instruction relocated to {} from {}",
                        k.data.len(),
                        self.procs[&tid].map.format_address(a as usize),
                        self.procs[&tid].map.format_address(k.address as usize));
            } else {
                c.relocated = k.address;
                c.data = k.data.to_vec();
            }

            self.procs[&tid].write(c.relocated as usize, &c.data)?;


            self.procs[&tid].redirect(c.relocated)?;
            self.debug.debug_flush_block(&k, &c, (rip, c.relocated as usize), 0)?;

            self.window.push(c);
        } else {
            let ip = self.procs[&tid].getip()?;

            log::error!(
                "{FAIL} Critical error with rip: {}",
                self.procs[&tid].map.format_address(ip)
            );

            self.procs.get_mut(&tid).unwrap().disassemble_rip_log()?;

            bail!("What?????");
        }

        Ok(())
    }

    fn handler_trap(&mut self, tid: Pid) -> Result<Pid> {
        let ip = self.procs[&tid.as_raw()].redirect_relative(-1)?;
        self.swap_chunk()?;
        self.cross_chunk(ip, tid.as_raw() as i32)?;

        if let Some(tui) = self.tui.as_mut() {
            tui.flush(&mut self.debug)?;
        }

        Ok(tid)
    }

    fn handler_other(&mut self, tid: Pid, sig: Signal) -> Result<Pid> {
        if sig == SIGSEGV || sig == SIGILL {
            let ip = self.procs[&tid.as_raw()].getip()?;

            log::error!(
                "{FAIL} Critical error with rip: {}",
                self.procs[&tid.as_raw()].map.format_address(ip)
            );

            self.procs.get_mut(&tid.as_raw()).unwrap().disassemble_rip_log()?;

            bail!("Critical error");
        }

        Ok(tid)
    }

    fn handler_exited(&mut self, tid: Pid) -> Result<Pid> {
        self.procs.remove(&tid.as_raw());
        if tid.as_raw() == self.major.as_raw() {
            bail!("{FAIL} Exited. ");
        }

        Ok(tid)
    }

    fn handler_event(&mut self, tid: Pid) -> Result<Pid> {
        let new_tid = ptrace::getevent(tid)? as libc::pid_t;
        log::info!("{INFO} New thread is {}", new_tid);
        Ok(tid)
    }

    pub fn staging(&mut self) -> Result<()> {
        let term = Term::stdout();
        self.procs[&self.major.as_raw()].cont()?;

        if !self.debug.debug || self.tui.is_some() {
            log::set_max_level(log::LevelFilter::Off);
        }

        loop {
            let status = Process::wait().context("Failed to wait on child")?;

            if let Some(tid) = status.pid()
                && !self.procs.contains_key(&tid.as_raw())
            {
                self.procs.insert(tid.as_raw(), Process::new(tid)?);
            }

            let tid = match status {
                WaitStatus::Stopped(tid, SIGTRAP) => self.handler_trap(tid),
                WaitStatus::Stopped(tid, sig) => self.handler_other(tid, sig),
                WaitStatus::Exited(tid, _) => self.handler_exited(tid),
                WaitStatus::PtraceEvent(tid, SIGTRAP, _) => self.handler_event(tid),
                WaitStatus::PtraceSyscall(tid) | WaitStatus::Continued(tid) => Ok(tid),
                _ => Ok(self.major),
            }?.as_raw();

            if !self.procs.contains_key(&tid) {
                continue;
            }

            if !self.debug.debug {
                self.procs[&tid].cont()?;
                continue;
            }

            while self.debug.debug {
                match term.read_key() {
                    Ok(Key::Char(c)) => match c {
                        'n' => {
                            self.procs[&tid].stepover()?;
                        }
                        's' => {
                            self.procs[&tid].step()?;
                        }
                        'c' => {
                            self.procs[&tid].cont()?;
                            break;
                        }
                        'q' => {
                            self.procs[&tid].kill()?;
                            return Ok(());
                        }
                        _ => {}
                    },
                    _ => {}
                }

                let ip = self.procs[&tid].getip()?;
                if self.window.find_block_in_memory(ip as u64).is_none() {
                    self.cross_chunk(ip, tid)?;
                }
                let ip = self.procs[&tid].getip()?;

                if let Some(tui) = self.tui.as_mut() {
                    if let Some(k) = self.window.find_block_in_memory(ip as u64)
                        && let Some(c) = self.instruction_blocks.find_block(k.origin_address) {
                        let mut origin = Assembly::new(&c.data);
                        let mut relocated = Assembly::new(&k.data);

                        let nip = relocated.byte_offset_to_ip(ip - k.relocated as usize)?;
                        let r_offset = origin.ip_to_byte_offset(nip)?;

                        self.debug.debug_flush_ip((c.address as usize + r_offset, ip), nip)?;
                    }
                    tui.flush(&mut self.debug)?;
                } else {
                    self.procs
                        .get_mut(&tid)
                        .context("")?
                        .disassemble_rip_log()?;
                }
            }
        }
    }
}

pub trait SymbolResolvable {
    fn resolve_symbol(&self, process: &mut Process, name: &str) -> Option<(String, usize)>;
}

impl<T> SymbolResolvable for T
where
    T: AsRef<[(String, HashMap<String, SymbolTableEntry>)]>,
{
    fn resolve_symbol(&self, process: &mut Process, name: &str) -> Option<(String, usize)> {
        let mut r: Option<(String, usize)> = None;

        for (dep, hash) in self.as_ref() {
            if let Some(v) = hash.get(name) {
                let base = process.module_base_address(dep)?;
                r = match v.sym_type {
                    STT_NOTYPE | STT_OBJECT | STT_FUNC => {
                        Some((dep.clone(), base as usize + v.sym_value as usize))
                    }
                    STT_TLS => Some((dep.clone(), v.sym_value as usize)),
                    STT_GNU_IFUNC => {
                        let resolver = base as usize + v.sym_value as usize;

                        let rp = process
                            .execute_once_inplace(
                                |addr| {
                                    assemble(addr, |asm| {
                                        asm.call(resolver as u64)?;
                                        asm.int3()?;
                                        Ok(())
                                    })
                                    .ok()
                                },
                                |_| {},
                            )
                            .ok()?;

                        Some((dep.clone(), rp.rax as usize))
                    }
                    _ => None,
                };

                if v.sym_bind == STB_GLOBAL {
                    break;
                }
            }
        }

        r
    }
}

```

### loader-rs/tui.rs

- Size: 3846 bytes
- Modified: 2025-12-20 20:25:17

```text
use std::cmp::min;

use crate::debug::HollowStageDebug;

use anyhow::Result;
use crossterm::{
    execute,
    terminal::{EnterAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use hollowell::asm::DynamicFormatter;

use ratatui::widgets::{List, ListDirection};
use ratatui::{
    layout::{Constraint, Direction, Layout},
    prelude::*,
    style::{Modifier, Style},
    text::{Line},
    widgets::{Block, Borders, Cell, Row, Table, TableState},
};
use std::io;
use std::io::Stdout;

pub struct UI {
    pub terminal: Terminal<CrosstermBackend<Stdout>>,
    pub table_state: TableState,
}

impl UI {
    pub fn new() -> Result<Self> {
        enable_raw_mode()?;
        execute!(io::stdout(), EnterAlternateScreen)?;

        let backend = CrosstermBackend::new(io::stdout());
        let terminal = Terminal::new(backend)?;

        let mut table_state = TableState::default();
        table_state.select(Some(0));

        Ok(UI { terminal, table_state })
    }

    pub fn flush(&mut self, hd: &mut HollowStageDebug) -> Result<()> {
        if hd.clear {
            self.terminal.clear()?;
            hd.clear = false;
        }

        if let Some(major) = &hd.major {
            self.terminal.draw(|f| {
                let size = f.area();
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Min(25), Constraint::Length(12)])
                    .split(size);

                let header_cells = [
                    format!("Origin ({})", major.map.format_address(hd.focused_origin[0].ip() as usize)),
                    format!("Relocated ({})", major.map.format_address(hd.focused_relocated[0].ip() as usize)),
                ].into_iter().map(|h| {
                    Cell::from(Line::from((*h).to_string()))
                        .style(Style::default().add_modifier(Modifier::BOLD))
                });
                let header = Row::new(header_cells).height(1);

                let t1 = hd.focused_origin
                    .iter()
                    .map(|x| x.format_tui(hd.ips.0, &major.map))
                    .collect::<Vec<_>>();

                let t2 = hd.focused_relocated
                    .iter()
                    .map(|x| x.format_tui(hd.ips.1, &major.map))
                    .collect::<Vec<_>>();

                let widths = [
                    Constraint::Fill(1),
                    Constraint::Fill(1),
                ];
                let mut rows = Vec::new();
                for i in 0..min(t1.len(), t2.len()) {
                    rows.push(Row::new(vec![t1[i].clone(), t2[i].clone()]));
                }

                let asm_block = Block::default()
                    .borders(Borders::ALL)
                    .title("Assembly");

                let table = Table::new(rows, widths)
                    .header(header)
                    .block(asm_block)
                    .column_spacing(1);

                f.render_stateful_widget(table, chunks[0], &mut self.table_state);

                let list = List::new(hd.focused_near.iter().map(|x| x.format_tui(major.getip().unwrap_or(0), &major.map)).collect::<Vec<_>>())
                    .block(Block::bordered().title("Messages"))
                    .style(Style::new().white())
                    .highlight_style(Style::new().italic())

                    .highlight_symbol(">>")
                    .repeat_highlight_symbol(true)
                    .direction(ListDirection::TopToBottom);

                f.render_widget(list, chunks[1]);

                self.table_state.select(Some(hd.ins_number));
            })?;
        }

        Ok(())
    }

    pub fn clean(&mut self) {
        disable_raw_mode().unwrap();
    }
}

impl Drop for UI {
    fn drop(&mut self) {
        self.clean();
    }
}

```

### obj/Makefile

- Size: 406 bytes
- Modified: 2025-12-18 18:17:21

```text

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
```


-----

## Summary

- Total files scanned: 26
- Included text files: 22
- Skipped binary files: 0
- Skipped ignored files: 4
- Unreadable files: 0
- Truncated files (per-file cap): 0
