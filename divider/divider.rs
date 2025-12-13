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
