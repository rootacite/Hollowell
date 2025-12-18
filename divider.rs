
use anyhow::*;
use goblin::elf::section_header::{SHT_NOBITS, SHT_NOTE, SHT_NULL};
use std::io::Write;
use std::mem::size_of;
use std::{env, fs};
use std::ops::DerefMut;
use flate2::Compression;
use flate2::write::GzEncoder;

use plain::Plain;
use sha2::{Digest, Sha256};

use hollowell::{elf, elfdef};

#[repr(transparent)]
pub struct Header(goblin::elf::Header);
unsafe impl Plain for Header {}

pub trait Flatten {
    fn flatten(&self) -> Vec<u8>;
}

impl<T> Flatten for &[T]
    where T: Plain
{
    fn flatten(&self) -> Vec<u8>
    {
        let mut flattened: Vec<u8> = Vec::new();
        for i in self.iter()
        {
            let mut b = unsafe { plain::as_bytes::<T>(&i) }.to_vec();
            flattened.append(&mut b);
        }

        flattened
    }
}

#[allow(unused)]
const SUCC: &str = "\x1b[32m[+]\x1b[0m";
#[allow(unused)]
const FAIL: &str = "\x1b[31m[-]\x1b[0m";
#[allow(unused)]
const ALER: &str = "\x1b[33m[!]\x1b[0m";
#[allow(unused)]
const INFO: &str = "\x1b[34m[*]\x1b[0m";

fn hash_sha256(data: &[u8]) -> Vec<u8>
{
    let mut hasher = Sha256::new();
    hasher.update(data);
    let key: sha2::digest::generic_array::GenericArray<u8, sha2::digest::typenum::UInt<sha2::digest::typenum::UInt<sha2::digest::typenum::UInt<sha2::digest::typenum::UInt<sha2::digest::typenum::UInt<sha2::digest::typenum::UInt<sha2::digest::typenum::UTerm, sha2::digest::consts::B1>, sha2::digest::consts::B0>, sha2::digest::consts::B0>, sha2::digest::consts::B0>, sha2::digest::consts::B0>, sha2::digest::consts::B0>> = hasher.finalize();

    key.as_slice().to_owned()
}

fn confuse_data(data: &mut [u8], seed: &str) -> Result<()>
{
    let key = hash_sha256(&seed.as_bytes());

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

fn write_base(elf_data: &[u8], elf_parser: &elf::ExecuteLinkFile, seed: &str) -> Result<()>
{
    let b_ehdr = &elf_data[0..size_of::<Header>()];
    write_compressed("ehdr.bin", &b_ehdr, seed)?;
    println!("{SUCC} Wrote {} bytes to ehdr.bin", b_ehdr.len());

    let off_phdr = elf_parser.borrow_elf().header.e_phoff as usize;
    let sz_phdr = elf_parser.borrow_elf().header.e_phnum as usize
        * elf_parser.borrow_elf().header.e_phentsize as usize;
    let b_phdr = &elf_data[off_phdr..off_phdr + sz_phdr];
    write_compressed("phdr.bin", &b_phdr, seed)?;
    println!("{SUCC} Wrote {} bytes to phdr.bin", b_phdr.len());

    Ok(())
}

fn write_chunk_table(secs: &[elfdef::SectionHeader], seed: &str) -> Result<()>
{
    let mut tab = Vec::<hollowell::chunk::Chunk>::new();

    for i in secs {
        let mut entry = hollowell::chunk::Chunk {
            name_hash: [0u8; 32],
            vaddr: i.sh_addr,
            chunk_type: i.sh_type,
            size: i.sh_size,
            flags: i.sh_flags,
            align: i.sh_addralign,
            link: i.sh_link,
            info: i.sh_info,
            entsize: i.sh_entsize,
        };
        entry.name_hash.copy_from_slice(hash_sha256(i.sh_name.as_bytes()).as_slice());

        tab.push(entry);
    }

    let b_tab = tab.as_slice().flatten();
    write_compressed("ct.bin", &b_tab, seed)?;
    println!("{SUCC} Wrote {} bytes to ct.bin", b_tab.len());
    Ok(())
}

fn write_chunks(elf_data: &[u8], secs: &[elfdef::SectionHeader], seed: &str) -> Result<()>
{
    for i in secs
    {
        if i.sh_type != SHT_NOBITS && i.sh_addr != 0
        {
            let bytes = &elf_data[i.sh_offset as usize..i.sh_offset as usize + i.sh_size as usize];
            write_compressed(&format!("{:#0x}.bin", i.sh_addr), bytes, seed)?;
            println!("{SUCC} Wrote {} bytes to {}", bytes.len(), &format!("{:#0x}.bin", i.sh_addr));
        }
    }

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
    let seed = arg[2].clone();
    let elf_parser = elf::ExecuteLinkFile::prase(&elf_path).expect(&format!("{FAIL} Is this really a elf ??"));
    let elf_data = fs::read(elf_path)?;

    write_base(&elf_data, &elf_parser, &seed)?;

    let secs = elf_parser.get_sec_table()?;
    let secs = secs
        .into_iter().filter(|x| x.sh_type != SHT_NULL && x.sh_type != SHT_NOTE)
        .collect::<Vec<elfdef::SectionHeader>>();

    write_chunk_table(&secs, &seed)?;
    write_chunks(&elf_data, &secs, &seed)?;

    Ok(())
}
