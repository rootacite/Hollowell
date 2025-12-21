
use anyhow::*;
use goblin::elf::section_header::{SHF_EXECINSTR, SHT_NOBITS, SHT_NOTE, SHT_NULL};

use std::mem::size_of;
use std::{env, fs};
use hollowell::{elf, elfdef};
use hollowell::asm::Assembly;
use hollowell::chunk::{hash_sha256, write_compressed, Chunk};
use hollowell::elfdef::Header;
use hollowell::auxiliary::Flatten;

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
    let mut cc = 0u32;

    loop {
        let b = decoder.next_branch()?;

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
        println!("{INFO} Chunk {} from {:#0x} sized {:#0x}", cc, sec.sh_addr + ip,b as u64 - ip);
        cc += 1;

        tab.push(entry);
        ip = b as u64;
        if ip >= bytes.len() as u64
        {
            break Ok(());
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
            println!("{INFO} Included section {}.", i.sh_name);

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
    println!("{INFO} Origin file divided to {} chunks. ", ct.len());

    write_chunk_table(&ct, &seed, &output_path)?;
    write_chunks(&elf_data, &ct, &seed, &output_path)?;

    Ok(())
}
