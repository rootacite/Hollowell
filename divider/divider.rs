
mod elf;

use std::*;
use std::mem::size_of;
use anyhow::*;

use plain::Plain;

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

fn main() -> Result<()>
{
    let arg = env::args().into_iter().collect::<Vec<String>>();
    if arg.len() < 2 {
        return Err(anyhow!("No operation object."));
    }

    let elf_path = arg[1].clone();
    let elf_parser = ExecuteLinkFile::prase(&elf_path).expect(&format!("{FAIL} Is this really a elf ??"));
    let elf_data = fs::read(elf_path)?;

    let b_ehdr = &elf_data[0..size_of::<Header>()];
    fs::write("ehdr.bin", &b_ehdr)?;
    println!("{SUCC} Wrote {} bytes to ehdr.bin", b_ehdr.len());

    let off_phdr = elf_parser.borrow_elf().header.e_phoff as usize;
    let sz_phdr = elf_parser.borrow_elf().header.e_phnum as usize * elf_parser.borrow_elf().header.e_phentsize as usize;
    let b_phdr = &elf_data[off_phdr..off_phdr + sz_phdr];
    fs::write("phdr.bin", &b_phdr)?;
    println!("{SUCC} Wrote {} bytes to phdr.bin", b_phdr.len());

    for p in elf_parser.get_loads().expect(&format!("{FAIL} An elf file without PT_LOADs ?"))
    {
        let b_load = &elf_data[p.p_offset as usize..(p.p_offset + p.p_filesz) as usize];
        fs::write(format!("{:#0x}.bin", p.p_vaddr), b_load)?;
        println!("{SUCC} Wrote {} bytes to {:#0x}.bin", b_load.len(), p.p_vaddr);
    }

    Ok(())
}