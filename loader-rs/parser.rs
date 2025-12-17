use std::collections::HashMap;
use crate::chunk;
use crate::elfdef;

use anyhow::{Context, Result};
use anyhow::bail;
use crate::auxiliary::ProgramHeaderExt;

#[allow(unused)]
pub fn get_ehdr() -> Result<elfdef::Header>
{
    let ehdr_bytes = chunk::get_chunk_by_name("ehdr")?;
    let Ok(ehdr) = plain::from_bytes::<elfdef::Header>(&ehdr_bytes) else { bail!("Could not parse ELF header") };

    Ok(ehdr.clone())
}

pub fn get_phdr() -> Result<Vec<elfdef::ProgramHeader>>
{
    let phdr_bytes = chunk::get_chunk_by_name("phdr")?;
    let Ok(phdr) = plain::slice_from_bytes::<elfdef::ProgramHeader>(&phdr_bytes) else { bail!("Could not parse Program header") };

    Ok(phdr.to_vec())
}

pub fn peek_data_at(phdr: &[elfdef::ProgramHeader], address: usize, size: usize) -> Result<Vec<u8>>
{
    let mut chunk_map = HashMap::<u64, Vec<u8>>::new();
    let mut result = Vec::<u8>::new();
    
    for addr in address..address + size {
        let p = phdr.locate(addr).context("Could not locate address.")?;
        if !chunk_map.contains_key(&p.p_vaddr)
        {
            let chunk = chunk::get_chunk_by_vdata(p.p_vaddr)?;
            chunk_map.insert(p.p_vaddr, chunk);
        }
        
        let chunk = chunk_map.get(&p.p_vaddr).context("Could not find chunk.")?;
        result.push(chunk[addr - p.p_vaddr as usize]);
    }
    
    Ok(result)
}