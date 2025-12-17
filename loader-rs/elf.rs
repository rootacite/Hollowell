
// elf.rs

use std::collections::HashMap;
use anyhow::{Context, Result};
use goblin::elf::{Elf, ProgramHeader, Sym, program_header::PT_LOAD, reloc::R_X86_64_JUMP_SLOT, Reloc};
use memmap2::Mmap;
use std::fs::File;
use std::ops::Deref;
use goblin::elf::dynamic::DT_NEEDED;
use ouroboros::self_referencing;
use crate::elfdef;
use crate::elfdef::{get_shared_object_path, HashConverter, SymbolTableEntry};

fn open_mem_map(path: &str) -> Result<Mmap> {
    let file = File::open(path)?;
    unsafe { Ok(Mmap::map(&file)?) }
}

#[self_referencing]
pub struct ExecuteLinkFile {
    data: Vec<u8>,

    #[borrows(data)]
    #[covariant]
    elf: Elf<'this>
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
    
}
