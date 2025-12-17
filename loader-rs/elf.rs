
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

    #[allow(unused)]
    pub fn get_rela_sym(&self, name: &str) -> Result<Reloc>
    {
        let rela_plt = self.borrow_elf().pltrelocs.iter();

        let sym = rela_plt
            .filter(|rela| {
                matches!(rela.r_type, R_X86_64_JUMP_SLOT) // R_X86_64_JUMP_SLOT
            })
            .filter_map(|rela| {
                let sym_index = rela.r_sym;
                let Ok(sym) = self.get_dyn_sym(sym_index) else {
                    return None;
                };
                let Ok(sym_name) = self.get_dyn_str(sym.st_name) else {
                    return None;
                };

                if sym_name == name { Some(rela) } else { None }
            })
            .collect::<Vec<Reloc>>();

        let first = sym
            .first()
            .context(format!("No symbol found with name {}", name))?;

        Ok(first.clone())
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

    pub fn get_dyn_sym(&self, location: usize) -> Result<Sym>
    {
        let dyn_sym = self.borrow_elf()
            .dynsyms
            .get(location)
            .context(format!("No symbol found at location {}", location))?;

        Ok(dyn_sym.clone())
    }

    #[allow(unused)]
    pub fn prase_dyn_sym(&self, name: &str) -> Result<Sym>
    {
        let dyn_sym = self.borrow_elf()
            .dynsyms.iter()
            .find(|sym| self.get_dyn_str(sym.st_name).ok().as_deref() == Some(name))
            .context(format!("No symbol found with name {}", name))?;

        Ok(dyn_sym.clone())
    }

    pub fn get_dyn_str(&self, location: usize) -> Result<String>
    {
        let str = self.borrow_elf()
            .dynstrtab
            .get_at(location)
            .context(format!("Could not get dynstr at location {}", location))?;

        Ok(str.to_owned())
    }
    
    #[allow(unused)]
    pub fn get_e_type(&self) -> u16
    {
        self.borrow_elf().header.e_type
    }
}
