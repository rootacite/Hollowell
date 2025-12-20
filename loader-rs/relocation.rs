
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