
use std::collections::HashMap;
use std::ffi::CString;
use anyhow::Context;
use goblin::elf::dynamic::{DT_FINI, DT_FINI_ARRAY, DT_FINI_ARRAYSZ, DT_FLAGS, DT_FLAGS_1, DT_INIT, DT_INIT_ARRAY, DT_INIT_ARRAYSZ, DT_NEEDED};
use goblin::elf::program_header::{PF_R, PF_W, PF_X};
use goblin::elf::reloc::R_X86_64_RELATIVE;
use goblin::elf::section_header::{SHF_ALLOC, SHN_UNDEF, SHT_DYNAMIC, SHT_DYNSYM, SHT_NOBITS, SHT_PROGBITS, SHT_RELA, SHT_INIT_ARRAY, SHT_FINI_ARRAY};
use goblin::elf::sym::{STT_NOTYPE, STT_OBJECT, STT_FUNC, STT_TLS, STT_GNU_IFUNC, STB_GLOBAL};
use hollowell::elfdef::{get_shared_object_path, Dyn, Rela, SymbolTableEntry, SHT_RELR};

use hollowell::chunk::Chunk;
use hollowell::asm::assemble;
use hollowell::auxiliary::{hash_sha256, ProgramHeaderExt, RandomLength};
use hollowell::elf::ExecuteLinkFile;
use hollowell::processes::Process;
use hollowell::elfdef;
use hollowell::chunk::{get_chunks_by_filter, get_phdr};

use crate::hollowgen::HollowGenerator;

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

pub struct HollowStage
{
    pub data: Vec<u8>,
    pub deps: Vec<(String, HashMap<String, SymbolTableEntry>)>,
    pub rela: Vec<Rela>,
    pub relr: Vec<Relr>,
    pub syms: Vec<SymbolTableEntry>,
    pub chunks: Vec<(Chunk, Option<Bytes>)>,
}

impl HollowStage
{
    pub fn build() -> anyhow::Result<Self>
    {
        let phdr = get_phdr()?;

        let mut builder = HollowGenerator::new_x86_64();
        let image_size = phdr.as_slice().get_image_size();

        let mut deps: Vec<String> = Vec::new();
        let mut rela: Vec<Rela> = Vec::new();
        let mut relr: Vec<Relr> = Vec::new();
        let mut syms: Vec<SymbolTableEntry> = Vec::new();
        let mut chunks: Vec<(Chunk, Option<Bytes>)> = Vec::new();

        if let Some((_, Some(interp))) = get_chunks_by_filter(|x| { hash_sha256(".interp".as_bytes()) == x.name_hash }).first()
        {
            let interp_str = String::from_utf8(interp.to_vec())?;
            builder.add_interp(&interp_str);
        }

        if let Some((_, Some(dynamic))) = get_chunks_by_filter(|x| { x.chunk_type == SHT_DYNAMIC }).first()
            && let Some((_, Some(dynstr))) = get_chunks_by_filter(|x| { hash_sha256(".dynstr".as_bytes()) == x.name_hash }).first()
        {
            if let Some((_, Some(dynsym))) = get_chunks_by_filter(|x| { x.chunk_type == SHT_DYNSYM }).first()
            {
                let slice_syms = plain::slice_from_bytes::<elfdef::Sym>(&dynsym)
                    .ok().context("failed to parse plain dynamic")?;

                syms = slice_syms.iter().map(|x| x.as_entry(&dynstr) ).collect::<Vec<SymbolTableEntry>>();
            }

            let dynamic = plain::slice_from_bytes::<Dyn>(&dynamic).ok().context("failed to parse plain dynamic")?;

            for d in dynamic.iter()
            {
                match d.d_tag {
                    DT_NEEDED => {
                        let len = dynstr.as_slice().strlen(d.d_val as usize);
                        let bytes = dynstr[d.d_val as usize..d.d_val as usize + len].to_vec();
                        let cstr = CString::new(bytes)?;
                        deps.push(cstr.to_str()?.to_string());
                        builder.add_dependencies(&cstr);
                    },
                    DT_INIT | DT_FINI | DT_INIT_ARRAY | DT_FINI_ARRAY |
                    DT_INIT_ARRAYSZ | DT_FINI_ARRAYSZ | DT_FLAGS | DT_FLAGS_1 => {
                        builder.add_dynamic(Dyn {
                            d_tag: d.d_tag,
                            d_val: d.d_val,
                        });
                    }
                    _ => {}
                }
            }
        }

        for (_, r) in get_chunks_by_filter(|x| { x.chunk_type == SHT_RELA })
        {
            if let Some(br) = r
            {
                let cr = plain::slice_from_bytes::<Rela>(&br).ok().context("failed to parse plain rela")?;
                for d in cr.iter()
                {
                    rela.push(d.to_owned());
                }
            }
        }

        for (_, r) in get_chunks_by_filter(|x| { x.chunk_type == SHT_RELR })
        {
            if let Some(br) = r
            {
                let cr = plain::slice_from_bytes::<Relr>(&br).ok().context("failed to parse plain rela")?;
                for d in cr.iter()
                {
                    relr.push(d.to_owned());
                }
            }
        }

        for (v, r) in get_chunks_by_filter(|x| {
            matches!(x.chunk_type, SHT_PROGBITS | SHT_NOBITS | SHT_INIT_ARRAY | SHT_FINI_ARRAY)
                && (x.flags & (SHF_ALLOC as u64) != 0)
        })
        {
            chunks.push((v, r));
        }

        builder.add_segment(vec![0xcc; 16], image_size, PF_R | PF_W | PF_X, 0);

        builder.set_entry(0x8, 0);
        builder.add_rela(0, 0, None, R_X86_64_RELATIVE, 0);

        let mut recursive_deps = Vec::<String>::new();

        deps = deps
            .iter()
            .filter_map(|x| get_shared_object_path(&x))
            .collect::<Vec<String>>();

        for dep in &deps
        {
            ExecuteLinkFile::get_dependencies_recursively(&dep, &mut recursive_deps)?;
        }

        recursive_deps = recursive_deps
            .iter()
            .filter(|x| !deps.contains(&x))
            .map(|x| x.to_string())
            .collect::<Vec<String>>();

        deps.append(&mut recursive_deps);

        let dk = deps.iter().filter_map(|x| {
            if let Some(e) = ExecuteLinkFile::prase(&x).ok()
                && let Some(s) = e.get_dynsym_table().ok() {
                let s = s.into_iter().filter(|x| { (*x).1.sym_ndx != SHN_UNDEF as u16 }).collect();

                return Some((x.to_owned(), s));
            }

            None
        }).collect::<Vec<_>>();

        anyhow::Ok(HollowStage {
            data: builder.build(),
            deps: dk,
            rela,
            relr,
            syms,
            chunks
        })
    }
}

pub trait SymbolResolvable
{
    fn resolve_symbol(&self, process: &mut Process, name: &str) -> Option<(String, usize)>;
}

impl<T> SymbolResolvable for T
where
    T: AsRef<[(String, HashMap<String, SymbolTableEntry>)]>
{
    fn resolve_symbol(&self, process: &mut Process, name: &str) -> Option<(String, usize)> {
        let mut r: Option<(String, usize)> = None;

        for (dep, hash) in self.as_ref()
        {
            if let Some(v) = hash.get(name)
            {
                let base = process.module_base_address(dep)?;
                r = match v.sym_type
                {
                    STT_NOTYPE | STT_OBJECT | STT_FUNC => {
                        Some((dep.clone(), base as usize + v.sym_value as usize))
                    }
                    STT_TLS => {
                        Some((dep.clone(), v.sym_value as usize))
                    }
                    STT_GNU_IFUNC => {
                        let resolver = base as usize + v.sym_value as usize;

                        let rp = process.execute_once_inplace(|addr| {
                            assemble(addr, |asm| {
                                asm.call(resolver as u64)?;
                                asm.int3()?;
                                Ok(())
                            }).ok()
                        }, |_| { } ).ok()?;

                        Some((dep.clone(), rp.rax as usize))
                    }
                    _ =>{
                        None
                    }
                };

                if v.sym_bind == STB_GLOBAL {
                    break;
                }
            }
        }

        r
    }
}
