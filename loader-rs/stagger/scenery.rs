
use std::collections::HashMap;
use std::ffi::CString;
use anyhow::Context;
use goblin::elf32::section_header::SHF_EXECINSTR;
use goblin::elf::dynamic::{DT_FINI, DT_FINI_ARRAY, DT_FINI_ARRAYSZ, DT_FLAGS, DT_FLAGS_1, DT_INIT, DT_INIT_ARRAY, DT_INIT_ARRAYSZ, DT_NEEDED};
use goblin::elf::program_header::{PF_R, PF_W, PF_X};
use goblin::elf::reloc::R_X86_64_RELATIVE;
use goblin::elf::section_header::{
    SHF_ALLOC, SHN_UNDEF, SHT_DYNAMIC, SHT_DYNSYM, SHT_FINI_ARRAY, SHT_INIT_ARRAY, SHT_NOBITS,
    SHT_PROGBITS, SHT_RELA,
};
use nix::sys::memfd::{memfd_create, MFdFlags};
use nix::sys::ptrace;
use nix::sys::ptrace::Options;
use nix::unistd::{lseek, write, ForkResult, Pid, Whence};
use hollowell::auxiliary::{ChunkMeta, ProgramHeaderExt, QuickConver, RandomLength};
use hollowell::chunk::{get_chunks_by_filter, get_ehdr, get_phdr, hash_sha256, Chunk};
use hollowell::elf::ExecuteLinkFile;
use hollowell::elfdef;
use hollowell::elfdef::{get_shared_object_path, Dyn, Rela, SymbolTableEntry, SHT_RELR};
use hollowell::processes::Process;
use crate::fexecve_with_current_argv_env;
use crate::hollowgen::HollowGenerator;
use crate::relocation::Relocator;
use crate::stagger::{Bytes, Relr, NEAR_LIMIT};
use crate::stagger::kinesis::HollowKinesis;

#[allow(unused)]
const SUCC: &str = "\x1b[32m[+]\x1b[0m";
#[allow(unused)]
const FAIL: &str = "\x1b[31m[-]\x1b[0m";
#[allow(unused)]
const ALER: &str = "\x1b[31m[!]\x1b[0m";
#[allow(unused)]
const INFO: &str = "\x1b[34m[*]\x1b[0m";

pub struct HollowScenery {
    pub data: Vec<u8>,
    pub deps: Vec<(String, HashMap<String, SymbolTableEntry>)>,
    pub rela: Vec<Rela>,
    pub relr: Vec<Relr>,
    pub syms: Vec<SymbolTableEntry>,
    pub chunks: Vec<(Chunk, Option<Bytes>)>,
}

impl HollowScenery {
    pub fn build() -> anyhow::Result<Self>
    {
        let mut builder = HollowGenerator::new_x86_64();

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

        let mut chunks_map: HashMap<u64, (Chunk, Option<Bytes>)> = HashMap::new();

        for (chunk, bytes) in chunks {
            let vaddr = chunk.vaddr;
            let current_len = bytes.as_ref().map(|b| b.len()).unwrap_or(0);

            if let Some(existing) = chunks_map.get(&vaddr) {
                let existing_len = existing.1.as_ref().map(|b| b.len()).unwrap_or(0);

                if current_len > existing_len {
                    chunks_map.insert(vaddr, (chunk, bytes));
                }
            } else {
                chunks_map.insert(vaddr, (chunk, bytes));
            }
        }

        chunks = chunks_map.into_values().collect();

        builder.add_segment(vec![0xcc; 16], NEAR_LIMIT as usize, PF_R | PF_W | PF_X, 0);

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

        anyhow::Ok(HollowScenery {
            data: builder.build(),
            deps: dk,
            rela,
            relr,
            syms,
            chunks,
        })
    }

    pub fn startup(&mut self) -> anyhow::Result<HollowKinesis>
    {
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

        let major = child;
        let mut instruction_area = (u64::MAX, 0u64);
        let mut instruction_blocks: Vec<ChunkMeta> = Vec::new();
        let mut procs: HashMap<i32, Process> = HashMap::new();

        let ehdr = get_ehdr()?;

        let mut proc = Process::new(major)?;
        log::info!("{SUCC} Opened process {}", major);
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

        for i in self.chunks.iter()
        {
            if let (s, Some(b)) = i
                && s.vaddr >= (sbase - base)
            {

                if s.flags & SHF_EXECINSTR as u64 == 0 {
                    proc.map_region(base as usize, &s, b)?;
                } else {
                    let sa = base as usize + s.vaddr as usize;

                    if sa as u64 <= instruction_area.0 {
                        instruction_area.0 = sa as u64;
                    }

                    if sa + s.size as usize > instruction_area.1 as usize {
                        instruction_area.1 = sa as u64 + s.size;
                    }

                    proc.write(sa, &vec![0xccu8; s.size as usize])?;
                    instruction_blocks.push(ChunkMeta {
                        address: sa as u64,
                        fault_counter: 0,
                        in_window: false,
                        data: b.to_vec(),
                    });
                }
            }
        }

        instruction_blocks.sort_by(|a, b| a.address.cmp(&b.address));

        if let Err(_) = proc.disassemble_rip_log() {
            log::error!("{FAIL} Failed to disassemble rip.");
        }

        proc.flush_map()?;
        proc.do_rela_reloc(base as usize, &self.rela, &self.deps, &self.syms)?;
        proc.do_relr_reloc(base as usize, &self.relr)?;

        let phdr = get_phdr()?;
        let image_size = phdr.as_slice().get_image_size();

        instruction_area.0 = sbase + image_size as u64;
        instruction_area.1 = sbase + NEAR_LIMIT - 1;

        proc.redirect(base + ehdr.e_entry)?;
        procs.insert(major.as_raw(), proc);

        Ok(HollowKinesis {
            procs,
            major: major.as_raw(),
            instruction_blocks,
            window: Vec::new(),
            allow_relocate: true,
            instruction_area,
        })
    }
}