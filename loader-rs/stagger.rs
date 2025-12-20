use anyhow::{Context, Result, bail};
use console::{Key, Term};
use goblin::elf::dynamic::{
    DT_FINI, DT_FINI_ARRAY, DT_FINI_ARRAYSZ, DT_FLAGS, DT_FLAGS_1, DT_INIT, DT_INIT_ARRAY,
    DT_INIT_ARRAYSZ, DT_NEEDED,
};
use goblin::elf::program_header::{PF_R, PF_W, PF_X};
use goblin::elf::reloc::R_X86_64_RELATIVE;
use goblin::elf::section_header::{
    SHF_ALLOC, SHN_UNDEF, SHT_DYNAMIC, SHT_DYNSYM, SHT_FINI_ARRAY, SHT_INIT_ARRAY, SHT_NOBITS,
    SHT_PROGBITS, SHT_RELA,
};
use goblin::elf::sym::{STB_GLOBAL, STT_FUNC, STT_GNU_IFUNC, STT_NOTYPE, STT_OBJECT, STT_TLS};
use goblin::elf32::section_header::SHF_EXECINSTR;
use std::collections::HashMap;
use std::ffi::CString;
use libc::{PROT_EXEC, PROT_READ, PROT_WRITE};
use hollowell::elfdef::{Dyn, Rela, SHT_RELR, SymbolTableEntry, get_shared_object_path};
use nix::sys::memfd::{MFdFlags, memfd_create};
use nix::sys::ptrace;
use nix::sys::ptrace::Options;
use nix::sys::signal::Signal;
use nix::sys::signal::Signal::{SIGILL, SIGSEGV, SIGTRAP};
use nix::sys::wait::WaitStatus;
use nix::unistd::{ForkResult, Pid, Whence, lseek, write};
use rand::Rng;

use crate::fexecve_with_current_argv_env;
use crate::hollowgen::HollowGenerator;
use crate::relocation::Relocator;
use crate::tui::UI;
use hollowell::asm::{Assembly, assemble};
use hollowell::auxiliary::{BlockLocator, BlockLocatorInMemory, ChunkMeta, ChunkMetaInMemory, ProgramHeaderExt, QuickConver, RandomLength};
use hollowell::chunk::{Chunk, get_ehdr};
use hollowell::chunk::{get_chunks_by_filter, get_phdr, hash_sha256};
use hollowell::elf::ExecuteLinkFile;
use hollowell::elfdef;
use hollowell::processes::Process;

use crate::debug::HollowStageDebug;

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

pub struct HollowStage {
    pub data: Vec<u8>,
    pub deps: Vec<(String, HashMap<String, SymbolTableEntry>)>,
    pub rela: Vec<Rela>,
    pub relr: Vec<Relr>,
    pub syms: Vec<SymbolTableEntry>,
    pub chunks: Vec<(Chunk, Option<Bytes>)>,

    pub procs: HashMap<i32, Process>,
    pub major: Pid,
    pub instruction_blocks: Vec<ChunkMeta>,
    pub window: Vec<ChunkMetaInMemory>,
    pub tui: Option<UI>,

    pub instruction_area: (u64, u64),
    pub debug: HollowStageDebug,
    pub do_relocate: bool,
    pub do_log: bool,
}

impl HollowStage {
    #[allow(unused)]
    pub fn allocate_randomly(
        instruction_area: (u64, u64),
        blocks: &[(u64, u64)],
        request_size: u64,
    ) -> Option<u64> {
        let (area_start, area_end) = instruction_area;
        if request_size == 0 || area_end <= area_start {
            return None;
        }

        let available_space = area_end - area_start;
        if request_size > available_space {
            return None;
        }

        let max_start_addr = area_end - request_size;

        let mut rng = rand::rng();
        const MAX_RETRIES: usize = 32;

        for _ in 0..MAX_RETRIES {
            let mut candidate = rng.random_range(area_start..=max_start_addr);
            candidate &= !0xfu64;

            if !Self::is_overlapping(candidate, request_size, blocks) {
                return Some(candidate);
            }
        }

        None
    }

    #[allow(unused)]
    pub fn allocate_after_highest(
        instruction_area: (u64, u64),
        blocks: &[(u64, u64)],
        request_size: u64,
    ) -> Option<u64> {
        let (area_start, area_end) = instruction_area;

        if request_size == 0 || area_end <= area_start {
            return None;
        }

        let highest_occupied_end = blocks
            .iter()
            .map(|(start, size)| start.saturating_add(*size))
            .max()
            .unwrap_or(area_start);

        let candidate = (highest_occupied_end + 0xf) & !0xfu64;

        if candidate + request_size <= area_end {
            if !Self::is_overlapping(candidate, request_size, blocks) {
                return Some(candidate);
            }
        }
        None
    }

    #[inline]
    fn is_overlapping(candidate: u64, size: u64, blocks: &[(u64, u64)]) -> bool {
        let candidate_end = candidate + size;

        for &(b_addr, b_size) in blocks {
            let b_end = b_addr + b_size;

            if candidate < b_end && candidate_end > b_addr {
                return true;
            }
        }
        false
    }

    pub fn build() -> Result<Self>
    {
        let phdr = get_phdr()?;

        let mut builder = HollowGenerator::new_x86_64();
        let image_size = phdr.as_slice().get_image_size();

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

        builder.add_segment(vec![0xcc; 16], image_size, PF_R | PF_W | PF_X, 0);

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

        anyhow::Ok(HollowStage {
            data: builder.build(),
            deps: dk,
            rela,
            relr,
            syms,
            chunks,
            procs: HashMap::new(),
            major: Pid::from_raw(0),
            instruction_blocks: Vec::new(),
            window: Vec::new(),
            tui: None,
            instruction_area: (u64::MAX, 0),
            do_relocate: true,
            do_log: false,

            debug: HollowStageDebug {
                focused_origin: vec![],
                focused_relocated: vec![],
                ips: (0, 0),
                debug: false,
                tui: false,
                ins_number: 0,
                clear: false,
                focused_near: vec![],
                major: None
            },
        })
    }

    pub fn startup(&mut self) -> Result<Pid>
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

        self.major = child;
        self.debug.major = Some(Process::new(child)?);
        Ok(child)
    }

    pub fn prepare(&mut self) -> Result<()>
    {
        let ehdr = get_ehdr()?;

        let mut proc = Process::new(self.major)?;
        log::info!("{SUCC} Opened process {}", self.major);
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

        for i in self.chunks.iter() {
            if let (s, Some(b)) = i
                && s.vaddr >= (sbase - base)
            {
                if s.flags & SHF_EXECINSTR as u64 == 0 {
                    proc.map_region(base as usize, &s, b)?;
                } else {
                    let sa = base as usize + s.vaddr as usize;

                    if sa as u64 <= self.instruction_area.0 {
                        self.instruction_area.0 = sa as u64;
                    }

                    if sa + s.size as usize > self.instruction_area.1 as usize {
                        self.instruction_area.1 = sa as u64 + s.size;
                    }

                    proc.write(sa, &vec![0xccu8; s.size as usize])?;
                    self.instruction_blocks.push(ChunkMeta {
                        address: sa as u64,
                        fault_counter: 0,
                        in_window: false,
                        data: b.to_vec(),
                    });
                }
            }
        }

        self.instruction_blocks
            .sort_by(|a, b| a.address.cmp(&b.address));

        if let Err(_) = proc.disassemble_rip_log() {
            log::error!("{FAIL} Failed to disassemble rip.");
        }

        proc.flush_map()?;
        proc.do_rela_reloc(base as usize, &self.rela, &self.deps, &self.syms)?;
        proc.do_relr_reloc(base as usize, &self.relr)?;

        let phdr = get_phdr()?;
        let image_size = phdr.as_slice().get_image_size();

        let dp = sbase + image_size as u64;
        self.instruction_area.0 = dp;
        self.instruction_area.1 = dp + image_size as u64;
        proc.write(dp as usize, &vec![0xccu8; image_size])?;

        proc.redirect(base + ehdr.e_entry)?;
        self.procs.insert(self.major.as_raw(), proc);

        Ok(())
    }

    fn cross_chunk(&mut self, rip: usize, tid: i32) -> Result<()>
    {
        if let Some(k) = self.instruction_blocks.find_block(rip as u64) {
            log::debug!("{INFO} {} trapped in origin chunk {}", tid, self.procs[&tid].map.format_address(k.address as usize));
            if "memfd:hollow+0x48247" == self.procs[&tid].map.format_address(k.address as usize) && k.in_window
            {
                // self.debug.debug = true;
            }
            // If rip trapped in a known chunk
            // We consider whether it has not been loaded
            // or has been loaded but repositioned
            if k.in_window {
                // Chunk has already been loaded, but relocated
                if let Some(v) = self.window.find_block_out_memory(k.address) {
                    log::debug!("{INFO} Chunk {} has already been loaded at {}",
                        self.procs[&tid].map.format_address(k.address as usize),
                        self.procs[&tid].map.format_address(v.relocated as usize));
                    let mut origin = Assembly::new(&k.data);
                    let mut relocated = Assembly::new(&v.data);

                    let nip = origin.byte_offset_to_ip(rip - k.address as usize)?;
                    let r_offset = relocated.ip_to_byte_offset(nip)?;

                    self.procs[&tid].redirect(v.relocated + r_offset as u64)?;
                    self.debug.debug_flush_block(&k, &v, (rip, v.relocated as usize + r_offset), nip)?;

                    // Insert stub code
                    let stub = assemble(rip as u64, |asm| {
                        asm.jmp(v.relocated + r_offset as u64)?;
                        Ok(())
                    })?;
                    if rip + stub.len() < k.address as usize + k.data.len()
                    {
                        self.procs[&tid].write(rip, &stub)?;
                        log::debug!("{INFO} {:#0x} bytes of stub code wrote to {}", stub.len(), self.procs[&tid].map.format_address(rip));
                    }
                } else {
                    bail!("Trapped in in-window thunks, but can't find in window. ");
                }
            }
            else {
                // Chunk has not been loaded, swap it to memory
                let mut c = ChunkMetaInMemory {
                    data: vec![],
                    relocated: k.address,
                    origin_address: k.address,
                };

                k.fault_counter += 1;
                k.in_window = true;

                let mut ra = Self::allocate_randomly(
                    self.instruction_area,
                    &self.window.iter().map(|x| (x.relocated, x.data.len() as u64)).collect::<Vec<_>>(),
                    k.data.len() as u64 * 2,
                );

                if ra.is_none()
                {
                    let mut sz = k.data.len() as u64 * 2;
                    sz &= !0xfffu64;
                    sz /= 0x1000u64;
                    let p = self.procs.get_mut(&tid).unwrap()
                        .alloc_pages(sz + 1, (PROT_READ | PROT_WRITE | PROT_EXEC) as u64)?;

                    ra = Some(p);
                }

                if self.do_relocate && let Some(a) = ra {
                    let r = Assembly::instruction_relocate(
                        k.address as usize,
                        &k.data,
                        a,
                    )?.code_buffer;

                    c.relocated = a;
                    c.data = r;

                    let mut stub = assemble(c.relocated + c.data.len() as u64, |asm| {
                        asm.jmp(k.address + k.data.len() as u64)?;
                        Ok(())
                    })?;
                    c.data.append(&mut stub);

                    log::info!("{SUCC} {} Bytes of instruction relocated to {} from {}",
                        k.data.len(),
                        self.procs[&tid].map.format_address(a as usize),
                        self.procs[&tid].map.format_address(k.address as usize));
                } else {
                    c.relocated = k.address;
                    c.data = k.data.to_vec();
                }

                self.procs[&tid].write(c.relocated as usize, &c.data)?;

                let mut origin = Assembly::new(&k.data);
                let mut relocated = Assembly::new(&c.data);

                let nip = origin.byte_offset_to_ip(rip - k.address as usize)?;
                let r_offset = relocated.ip_to_byte_offset(nip)?;
                let relocated_ip = c.relocated as usize + r_offset;

                self.procs[&tid].redirect(relocated_ip as u64)?;
                self.debug.debug_flush_block(&k, &c, (rip, relocated_ip), nip)?;

                self.window.push(c);
            }
        }
        else {
            let ip = self.procs[&tid].getip()?;

            log::error!(
                "{FAIL} Critical error with rip: {}",
                self.procs[&tid].map.format_address(ip)
            );

            self.procs.get_mut(&tid).unwrap().disassemble_rip_log()?;

            bail!("What?????");
        }

        Ok(())
    }

    fn handler_trap(&mut self, tid: Pid) -> Result<Pid> {
        let ip = self.procs[&tid.as_raw()].redirect_relative(-1)?;

        self.cross_chunk(ip, tid.as_raw() as i32)?;

        if let Some(tui) = self.tui.as_mut() {
            tui.flush(&mut self.debug)?;
        }

        Ok(tid)
    }

    fn handler_other(&mut self, tid: Pid, sig: Signal) -> Result<Pid> {
        if sig == SIGSEGV || sig == SIGILL {
            let ip = self.procs[&tid.as_raw()].getip()?;

            log::error!(
                "{FAIL} Critical error with rip: {}",
                self.procs[&tid.as_raw()].map.format_address(ip)
            );

            self.procs.get_mut(&tid.as_raw()).unwrap().disassemble_rip_log()?;

            bail!("Critical error");
        }

        Ok(tid)
    }

    fn handler_exited(&mut self, tid: Pid) -> Result<Pid> {
        self.procs.remove(&tid.as_raw());
        if tid.as_raw() == self.major.as_raw() {
            bail!("{FAIL} Exited. ");
        }

        Ok(tid)
    }

    fn handler_event(&mut self, tid: Pid) -> Result<Pid> {
        let new_tid = ptrace::getevent(tid)? as libc::pid_t;
        log::info!("{INFO} New thread is {}", new_tid);
        Ok(tid)
    }

    pub fn staging(&mut self) -> Result<()> {
        let term = Term::stdout();
        self.procs[&self.major.as_raw()].cont()?;

        if !self.debug.debug || self.tui.is_some() {
            log::set_max_level(log::LevelFilter::Off);
        }

        if self.do_log {
            log::set_max_level(log::LevelFilter::Debug);
        }

        loop {
            let status = Process::wait().context("Failed to wait on child")?;

            if let Some(tid) = status.pid()
                && !self.procs.contains_key(&tid.as_raw())
            {
                self.procs.insert(tid.as_raw(), Process::new(tid)?);
            }

            let tid = match status {
                WaitStatus::Stopped(tid, SIGTRAP) => self.handler_trap(tid),
                WaitStatus::Stopped(tid, sig) => self.handler_other(tid, sig),
                WaitStatus::Exited(tid, _) => self.handler_exited(tid),
                WaitStatus::PtraceEvent(tid, SIGTRAP, _) => self.handler_event(tid),
                WaitStatus::PtraceSyscall(tid) | WaitStatus::Continued(tid) => Ok(tid),
                _ => Ok(self.major),
            }?.as_raw();

            if !self.procs.contains_key(&tid) {
                continue;
            }

            if !self.debug.debug {
                self.procs[&tid].cont()?;
                continue;
            }

            while self.debug.debug {
                match term.read_key() {
                    Ok(Key::Char(c)) => match c {
                        'n' => {
                            self.procs[&tid].stepover()?;
                        }
                        's' => {
                            self.procs[&tid].step()?;
                        }
                        'c' => {
                            self.procs[&tid].cont()?;
                            break;
                        }
                        'q' => {
                            self.procs[&tid].kill()?;
                            return Ok(());
                        }
                        _ => {}
                    },
                    _ => {}
                }

                let ip = self.procs[&tid].getip()?;

                if let Some(tui) = self.tui.as_mut() {
                    if let Some(k) = self.window.find_block_in_memory(ip as u64)
                        && let Some(c) = self.instruction_blocks.find_block(k.origin_address) {
                        let mut origin = Assembly::new(&c.data);
                        let mut relocated = Assembly::new(&k.data);

                        let nip = relocated.byte_offset_to_ip(ip - k.relocated as usize)?;
                        let r_offset = origin.ip_to_byte_offset(nip)?;

                        self.debug.debug_flush_ip((c.address as usize + r_offset, ip), nip)?;
                    }
                    tui.flush(&mut self.debug)?;
                } else {
                    self.procs
                        .get_mut(&tid)
                        .context("")?
                        .disassemble_rip_log()?;
                }
            }
        }
    }
}

pub trait SymbolResolvable {
    fn resolve_symbol(&self, process: &mut Process, name: &str) -> Option<(String, usize)>;
}

impl<T> SymbolResolvable for T
where
    T: AsRef<[(String, HashMap<String, SymbolTableEntry>)]>,
{
    fn resolve_symbol(&self, process: &mut Process, name: &str) -> Option<(String, usize)> {
        let mut r: Option<(String, usize)> = None;

        for (dep, hash) in self.as_ref() {
            if let Some(v) = hash.get(name) {
                let base = process.module_base_address(dep)?;
                r = match v.sym_type {
                    STT_NOTYPE | STT_OBJECT | STT_FUNC => {
                        Some((dep.clone(), base as usize + v.sym_value as usize))
                    }
                    STT_TLS => Some((dep.clone(), v.sym_value as usize)),
                    STT_GNU_IFUNC => {
                        let resolver = base as usize + v.sym_value as usize;

                        let rp = process
                            .execute_once_inplace(
                                |addr| {
                                    assemble(addr, |asm| {
                                        asm.call(resolver as u64)?;
                                        asm.int3()?;
                                        Ok(())
                                    })
                                    .ok()
                                },
                                |_| {},
                            )
                            .ok()?;

                        Some((dep.clone(), rp.rax as usize))
                    }
                    _ => None,
                };

                if v.sym_bind == STB_GLOBAL {
                    break;
                }
            }
        }

        r
    }
}
