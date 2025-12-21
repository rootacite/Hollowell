
use std::collections::HashMap;
use anyhow::{bail, Context};
use console::{Key, Term};
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::signal::Signal::{SIGILL, SIGSEGV, SIGTRAP};
use nix::sys::wait::WaitStatus;
use nix::unistd::Pid;
use rand::Rng;
use hollowell::asm::{assemble, Assembly};
use hollowell::auxiliary::{BlockLocator, BlockLocatorInMemory, ChunkMeta, ChunkMetaInMemory};
use hollowell::processes::Process;
use crate::stagger::debug::HollowDebug;
use crate::tui::UI;

#[allow(unused)]
const SUCC: &str = "\x1b[32m[+]\x1b[0m";
#[allow(unused)]
const FAIL: &str = "\x1b[31m[-]\x1b[0m";
#[allow(unused)]
const ALER: &str = "\x1b[31m[!]\x1b[0m";
#[allow(unused)]
const INFO: &str = "\x1b[34m[*]\x1b[0m";

pub struct HollowKinesis {
    pub procs: HashMap<i32, Process>,
    pub major: i32,
    pub instruction_blocks: Vec<ChunkMeta>,
    pub window: Vec<ChunkMetaInMemory>,
    pub allow_relocate: bool,
    pub instruction_area: (u64, u64),
}

impl HollowKinesis {
    #[allow(unused)]
    pub fn allocate_randomly(
        &self,
        request_size: u64,
    ) -> Option<u64> {
        let (area_start, area_end) = self.instruction_area;
        let blocks = self.window.iter().map(|x| (x.relocated, x.data.len() as u64)).collect::<Vec<_>>();

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

            if !Self::is_overlapping(candidate, request_size, &blocks) {
                return Some(candidate);
            }
        }

        let orc = area_end;



        None
    }

    #[inline]
    fn is_overlapping(candidate: u64, size: u64, blocks: &[(u64, u64)]) -> bool
    {
        let candidate_end = candidate + size;

        for &(b_addr, b_size) in blocks {
            let b_end = b_addr + b_size;

            if candidate < b_end && candidate_end > b_addr {
                return true;
            }
        }
        false
    }

    fn cross_chunk(&mut self, rip: usize, tid: i32, debug: &mut HollowDebug) -> anyhow::Result<()>
    {
        let idx = match self.instruction_blocks.find_block_index(rip as u64) {
            Some(i) => i,
            None => {
                let ip = self.procs[&tid].getip()?;
                log::error!("{FAIL} Critical error with rip: {}", self.procs[&tid].map.format_address(ip));

                self.procs.get_mut(&tid).unwrap().disassemble_rip_log()?;
                bail!("What?????");
            }
        };

        log::debug!("{INFO} {} trapped in origin chunk {}", tid, self.procs[&tid].map.format_address(self.instruction_blocks[idx].address as usize));
        // If rip trapped in a known chunk
        // We consider whether it has not been loaded
        // or has been loaded but repositioned
        if self.instruction_blocks[idx].in_window {
            // Chunk has already been loaded, but relocated
            if let Some(v) = self.window.find_block_out_memory(self.instruction_blocks[idx].address) {
                log::debug!("{INFO} Chunk {} has already been loaded at {}",
                        self.procs[&tid].map.format_address(self.instruction_blocks[idx].address as usize),
                        self.procs[&tid].map.format_address(v.relocated as usize));
                let mut origin = Assembly::new(&self.instruction_blocks[idx].data);
                let mut relocated = Assembly::new(&v.data);

                let nip = origin.byte_offset_to_ip(rip - self.instruction_blocks[idx].address as usize)?;
                let r_offset = relocated.ip_to_byte_offset(nip)?;

                self.procs[&tid].redirect(v.relocated + r_offset as u64)?;
                debug.debug_flush_block(&self.instruction_blocks[idx], &v, (rip, v.relocated as usize + r_offset), nip)?;

                // Insert stub code
                let stub = assemble(rip as u64, |asm| {
                    asm.jmp(v.relocated + r_offset as u64)?;
                    Ok(())
                })?;
                if rip + stub.len() < self.instruction_blocks[idx].address as usize + self.instruction_blocks[idx].data.len()
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
                relocated: self.instruction_blocks[idx].address,
                origin_address: self.instruction_blocks[idx].address,
            };

            self.instruction_blocks[idx].fault_counter += 1;
            self.instruction_blocks[idx].in_window = true;

            let ra = self.allocate_randomly(
                self.instruction_blocks[idx].data.len() as u64 * 2,
            );

            if self.allow_relocate && let Some(a) = ra {
                let r = Assembly::instruction_relocate(
                    self.instruction_blocks[idx].address as usize,
                    &self.instruction_blocks[idx].data,
                    a,
                )?.code_buffer;

                c.relocated = a;
                c.data = r;

                let mut stub = assemble(c.relocated + c.data.len() as u64, |asm| {
                    asm.jmp(self.instruction_blocks[idx].address + self.instruction_blocks[idx].data.len() as u64)?;
                    Ok(())
                })?;
                c.data.append(&mut stub);

                log::info!("{SUCC} {} Bytes of instruction relocated to {} from {}",
                        self.instruction_blocks[idx].data.len(),
                        self.procs[&tid].map.format_address(a as usize),
                        self.procs[&tid].map.format_address(self.instruction_blocks[idx].address as usize));
            } else {
                c.relocated = self.instruction_blocks[idx].address;
                c.data = self.instruction_blocks[idx].data.to_vec();
            }

            self.procs[&tid].write(c.relocated as usize, &c.data)?;

            let mut origin = Assembly::new(&self.instruction_blocks[idx].data);
            let mut relocated = Assembly::new(&c.data);

            let nip = origin.byte_offset_to_ip(rip - self.instruction_blocks[idx].address as usize)?;
            let r_offset = relocated.ip_to_byte_offset(nip)?;
            let relocated_ip = c.relocated as usize + r_offset;

            self.procs[&tid].redirect(relocated_ip as u64)?;
            debug.debug_flush_block(&self.instruction_blocks[idx], &c, (rip, relocated_ip), nip)?;

            self.window.push(c);
        }

        Ok(())
    }

    fn handler_trap(&mut self, tid: Pid, debug: &mut HollowDebug) -> anyhow::Result<Pid> {
        let ip = self.procs[&tid.as_raw()].redirect_relative(-1)?;

        self.cross_chunk(ip, tid.as_raw() as i32, debug)?;

        Ok(tid)
    }

    fn handler_other(&mut self, tid: Pid, sig: Signal) -> anyhow::Result<Pid> {
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

    fn handler_exited(&mut self, tid: Pid) -> anyhow::Result<Pid> {
        self.procs.remove(&tid.as_raw());
        if tid.as_raw() == self.major {
            bail!("{FAIL} Exited. ");
        }

        Ok(tid)
    }

    fn handler_event(&mut self, tid: Pid) -> anyhow::Result<Pid> {
        let new_tid = ptrace::getevent(tid)? as libc::pid_t;
        log::info!("{INFO} New thread is {}", new_tid);
        Ok(tid)
    }


    pub fn staging(&mut self, debug: &mut HollowDebug, tui: &mut Option<UI>) -> anyhow::Result<()> {
        let term = Term::stdout();
        self.procs[&self.major].cont()?;

        loop {
            let status = Process::wait().context("Failed to wait on child")?;

            if let Some(tid) = status.pid()
                && !self.procs.contains_key(&tid.as_raw())
            {
                self.procs.insert(tid.as_raw(), Process::new(tid)?);
            }

            let tid = match status {
                WaitStatus::Stopped(tid, SIGTRAP) => self.handler_trap(tid, debug),
                WaitStatus::Stopped(tid, sig) => self.handler_other(tid, sig),
                WaitStatus::Exited(tid, _) => self.handler_exited(tid),
                WaitStatus::PtraceEvent(tid, SIGTRAP, _) => self.handler_event(tid),
                WaitStatus::PtraceSyscall(tid) | WaitStatus::Continued(tid) => Ok(tid),
                _ => Ok(Pid::from_raw(self.major)),
            }?.as_raw();

            if let Some(tui) = tui.as_mut() {
                tui.flush(debug)?;
            }

            if !self.procs.contains_key(&tid) {
                continue;
            }

            if !debug.debug {
                self.procs[&tid].cont()?;
                continue;
            }

            while debug.debug {
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

                if let Some(tui) = tui.as_mut() {
                    if let Some(k) = self.window.find_block_in_memory(ip as u64)
                        && let Some(c) = self.instruction_blocks.find_block_index(k.origin_address) {
                        let mut origin = Assembly::new(&self.instruction_blocks[c].data);
                        let mut relocated = Assembly::new(&k.data);

                        let nip = relocated.byte_offset_to_ip(ip - k.relocated as usize)?;
                        let r_offset = origin.ip_to_byte_offset(nip)?;

                        debug.debug_flush_ip((self.instruction_blocks[c].address as usize + r_offset, ip), nip)?;
                    }
                    tui.flush(debug)?;
                } else {
                    self.procs
                        .get_mut(&tid)
                        .context("")?
                        .disassemble_rip_log()?;
                }
            }
        }
    }

    pub fn debug(&mut self) -> anyhow::Result<HollowDebug>
    {
        Ok(HollowDebug {
            focused_origin: vec![],
            focused_relocated: vec![],
            ips: (0, 0),
            debug: false,
            tui: false,
            ins_number: 0,
            clear: false,
            focused_near: vec![],
            major: Process::new(Pid::from_raw(self.major)).ok(),
            do_log: false,
        })
    }
}