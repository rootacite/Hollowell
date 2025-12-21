// processes.rs

use std::collections::HashMap;
use std::fs;

use anyhow::Result;
use anyhow::{Context, bail};
use nix::sys::uio::{RemoteIoVec, process_vm_readv, process_vm_writev};
use nix::unistd::Pid;

use crate::asm::{InstructionFormat, assemble};
use crate::map::MemoryMap;
use iced_x86::code_asm::{r8, r9, r10, rax, rdi, rdx, rsi};
use iced_x86::{Decoder, DecoderOptions, Instruction};
use nix::libc;
use nix::libc::user_regs_struct;
use nix::sys::ptrace;
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use std::io::{IoSlice, IoSliceMut};

use crate::chunk::Chunk;

#[allow(unused)]
const SUCC: &str = "\x1b[32m[+]\x1b[0m";
#[allow(unused)]
const FAIL: &str = "\x1b[31m[-]\x1b[0m";
#[allow(unused)]
const ALER: &str = "\x1b[33m[!]\x1b[0m";
#[allow(unused)]
const INFO: &str = "\x1b[34m[*]\x1b[0m";

type Bytes = Vec<u8>;

pub struct Process {
    pid: Pid,
    pub map: MemoryMap,
    pub history: HashMap<usize, usize>,
    modules_base: HashMap<String, usize>,
}

impl Process {
    pub fn new(pid: Pid) -> Result<Self>
    {
        let maps = fs::read_to_string(format!("/proc/{}/maps", pid))?;
        let map = MemoryMap::new(
            &maps
                .lines()
                .filter(|&line| !line.is_empty())
                .collect::<Vec<&str>>()
        );

        Ok(Self {
            pid,
            map,
            history: HashMap::new(),
            modules_base: HashMap::new(),
        })
    }

    pub fn getip(&self) -> Result<usize>
    {
        Ok(self.get_regs()?.rip as usize)
    }

    pub fn cont(&self) -> Result<()>
    {
        let rip = self.getip()?;
        ptrace::cont(self.pid, None)?;
        log::info!("{SUCC} Process {} continued from {}", self.pid, self.map.format_address(rip));
        Ok(())
    }

    pub fn step(&self) -> Result<WaitStatus>
    {
        ptrace::step(self.pid, None)?;
        Ok(Process::wait()?)
    }

    pub fn kill(&self) -> Result<()>
    {
        ptrace::kill(self.pid)?;
        Ok(())
    }

    pub fn stepover(&self) -> Result<WaitStatus>
    {
        let rip = self.getip()?;
        let inst = self.disassemble_one_at(rip)?;

        log::info!("{INFO} Prepare to cross {}:{:02} {}",
                        self.map.format_address(inst.ip() as usize),
                        inst.len(),
                        inst.fmt_line_default().unwrap_or_default()
                    );

        let ob = self.read(rip + inst.len(), 1)?;
        self.write(rip + inst.len(), &[0xccu8; 1])?;

        log::info!("{SUCC} Breakpoint at {}.", self.map.format_address(rip + inst.len()));

        self.cont()?;
        let w = Self::wait()?;
        self.write(rip + inst.len(), &ob)?;

        Ok(w)
    }

    pub fn wait() -> Result<WaitStatus>
    {
        let f = waitpid(None, Some(WaitPidFlag::WUNTRACED|WaitPidFlag::__WALL))?;

        match f {
            WaitStatus::Stopped(stopped_pid, signal) => {
                log::warn!("{ALER} PID {} stopped by signal: {:?}", stopped_pid, signal);
            }
            WaitStatus::Exited(exited_pid, status) => {
                log::warn!("{ALER} PID {} exited with status: {}", exited_pid, status);
            }
            WaitStatus::Signaled(signaled_pid, signal, core_dump) => {
                log::warn!(
                    "{ALER} PID {} killed by signal: {:?} (core dump: {})",
                    signaled_pid, signal, core_dump
                );
            }
            WaitStatus::Continued(continued_pid) => {
                log::warn!("{ALER} PID {} continued", continued_pid);
            }
            WaitStatus::StillAlive => {
                log::warn!("{ALER} Process still alive");
            }
            WaitStatus::PtraceEvent(stopped_pid, _, _) => {
                log::warn!("{ALER} PID {} stopped by PtraceEvent", stopped_pid);
            }
            _ => {}
        }

        Ok(f)
    }

    pub fn waitpid(pid: Pid) -> Result<WaitStatus>
    {
        let f = waitpid(pid, Some(WaitPidFlag::WUNTRACED))?;

        match f {
            WaitStatus::Stopped(stopped_pid, signal) => {
                log::warn!("{ALER} PID {} stopped by signal: {:?}", stopped_pid, signal);
            }
            WaitStatus::Exited(exited_pid, status) => {
                log::warn!("{ALER} PID {} exited with status: {}", exited_pid, status);
            }
            WaitStatus::Signaled(signaled_pid, signal, core_dump) => {
                log::warn!(
                    "{ALER} PID {} killed by signal: {:?} (core dump: {})",
                    signaled_pid, signal, core_dump
                );
            }
            WaitStatus::Continued(continued_pid) => {
                log::warn!("{ALER} PID {} continued", continued_pid);
            }
            WaitStatus::StillAlive => {
                log::warn!("{ALER} PID {} still alive", pid);
            }
            _ => {}
        }

        Ok(f)
    }

    pub fn get_pid(&self) -> Pid {
        self.pid.clone()
    }

    pub fn get_exe(&self) -> Result<String>
    {
        let r = fs::read_link(format!("/proc/{}/exe", self.pid))?
            .to_string_lossy()
            .into_owned();

        Ok(r)
    }

    pub fn get_map_str(&self) -> Result<String>
    {
        let r = fs::read_to_string(format!("/proc/{}/maps", self.pid))?;
        Ok(r)
    }

    pub fn read(&self, start_addr: usize, size: usize) -> Result<Vec<u8>>
    {
        let mut buffer = vec![0u8; size];
        let mut local_iov = [IoSliceMut::new(&mut buffer)];
        let remote_iov = [RemoteIoVec {
            base: start_addr,
            len: size,
        }];

        let bytes_read = process_vm_readv(self.pid, &mut local_iov, &remote_iov)?;
        if bytes_read == size {
            Ok(buffer)
        } else {
            buffer.truncate(bytes_read);
            Ok(buffer)
        }
    }

    pub fn write(&self, mut start_addr: usize, vdata: &[u8]) -> Result<usize>
    {
        let mut data = vdata.to_owned();

        let mut total_written = 0usize;
        while !data.is_empty() {
            let len = data.len();
            let local_iov = [IoSlice::new(data.as_mut_slice())];
            let remote_iov = [RemoteIoVec {
                base: start_addr,
                len,
            }];

            let written = process_vm_writev(self.pid, &local_iov, &remote_iov)?;

            if written == 0 {
                bail!(format!(
                    "process_vm_writev returned 0 (no progress) after writing {} bytes",
                    total_written
                ));
            }

            total_written += written;
            start_addr = start_addr.wrapping_add(written);
            data = data[written..].to_vec();
        }

        Ok(total_written)
    }

    pub fn get_regs(&self) -> Result<user_regs_struct> {
        Ok(ptrace::getregs(self.get_pid())?)
    }

    pub fn set_regs(&self, regs: &user_regs_struct) -> Result<()> {
        ptrace::setregs(self.get_pid(), *regs)?;
        Ok(())
    }

    pub fn flush_map(&mut self) -> Result<()>
    {
        let maps = fs::read_to_string(format!("/proc/{}/maps", self.pid))?;
        self.map = MemoryMap::new(
            &maps
                .lines()
                .filter(|&line| !line.is_empty())
                .collect::<Vec<&str>>()
        );

        Ok(())
    }

    pub fn module_base_address(&mut self, module: &str) -> Option<u64>
    {
        if let Some(base) = self.modules_base.get(module) {
            return Some(*base as u64);
        }

        let base = self.map.module_base_address(module)?;
        self.modules_base.insert(module.to_string(), base as usize);
        Some(base)
    }

    pub fn execute_once_inplace<F, F2>(
        &mut self,
        payload_builder: F,
        post_proc: F2,
    ) -> Result<user_regs_struct>
    where
        F: Fn(u64) -> Option<Vec<u8>>,
        F2: Fn(&user_regs_struct) -> (),
    {
        // Save context
        let regs = self.get_regs()?;
        let payload = payload_builder(regs.rip).context("payload build failed")?;

        let buffer = self.read(regs.rip as usize, payload.len() + 1)?;
        let instruction = [&payload as &[u8], &[0xccu8]].concat();

        self.write(regs.rip as usize, &instruction)?;
        log::info!("{SUCC} write instructions to {:#016x}", regs.rip);

        // Continue target
        self.cont()?;
        Self::wait()?;

        let r = self.get_regs()?;
        log::info!("{INFO} int3 at {:#016x}", r.rip);

        post_proc(&r);

        self.write(regs.rip as usize, &buffer)?;
        self.set_regs(&regs)?;
        Ok(r)
    }

    pub fn alloc_pages(&mut self, required_addr: u64, count: u64, permissions: u64) -> Result<u64>
    {
        // Alloc r-x private memory
        let r = self.execute_once_inplace(
            |addr| {
                let r = assemble(addr, |asm| {
                    asm.mov(rax, 9u64)?; // Syscall 9 (mmap)

                    asm.mov(rdi, required_addr)?; // Addr
                    asm.mov(rsi, 0x1000u64 * count)?; // Length, we alloc a page (4K)
                    asm.mov(rdx, permissions)?;
                    asm.mov(r10, (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64)?; // Private and anonymous
                    asm.mov(r8, -1i64)?; // Fd (-1 because we want anonymous)
                    asm.mov(r9, 0u64)?; // Offset

                    asm.syscall()?; // Syscall interrupt
                    Ok(())
                })
                .ok()?;

                Some(r)
            },
            |_| {},
        )?;

        Ok(r.rax as u64)
    }

    pub fn redirect(&self, rip: u64) -> Result<()> {
        let regs = self.get_regs()?;
        self.set_regs(&user_regs_struct { rip, ..regs })?;

        log::info!("{SUCC} Redirect the control flow to {}", self.map.format_address(rip as usize));

        Ok(())
    }

    pub fn redirect_relative(&self, offset: i32) -> Result<usize> {
        let mut regs = self.get_regs()?;

        if offset >= 0 {
            regs.rip += offset as u64;
        } else {
            let n = (-offset) as u64;
            regs.rip -= n;
        }
        self.set_regs(&user_regs_struct { rip: regs.rip, ..regs })?;

        log::info!("{SUCC} Redirect relatively the control flow to {}", self.map.format_address(regs.rip as usize));

        Ok(regs.rip as usize)
    }

    pub fn map_region(&self, base: usize, chunk: &Chunk, data: &Bytes) -> Result<()>
    {
        self.write(chunk.vaddr as usize + base, data)?;
        // println!(
        //     "{SUCC} Mapped section at base + {:#0x}, name hash = {}, {}, {}, ...",
        //     chunk.vaddr as usize, chunk.name_hash[0], chunk.name_hash[1], chunk.name_hash[2]
        // );
        Ok(())
    }

    pub fn disassemble<F, T>(&mut self, addr: usize, size: usize, callback: F) -> Result<T>
    where
        F: Fn(&mut Self, &[Instruction]) -> Result<T>,
    {
        let code_bytes = self.read(addr, size)?;
        let decoder = Decoder::with_ip(64, &code_bytes, addr as u64, DecoderOptions::NONE);
        let instructions: Vec<Instruction> = decoder.into_iter().collect();
        let result = callback(self, &instructions)?;
        Ok(result)
    }

    pub fn disassemble_one_at(&self, addr: usize) -> Result<Instruction>
    {
        let code_bytes = self.read(addr, 15)?;
        let decoder = Decoder::with_ip(64, &code_bytes, addr as u64, DecoderOptions::NONE);
        let instructions: Vec<Instruction> = decoder.into_iter().collect();

        Ok(instructions.first().context("Instruction decode failed")?.clone())
    }

    pub fn disassemble_block(&self, va: usize, data: &[u8], ip: usize) -> Result<()>
    {
        let decoder = Decoder::with_ip(64, data, va as u64, DecoderOptions::NONE);
        let instructions: Vec<Instruction> = decoder.into_iter().collect();
        let dmap = self.map.clone();
        let mut cc = 0;

        for inst in instructions
        {
            let prefix = if inst.ip() == ip as u64 {
                " \x1b[32mrip\x1b[0m "
            } else {
                "     "
            };

            let arrow = "\x1b[34m->\x1b[0m";

            log::info!(
                "{}{} <{:#04}> {}:{:02} {}",
                prefix,
                arrow,
                cc,
                dmap.format_address(inst.ip() as usize),
                inst.len(),
                inst.fmt_line_default().unwrap_or_default()
            );
            cc += 1;
        }

        Ok(())
    }

    pub fn disassemble_block_as_raw(&self, va: usize, data: &[u8]) -> Result<Vec<Instruction>>
    {
        let decoder = Decoder::with_ip(64, data, va as u64, DecoderOptions::NONE);
        let instructions: Vec<Instruction> = decoder.into_iter().collect();
        Ok(instructions)
    }

    pub fn disassemble_rip_log(&mut self) -> Result<()>
    {
        let regs = self.get_regs()?;
        let current_rip = self.get_regs()?.rip as usize;

        let mut start_addr = current_rip;

        for _ in 0..2 {
            if let Some(&prev_addr) = self
                .history
                .iter()
                .find(|(addr, len)| *addr + *len == start_addr)
                .map(|(k, _)| k)
            {
                start_addr = prev_addr;
            } else {
                break;
            }
        }

        let mut curr_addr = start_addr;
        let mut lines_printed = 0;
        let dmap = self.map.clone();

        while lines_printed < 5 {
            let (next_addr, success) = self.disassemble(curr_addr, 15, |s, insts| {
                if let Some(inst) = insts.first() {
                    let len = inst.len();

                    s.history.insert(curr_addr, len);

                    let prefix = if curr_addr == current_rip {
                        " \x1b[32mrip\x1b[0m "
                    } else {
                        "     "
                    };

                    let arrow = "\x1b[34m->\x1b[0m";

                    log::info!(
                        "{}{} {}:{:02} {}",
                        prefix,
                        arrow,
                        dmap.format_address(inst.ip() as usize),
                        inst.len(),
                        inst.fmt_line_default().unwrap_or_default()
                    );

                    return Ok((curr_addr + len, true));
                }
                Ok((0, false))
            })?;

            if !success || next_addr == 0 {
                break;
            }

            curr_addr = next_addr;
            lines_printed += 1;
        }

        log::info!("\x1b[90m{}\x1b[0m", "-".repeat(60));

        let gprs = [
            ("rax", regs.rax),
            ("rbx", regs.rbx),
            ("rcx", regs.rcx),
            ("rdx", regs.rdx),
            ("rsi", regs.rsi),
            ("rdi", regs.rdi),
            ("rbp", regs.rbp),
            ("rsp", regs.rsp),
            ("r8 ", regs.r8),
            ("r9 ", regs.r9),
            ("r10", regs.r10),
            ("r11", regs.r11),
            ("r12", regs.r12),
            ("r13", regs.r13),
            ("r14", regs.r14),
            ("r15", regs.r15),
        ];

        for chunk in gprs.chunks(4) {
            let row = chunk
                .iter()
                .map(|(name, val)| {
                    format!("\x1b[33m{}\x1b[0m: \x1b[36m0x{:016x}\x1b[0m", name, val)
                })
                .collect::<Vec<_>>()
                .join("  ");
            log::info!(" {}", row);
        }

        Ok(())
    }

    pub fn disassemble_rip_raw(&mut self) -> Result<Vec<Instruction>>
    {
        let mut r = Vec::<Instruction>::new();
        let current_rip = self.getip()?;

        let mut start_addr = current_rip;

        for _ in 0..2 {
            if let Some(&prev_addr) = self
                .history
                .iter()
                .find(|(addr, len)| *addr + *len == start_addr)
                .map(|(k, _)| k)
            {
                start_addr = prev_addr;
            } else {
                break;
            }
        }

        let mut curr_addr = start_addr;
        let mut lines_printed = 0;

        while lines_printed < 5 {
            let (next_addr, line) = self.disassemble(curr_addr, 15, |s, insts| {
                if let Some(inst) = insts.first() {
                    let len = inst.len();

                    s.history.insert(curr_addr, len);

                    return Ok((curr_addr + len, Some(inst.clone())));
                }
                Ok((0, None))
            })?;

            if let Some(line) = line {
                r.push(line);
            } else {
                break;
            }

            curr_addr = next_addr;
            lines_printed += 1;
        }
        Ok(r)
    }
}