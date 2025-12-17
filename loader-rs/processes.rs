// processes.rs

use std::collections::HashMap;
use std::fs;

use anyhow::Result;
use anyhow::{Context, bail};
use nix::sys::uio::{RemoteIoVec, process_vm_readv, process_vm_writev};
use nix::unistd::Pid;

use crate::asm::{InstructionFormat, assemble};
use crate::chunk::SectionChunk;
use crate::map::MemoryMap;
use iced_x86::code_asm::{r8, r9, r10, rax, rdi, rdx, rsi};
use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Decoder, DecoderOptions, Instruction, InstructionBlock,
};
use nix::libc;
use nix::libc::user_regs_struct;
use nix::sys::ptrace;
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use std::io::{IoSlice, IoSliceMut};

#[allow(unused)]
const SUCC: &str = "\x1b[32m[+]\x1b[0m";
#[allow(unused)]
const FAIL: &str = "\x1b[31m[-]\x1b[0m";
#[allow(unused)]
const ALER: &str = "\x1b[33m[!]\x1b[0m";
#[allow(unused)]
const INFO: &str = "\x1b[34m[*]\x1b[0m";

type Bytes = Vec<u8>;

#[allow(unused)]
fn list_processes() -> Result<HashMap<String, i32>, std::io::Error> {
    let mut processes = HashMap::<String, i32>::new();

    let entries = fs::read_dir("/proc")?;
    let dirs = entries
        .filter_map(|e| {
            let e = e.ok()?;
            let path = e.path();
            if path.is_dir() {
                return path.file_name()?.to_str().map(|s| s.to_string());
            }
            None::<String>
        })
        .collect::<Vec<String>>();

    for dir in dirs {
        let Ok(pid) = dir.parse::<i32>() else {
            continue;
        };
        let pid_path = format!("/proc/{}/exe", dir);
        let Ok(name_path) = fs::read_link(&pid_path) else {
            continue;
        };
        let name_path = name_path.to_string_lossy().to_string();

        if let Some(name) = name_path.split("/").last() {
            processes.insert(name.to_string(), pid);
        }
    }

    Ok(processes)
}

#[allow(unused)]
pub fn get_pid_by_name(name: &str) -> Result<i32, std::io::Error> {
    let ps = list_processes()?;
    Ok(ps[name])
}

pub struct Process {
    pid: Pid,
    #[allow(unused)]
    map: MemoryMap,
    pub history: HashMap<usize, usize>,
    modules_base: HashMap<String, usize>,
}

impl Process {
    #[allow(unused)]
    fn write_unaligned_head(pid: Pid, addr: usize, data: &[u8], word_size: usize) -> Result<usize> {
        let head_offset = addr % word_size;
        let aligned_addr = addr - head_offset;
        let orig_word = ptrace::read(pid, aligned_addr as *mut libc::c_void)?;
        let mut bytes = orig_word.to_ne_bytes();

        let copy_len = usize::min(word_size - head_offset, data.len());
        bytes[head_offset..head_offset + copy_len].copy_from_slice(&data[..copy_len]);
        let new_word = libc::c_long::from_le_bytes(bytes);

        ptrace::write(pid, aligned_addr as *mut libc::c_void, new_word)?;
        Ok(copy_len)
    }

    #[allow(unused)]
    fn write_full_word(pid: Pid, addr: usize, data: &[u8]) -> Result<usize> {
        let mut arr = [0u8; size_of::<libc::c_long>()];
        arr.copy_from_slice(data);
        let val = libc::c_long::from_le_bytes(arr);
        ptrace::write(pid, addr as *mut libc::c_void, val)?;
        Ok(size_of::<libc::c_long>())
    }

    #[allow(unused)]
    fn write_unaligned_tail(
        pid: Pid,
        addr: usize,
        data: &[u8],
        _word_size: usize,
    ) -> Result<usize> {
        let orig_word = ptrace::read(pid, addr as *mut libc::c_void)?;
        let mut bytes = orig_word.to_ne_bytes();
        bytes[..data.len()].copy_from_slice(data);
        let new_word = libc::c_long::from_le_bytes(bytes);

        ptrace::write(pid, addr as *mut libc::c_void, new_word)?;
        Ok(data.len())
    }

    #[allow(unused)]
    pub fn write_memory_ptrace(&self, start_addr: usize, data: &[u8]) -> Result<usize> {
        println!(
            "{INFO} Try to write {} bytes from {:#0x}",
            data.len(),
            start_addr
        );
        let word_size = size_of::<libc::c_long>();
        if word_size == 0 {
            bail!("invalid word size");
        }

        let mut addr = start_addr;
        let mut remaining = data;
        let mut written = 0usize;

        if addr % word_size != 0 && !remaining.is_empty() {
            let n = Self::write_unaligned_head(self.pid, addr, remaining, word_size)?;
            addr += n;
            remaining = &remaining[n..];
            written += n;
        }

        while remaining.len() >= word_size {
            let n = Self::write_full_word(self.pid, addr, &remaining[..word_size])?;
            addr += n;
            remaining = &remaining[n..];
            written += n;
        }

        if !remaining.is_empty() {
            let n = Self::write_unaligned_tail(self.pid, addr, remaining, word_size)?;
            written += n;
        }

        Ok(written)
    }

    pub fn new(pid: Pid) -> Result<Self> {
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

    pub fn wait(&self) -> Result<WaitStatus> {
        let f = waitpid(self.pid, Some(WaitPidFlag::WUNTRACED))?;

        match f {
            WaitStatus::Stopped(stopped_pid, signal) => {
                println!("{ALER} PID {} stopped by signal: {:?}", stopped_pid, signal);
            }
            WaitStatus::Exited(exited_pid, status) => {
                println!("{ALER} PID {} exited with status: {}", exited_pid, status);
            }
            WaitStatus::Signaled(signaled_pid, signal, core_dump) => {
                println!(
                    "{ALER} PID {} killed by signal: {:?} (core dump: {})",
                    signaled_pid, signal, core_dump
                );
            }
            WaitStatus::Continued(continued_pid) => {
                println!("{ALER} PID {} continued", continued_pid);
            }
            WaitStatus::StillAlive => {
                println!("{ALER} PID {} still alive", self.pid);
            }
            _ => {}
        }

        Ok(f)
    }

    pub fn waitpid(pid: Pid) -> Result<WaitStatus> {
        let f = waitpid(pid, Some(WaitPidFlag::WUNTRACED))?;

        match f {
            WaitStatus::Stopped(stopped_pid, signal) => {
                println!("{ALER} PID {} stopped by signal: {:?}", stopped_pid, signal);
            }
            WaitStatus::Exited(exited_pid, status) => {
                println!("{ALER} PID {} exited with status: {}", exited_pid, status);
            }
            WaitStatus::Signaled(signaled_pid, signal, core_dump) => {
                println!(
                    "{ALER} PID {} killed by signal: {:?} (core dump: {})",
                    signaled_pid, signal, core_dump
                );
            }
            WaitStatus::Continued(continued_pid) => {
                println!("{ALER} PID {} continued", continued_pid);
            }
            WaitStatus::StillAlive => {
                println!("{ALER} PID {} still alive", pid);
            }
            _ => {}
        }

        Ok(f)
    }

    #[allow(unused)]
    pub fn get_pid(&self) -> Pid {
        self.pid.clone()
    }

    #[allow(unused)]
    pub fn get_exe(&self) -> Result<String> {
        let r = fs::read_link(format!("/proc/{}/exe", self.pid))?
            .to_string_lossy()
            .into_owned();

        Ok(r)
    }

    #[allow(unused)]
    pub fn get_map_str(&self) -> Result<String> {
        let r = fs::read_to_string(format!("/proc/{}/maps", self.pid))?;

        Ok(r)
    }

    #[allow(unused)]
    pub fn read_memory_vm(&self, start_addr: usize, size: usize) -> Result<Vec<u8>> {
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

    #[allow(unused)]
    pub fn write_memory_vm(&self, mut start_addr: usize, vdata: &[u8]) -> Result<usize> {
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

    #[allow(unused)]
    pub fn get_regs(&self) -> Result<user_regs_struct> {
        Ok(ptrace::getregs(self.get_pid())?)
    }

    #[allow(unused)]
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

    #[allow(unused)]
    pub fn module_base_address(&mut self, module: &str) -> Option<u64> {
        if let Some(base) = self.modules_base.get(module) {
            return Some(*base as u64);
        }

        let base = self.map.module_base_address(module)?;
        self.modules_base.insert(module.to_string(), base as usize);
        Some(base)
    }

    #[allow(unused)]
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
        let regs = ptrace::getregs(self.pid)?;
        let payload = payload_builder(regs.rip).context("payload build failed")?;

        let buffer = self.read_memory_vm(regs.rip as usize, payload.len() + 1)?;
        let instruction = [&payload as &[u8], &[0xccu8]].concat();

        self.write_memory_ptrace(regs.rip as usize, &instruction)?;
        println!("{SUCC} write instructions to {:#016x}", regs.rip);

        // self.disassemble(regs.rip, instruction.len() as u64, |s, inst| {
        //     for i in inst.iter() {
        //         println!(
        //             "{INFO} {}",
        //             i.fmt_line_default().ok().context("Failed to parse line")?
        //         );
        //     }
        //
        //     Ok(())
        // })?;

        // Continue target
        ptrace::cont(self.pid, None)?;
        println!("{SUCC} continue from {:#016x}", regs.rip);
        self.wait();

        let r = ptrace::getregs(self.pid)?;
        println!("{INFO} int3 at {:#016x}", r.rip);

        post_proc(&r);

        self.write_memory_ptrace(regs.rip as usize, &buffer)?;
        ptrace::setregs(self.pid, regs)?;
        Ok(r)
    }

    #[allow(unused)]
    pub fn alloc_pages(&mut self, count: u64, permissions: u64) -> Result<u64> {
        // Alloc r-x private memory
        let r = self.execute_once_inplace(
            |addr| {
                let r = assemble(addr, |asm| {
                    asm.mov(rax, 9u64)?; // Syscall 9 (mmap)

                    asm.mov(rdi, 0u64)?; // Addr
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

    #[allow(unused)]
    pub fn disassemble<F, T>(&mut self, addr: u64, size: u64, callback: F) -> Result<T>
    where
        F: Fn(&mut Self, &[Instruction]) -> Result<T>,
    {
        let code_bytes = self.read_memory_vm(addr as usize, size as usize)?;
        let decoder = Decoder::with_ip(64, &code_bytes, addr, DecoderOptions::NONE);
        let instructions: Vec<Instruction> = decoder.into_iter().collect();
        let result = callback(self, &instructions)?;
        Ok(result)
    }

    #[allow(unused)]
    pub fn instruction_relocate(&self, addr: u64, size: u64, new_addr: u64) -> Result<Vec<u8>> {
        let origin = self.read_memory_vm(addr as usize, size as usize)?;

        let decoder = Decoder::with_ip(64, &origin, addr, DecoderOptions::NONE);
        let instructions: Vec<_> = decoder.into_iter().collect();

        let block = InstructionBlock::new(&instructions, new_addr);
        let options = BlockEncoderOptions::RETURN_RELOC_INFOS;

        let result = BlockEncoder::encode(64, block, options)
            .map_err(|e| format!("BlockEncoder failed: {}", e))
            .ok()
            .context("BlockEncoder failed")?;

        Ok(result.code_buffer.clone())
    }

    pub fn redirect(&self, rip: u64) -> Result<()> {
        let regs = self.get_regs()?;
        self.set_regs(&user_regs_struct { rip, ..regs })?;

        println!("{SUCC} Redirect the execution stream to {:#0x}", rip);

        Ok(())
    }
}

impl Process {
    pub fn map_region(&self, base: usize, chunk: &SectionChunk, data: &Bytes) -> Result<()> {
        self.write_memory_vm(chunk.vaddr as usize + base, data)?;
        println!(
            "{SUCC} Mapped section at base + {:#0x}, name hash = {}, {}, {}, ...",
            chunk.vaddr as usize, chunk.name_hash[0], chunk.name_hash[1], chunk.name_hash[2]
        );
        Ok(())
    }

    pub fn disassemble_rip(&mut self) -> Result<()> {
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
            let (next_addr, success) = self.disassemble(curr_addr as u64, 15, |s, insts| {
                if let Some(inst) = insts.first() {
                    let len = inst.len();

                    s.history.insert(curr_addr, len);

                    let prefix = if curr_addr == current_rip {
                        " \x1b[32mrip\x1b[0m "
                    } else {
                        "     "
                    };

                    let arrow = "\x1b[34m->\x1b[0m";

                    println!(
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

        println!("\x1b[90m{}\x1b[0m", "-".repeat(60));

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
            println!(" {}", row);
        }

        Ok(())
    }
}
