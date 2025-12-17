
mod chunk;
mod elfdef;
mod parser;
mod auxiliary;
mod hollowgen;
mod processes;
mod elf;
mod map;
mod asm;
mod relocation;
mod stagger;

use std;
use std::convert::Infallible;
use std::ffi::{CStr, CString};
use std::os::fd::{AsFd};
use anyhow::{Result, Context};

use crate::auxiliary::{QuickConver};

use nix::sys::memfd::{memfd_create, MFdFlags};

use nix::unistd::{write, lseek, Whence, ForkResult, Pid};
use nix::sys::ptrace;

use std::os::unix::ffi::OsStrExt;
use nix::sys::wait::{WaitStatus};

use crate::processes::Process;
use crate::parser::get_ehdr;

use console::{Term, Key};
use crate::stagger::SymbolResolvable;

#[allow(unused)]
const SUCC: &str = "\x1b[32m[+]\x1b[0m";
#[allow(unused)]
const FAIL: &str = "\x1b[31m[-]\x1b[0m";
#[allow(unused)]
const ALER: &str = "\x1b[31m[!]\x1b[0m";
#[allow(unused)]
const INFO: &str = "\x1b[34m[*]\x1b[0m";

type Relr = u64;
type Bytes = Vec<u8>;

fn fexecve_with_current_argv_env<Fd: AsFd>(fd: Fd) -> nix::Result<Infallible>
{

    let argv_c: Result<Vec<CString>, std::ffi::NulError> = std::env::args_os()
        .map(|os| CString::new(os.as_os_str().as_bytes()))
        .collect();
    let argv_c = argv_c.map_err(|_| nix::Error::from(nix::errno::Errno::EINVAL))?;
    let argv_refs: Vec<&CStr> = argv_c.iter().map(|s| s.as_c_str()).collect();

    let envp_c: Result<Vec<CString>, std::ffi::NulError> = std::env::vars_os()
        .map(|(k, v)| {
            // create NAME=VALUE as bytes
            let mut kv = Vec::with_capacity(k.as_os_str().len() + 1 + v.as_os_str().len());
            kv.extend_from_slice(k.as_os_str().as_bytes());
            kv.push(b'=');
            kv.extend_from_slice(v.as_os_str().as_bytes());
            CString::new(kv)
        })
        .collect();
    let envp_c = envp_c.map_err(|_| nix::Error::from(nix::errno::Errno::EINVAL))?;
    let envp_refs: Vec<&CStr> = envp_c.iter().map(|s| s.as_c_str()).collect();

    nix::unistd::fexecve(fd, &argv_refs, &envp_refs)
}

fn main() -> Result<()> {
    let term = Term::stdout();
    let ehdr = get_ehdr()?;
    let hollow = stagger::HollowStage::build()?;

    let hollow_mem = memfd_create("hollow", MFdFlags::empty())?;
    write(&hollow_mem, &hollow.data)?;
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

    let mut proc = Process::new(child)?;
    println!("{SUCC} Opened process {}", child);
    ptrace::cont(child, None)?;
    proc.wait()?;

    let regs = proc.get_regs()?;

    let sbase = regs.rip - 1 - 8;
    let base = proc.read_memory_vm((regs.rip - 1 - 8) as usize, 8)?.to::<u64>()?;
    println!("{SUCC} Hollow process load main module at {:#0x}, Base is {:#0x}", base, base);

    proc.redirect(base + ehdr.e_entry)?;

    for i in hollow.chunks.iter()
    {
        if let (s, Some(b)) = i && s.vaddr >= (sbase - base)
        {
            // At present, during the testing phase, the entire section is temporarily loaded
            // Subsequently, the loading layout will be shuffled based on instruction analysis
            // And the instructions and the data referenced by the instructions will be dynamically written
            // Instructions unrelated to the current location will be written to a random location for execution
            // Instructions or data unrelated to the current state will be filled with int3 (0xcc) and 0
            proc.map_region(base as usize, &s, b)?;
        }
    }

    proc.flush_map()?;
    proc.do_rela_reloc(base as usize, &hollow.rela, &hollow.deps, &hollow.syms)?;
    proc.do_relr_reloc(base as usize, &hollow.relr)?;

    let r_debug = hollow.deps.resolve_symbol(&mut proc, "_r_debug").context("hollow.r_debug")?;

    loop {
        if let Ok(key) = term.read_key()
        {
            match key {
                Key::Char(c) => {
                    match c {
                        's' => {
                            ptrace::step(child, None)?;
                        }
                        'c' => {
                            ptrace::cont(child, None)?;
                        }
                        'q' => {
                            ptrace::kill(child)?;
                            break;
                        }
                        _ => { continue; }
                    }
                },
                _ => { continue; }
            }
        } else
        {
            continue;
        }

        let status = proc.wait().context("Failed to wait on child")?;

        match status {
            WaitStatus::Stopped(_, _) => {
                let regs = proc.get_regs().ok().context("Failed to get regs")?;
                if let Err(_) = proc.disassemble_rip()
                {
                    println!("{FAIL} Failed to disassemble rip.");
                }
                println!("{INFO} RIP is at {:#0x}", regs.rip);
            }
            WaitStatus::Exited(_, _) => {
                break;
            }
            _ => {}
        }
    }

    Ok(())
}