
mod hollowgen;
mod relocation;
mod stagger;
mod tui;
mod debug;

use std;
use std::convert::Infallible;
use std::env;
use std::ffi::{CStr, CString};

use std::os::fd::{AsFd};
use anyhow::{Result};
use std::os::unix::ffi::OsStrExt;
use std::io::Write;
use crate::tui::UI;

#[allow(unused)]
const SUCC: &str = "\x1b[32m[+]\x1b[0m";
#[allow(unused)]
const FAIL: &str = "\x1b[31m[-]\x1b[0m";
#[allow(unused)]
const ALER: &str = "\x1b[31m[!]\x1b[0m";
#[allow(unused)]
const INFO: &str = "\x1b[34m[*]\x1b[0m";

fn fexecve_with_current_argv_env<Fd: AsFd>(fd: Fd) -> nix::Result<Infallible>
{

    let argv_c: Result<Vec<CString>, std::ffi::NulError> = env::args_os()
        .map(|os| CString::new(os.as_os_str().as_bytes()))
        .collect();
    let argv_c = argv_c.map_err(|_| nix::Error::from(nix::errno::Errno::EINVAL))?;
    let argv_refs: Vec<&CStr> = argv_c.iter().map(|s| s.as_c_str()).collect();

    let envp_c: Result<Vec<CString>, std::ffi::NulError> = env::vars_os()
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
    let mut builder = env_logger::Builder::new();
    builder.format(|buf, record| {
        writeln!(buf, "<{}> {}",
                 record.target(),
                 record.args()
        )
    });
    builder.filter_level(log::LevelFilter::Debug);

    let logger = builder.build();
    log::set_boxed_logger(Box::new(logger))?;

    log::set_max_level(log::LevelFilter::Debug);

    let mut hollow = stagger::HollowStage::build()?;

    hollow.do_relocate = !match env::var("HC_DONT_RELOCATE") {
        Ok(_) => true,
        Err(_) => false,
    };

    hollow.debug.debug = match env::var("HC_DEBUG") {
        Ok(_) => true,
        Err(_) => false,
    };

    hollow.do_log = match env::var("HC_LOG") {
        Ok(_) => true,
        Err(_) => false,
    };

    hollow.tui = match env::var("HC_TUI") {
        Ok(_) => {
            hollow.debug.debug = true;
            hollow.debug.tui = true;
            log::set_max_level(log::LevelFilter::Off);
            Some(UI::new()?)
        },
        Err(_) => None,
    };

    hollow.startup()?;
    hollow.prepare()?;
    hollow.staging()?;

    Ok(())
}