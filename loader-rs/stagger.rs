
pub mod kinesis;
pub mod debug;
pub mod scenery;

use anyhow::{Result};

use goblin::elf::sym::{STB_GLOBAL, STT_FUNC, STT_GNU_IFUNC, STT_NOTYPE, STT_OBJECT, STT_TLS};

use std::collections::HashMap;

use hollowell::elfdef::{SymbolTableEntry};


use crate::tui::UI;
use hollowell::asm::{assemble};

use hollowell::processes::Process;
use crate::stagger::debug::HollowDebug;
use crate::stagger::kinesis::HollowKinesis;
use crate::stagger::scenery::HollowScenery;

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

const NEAR_LIMIT: u64 = 2 * 1024 * 1024 * 1024;

pub struct HollowStage {
    #[allow(unused)]
    pub scenery: HollowScenery,
    pub kinesis: HollowKinesis,
    pub debug: HollowDebug,

    pub tui: Option<UI>,
}

impl HollowStage {
    pub fn arrange() -> Result<HollowStage>
    {
        let mut scenery = HollowScenery::build()?;
        let mut kinesis = scenery.startup()?;
        let debug = kinesis.debug()?;

        Ok(HollowStage {
            scenery,
            kinesis,
            debug,
            tui: None
        })
    }

    pub fn staging(&mut self) -> Result<()> {
        if !self.debug.debug || self.tui.is_some() {
            log::set_max_level(log::LevelFilter::Off);
        }

        if self.debug.do_log {
            log::set_max_level(log::LevelFilter::Debug);
        }

        Ok(self.kinesis.staging(&mut self.debug, &mut self.tui)?)
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
