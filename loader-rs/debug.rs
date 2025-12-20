use iced_x86::Instruction;
use hollowell::auxiliary::{ChunkMeta, ChunkMetaInMemory};
use hollowell::processes::Process;

use anyhow::{Result};

pub struct HollowStageDebug
{
    // Debug fields
    pub focused_origin: Vec<Instruction>,
    pub focused_relocated: Vec<Instruction>,
    pub ips: (usize, usize), // Ip in origin chunk, Ip in relocated chunk
    pub ins_number: usize,

    pub debug: bool,
    pub tui: bool,
    pub major: Option<Process>,

    pub clear: bool,

    pub focused_near: Vec<Instruction>,
}

impl HollowStageDebug {
    pub fn debug_flush_block(&mut self, o: &ChunkMeta, r: &ChunkMetaInMemory, ip: (usize, usize), n: usize) -> Result<()>
    {
        if !self.debug {
            return Ok(());
        }

        if let Some(major) = &mut self.major {
            if self.tui
            {
                self.focused_origin = major.disassemble_block_as_raw(o.address as usize, &o.data)?;
                self.focused_relocated = major.disassemble_block_as_raw(r.relocated as usize, &r.data)?;
                self.ips = ip;
                self.ins_number = n;
                self.clear = true;

                self.focused_near = major.disassemble_rip_raw()?;
                return Ok(());
            }

            if self.debug
            {
                major.disassemble_block(o.address as usize, &o.data, ip.0)?;
                log::info!("------------------------------------------------------");
                major.disassemble_block(r.relocated as usize, &r.data, ip.1)?;
            }
        }

        Ok(())
    }

    pub fn debug_flush_ip(&mut self, ip: (usize, usize), n: usize) -> Result<()>
    {
        self.ips = ip;
        self.ins_number = n;
        if let Some(major) = &mut self.major
        {
            self.clear = true;
            self.focused_near = major.disassemble_rip_raw()?;
        }

        Ok(())
    }
}