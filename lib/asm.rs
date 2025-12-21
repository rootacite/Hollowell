
// asm.rs

use anyhow::{bail, Result};
use iced_x86::{code_asm::*, BlockEncoder, BlockEncoderOptions, BlockEncoderResult, Code, Decoder, DecoderOptions, FlowControl, Formatter, GasFormatter, Instruction, InstructionBlock, OpKind};
use crate::map::MemoryMap;

use ratatui::{
    style::{Style, Color, Modifier},
    text::{Span},
};
use ratatui::prelude::Line;

pub fn assemble<F>(addr: u64, op: F) -> Result<Vec<u8>>
where
    F: Fn(&mut CodeAssembler) -> Result<()>,
{
    let mut asm = CodeAssembler::new(64)?;
    _ = op(&mut asm);
    Ok(asm.assemble(addr)?)
}

pub trait InstructionFormat {
    fn fmt_line(&self, formatter: &mut dyn Formatter) -> Result<String>;
    fn fmt_line_default(&self) -> Result<String>;
}

impl InstructionFormat for Instruction {
    fn fmt_line(&self, formatter: &mut dyn Formatter) -> Result<String> {
        let mut asm_str = String::new();
        formatter.format(self, &mut asm_str);

        Ok(format!(
            "\x1b[33m{}\x1b[0m",
            asm_str
        ))
    }

    fn fmt_line_default(&self) -> Result<String> {
        let mut fmt = GasFormatter::new();

        self.fmt_line(&mut fmt)
    }
}

pub struct Assembly
{
    data: Vec<u8>,
    offset: usize,
}

impl Assembly
{
    pub fn new(data: &[u8]) -> Self
    {
        Self { data: data.to_owned(), offset: 0 }
    }

    fn decode_one(&self) -> Result<Instruction>
    {
        let mut end = self.offset + 15;
        if end > self.data.len() {
            end = self.data.len();
        }

        let code_bytes = &self.data[self.offset..end];

        let mut decoder = Decoder::with_ip(64, code_bytes, self.offset as u64, DecoderOptions::NONE);

        let instruction = decoder.decode();

        if instruction.is_invalid() {
            bail!("Failed to decode instruction at offset {}", self.offset);
        }

        Ok(instruction)
    }
    pub fn set_ip(&mut self, ip: usize)
    {
        self.offset = ip;
    }

    pub fn next_branch(&mut self) -> Result<usize>
    {
        let o = self.offset;
        loop {
            let instruction = self.decode_one()?;
            self.offset += instruction.len();


            if instruction.code() == Code::Endbr64 && self.offset - 4 != o {
                break Ok(self.offset - instruction.len());
            }

            if self.offset >= self.data.len()
            {
                break Ok(self.offset);
            }
        }
    }

    pub fn instruction_relocate(
        addr: usize,
        data: &[u8],
        new_addr: u64,
    ) -> anyhow::Result<BlockEncoderResult> {
        // 1) Decode original instructions at original address
        let decoder = Decoder::with_ip(64, data, addr as u64, DecoderOptions::NONE);
        let original_instructions: Vec<Instruction> = decoder.into_iter().collect();

        // record original instruction IPs (one-to-one with original_instructions)
        let original_ips: Vec<u64> = original_instructions.iter().map(|i| i.ip()).collect();

        // 2) First encode the block at new_addr to get a provisional layout (to discover new sizes)
        let first_block = InstructionBlock::new(&original_instructions, new_addr);
        let options = BlockEncoderOptions::RETURN_RELOC_INFOS;
        let first_result = BlockEncoder::encode(64, first_block, options)
            .map_err(|e| anyhow::anyhow!("BlockEncoder first pass failed: {}", e))?;

        // re-decode the encoded bytes to get the new per-instruction IPs after re-encoding
        let redecoded = Decoder::with_ip(64, &first_result.code_buffer, new_addr, DecoderOptions::NONE);
        let reencoded_instructions: Vec<Instruction> = redecoded.into_iter().collect();
        let reencoded_ips: Vec<u64> = reencoded_instructions.iter().map(|i| i.ip()).collect();

        // 3) Create a modified instruction list (clone original) and patch near-branch targets
        let mut patched_instructions = original_instructions.clone();

        for inst in patched_instructions.iter_mut() {
            // only consider near branches / calls that have an absolute near target
            match inst.flow_control() {
                FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch | FlowControl::Call => {
                    // Check operand kind: only patch near branch operand kinds
                    match inst.op0_kind() {
                        OpKind::NearBranch16 => {
                            let target = inst.near_branch_target();
                            if Self::is_inside_original_block(target, addr, data.len()) {
                                if let Some(idx) = original_ips.iter().position(|&ip| ip == target) {
                                    let new_target = reencoded_ips[idx];
                                    inst.set_near_branch16(new_target as u16);
                                }
                            }
                        }
                        OpKind::NearBranch32 => {
                            let target = inst.near_branch_target();
                            if Self::is_inside_original_block(target, addr, data.len()) {
                                if let Some(idx) = original_ips.iter().position(|&ip| ip == target) {
                                    let new_target = reencoded_ips[idx];
                                    inst.set_near_branch32(new_target as u32);
                                }
                            }
                        }
                        OpKind::NearBranch64 => {
                            let target = inst.near_branch_target();
                            if Self::is_inside_original_block(target, addr, data.len()) {
                                if let Some(idx) = original_ips.iter().position(|&ip| ip == target) {
                                    let new_target = reencoded_ips[idx];
                                    inst.set_near_branch64(new_target);
                                }
                            }
                        }
                        _ => {
                            // not a near-branch operand; skip
                        }
                    }
                }
                _ => {
                    // not a branch/call we handle; skip
                }
            }
        }

        // 4) Final encode with patched instructions
        let final_block = InstructionBlock::new(&patched_instructions, new_addr);
        let final_result = BlockEncoder::encode(64, final_block, options)
            .map_err(|e| anyhow::anyhow!("BlockEncoder second pass failed: {}", e))?;

        Ok(final_result)
    }

    fn is_inside_original_block(target: u64, orig_addr: usize, orig_len: usize) -> bool {
        let start = orig_addr as u64;
        let end = (orig_addr + orig_len) as u64;
        (target >= start) && (target < end)
    }


    pub fn byte_offset_to_ip(&mut self, offset: usize) -> Result<usize>
    {
        let mut ip = 0usize;
        loop {
            let instruction = self.decode_one()?;
            self.offset += instruction.len();

            let co = instruction.ip();

            if co == offset as u64 {
                return Ok(ip);
            }

            ip += 1;


            if self.offset >= self.data.len() {
                break Ok(ip);
            }
        }
    }

    pub fn ip_to_byte_offset(&mut self, ip: usize) -> anyhow::Result<usize>
    {
        for _ in 0..ip {
            let instruction = self.decode_one()?;
            self.offset += instruction.len();

            if self.offset >= self.data.len() {
                return Ok(self.offset);
            }
        }

        Ok(self.offset)
    }
}

pub trait DynamicFormatter
{
    fn format(&self, ip: usize, map: &MemoryMap) -> String;
    fn format_tui(&self, ip: usize, map: &MemoryMap) -> Line<'_>;
}

impl DynamicFormatter for Instruction
{
    fn format(&self, ip: usize, map: &MemoryMap) -> String
    {
        let prefix = if self.ip() == ip as u64 {
            " \x1b[32mrip\x1b[0m "
        } else {
            "     "
        };

        let arrow = "\x1b[34m->\x1b[0m";

        format!(
            "{}{} {}:{:02} {}",
            prefix,
            arrow,
            map.format_address(self.ip() as usize),
            self.len(),
            self.fmt_line_default().unwrap_or_default()
        )
    }

    fn format_tui(&self, ip: usize, map: &MemoryMap) -> Line<'_> {
        let mut spans = Vec::new();

        if self.ip() == ip as u64 {
            spans.push(
                Span::styled(
                    " rip ",
                    Style::new().fg(Color::Green).add_modifier(Modifier::BOLD),
                )
            );
        } else {
            spans.push(Span::raw("     "));
        }

        spans.push(Span::styled("->", Style::new().fg(Color::Blue)));
        spans.push(Span::raw(" "));
        spans.push(Span::raw(format!(
            "{}:{:02} {}",
            map.format_address(self.ip() as usize),
            self.len(),
            self.fmt_line_default().unwrap_or_default()
        )));

        Line::from(spans)
    }
}
