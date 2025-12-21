
use anyhow::{bail};
use goblin::elf::program_header::PT_LOAD;
use plain::{Plain};

use crate::elfdef::ProgramHeader;

#[allow(unused)]
const SUCC: &str = "\x1b[32m[+]\x1b[0m";
#[allow(unused)]
const FAIL: &str = "\x1b[31m[-]\x1b[0m";
#[allow(unused)]
const ALER: &str = "\x1b[31m[!]\x1b[0m";
#[allow(unused)]
const INFO: &str = "\x1b[34m[*]\x1b[0m";

#[derive(Debug, Clone)]
pub struct ChunkMeta
{
    pub address: u64,
    pub in_window: bool,
    pub fault_counter: u32,
    pub data: Vec<u8>
}

#[derive(Debug, Clone)]
pub struct ChunkMetaInMemory
{
    pub origin_address: u64,
    pub data: Vec<u8>,
    pub relocated: u64
}

pub trait ProgramHeaderExt {
    fn get_image_size(&self) -> usize;
    #[allow(unused)]
    fn locate(&self, address: usize) -> Option<&ProgramHeader>;
}

pub trait Flatten<T> {
    fn flatten(&self) -> Vec<u8>;
}

pub trait RandomLength {
    fn strlen(&self, addr: usize) -> usize;
}

impl ProgramHeaderExt for &[ProgramHeader]
{
    fn get_image_size(&self) -> usize
    {
        let mut image_size: u64 = 0;

        for i in self.iter()
        {
            if i.p_type == PT_LOAD && i.p_vaddr + i.p_memsz >= image_size {
                image_size = i.p_vaddr + i.p_memsz;
            }
        }

        image_size as usize
    }

    fn locate(&self, address: usize) -> Option<&ProgramHeader>
    {
        for i in self.iter()
        {
            if i.p_type == PT_LOAD
                && address >= i.p_vaddr as usize
                && address < (i.p_vaddr + i.p_memsz) as usize {
                return Some(i);
            }
        }

        None
    }
}

impl<T, B> Flatten<T> for B
    where
        T: Plain,
        B: AsRef<[T]>
{
    fn flatten(&self) -> Vec<u8>
    {
        let mut flattened: Vec<u8> = Vec::new();
        for i in self.as_ref().iter()
        {
            let mut b = unsafe { plain::as_bytes::<T>(&i) }.to_vec();
            flattened.append(&mut b);
        }

        flattened
    }
}

impl RandomLength for &[u8]
{
    fn strlen(&self, offset: usize) -> usize
    {
        let mut len: usize = 0;

        for i in offset..self.len()
        {
            if self.get(i) != Some(&b'\0')
            {
                len += 1;
            }
            else
            {
                break;
            }
        }

        len
    }
}

pub trait QuickConver {
    fn to<T>(&self) -> anyhow::Result<T>
    where
        T: Plain + Clone;
}

impl<B> QuickConver for B
where
    B: AsRef<[u8]>
{
    fn to<T>(&self) -> anyhow::Result<T>
    where
        T: Plain + Clone,
    {
        let e = plain::from_bytes::<T>(self.as_ref());
        match e {
            Ok(v) => {
                anyhow::Ok(v.to_owned())
            }
            Err(_) => {
                bail!("Failed to convert");
            }
        }
    }
}

pub trait BlockLocator
{
    fn find_block_index(&self, x: u64) -> Option<usize>;
}

pub trait BlockLocatorInMemory {
    fn find_block_in_memory(&mut self, x: u64) -> Option<&mut ChunkMetaInMemory>;
    fn find_block_out_memory(&mut self, x: u64) -> Option<&mut ChunkMetaInMemory>;
}

impl<B> BlockLocator for B
where
    B: AsRef<[ChunkMeta]>
{
    fn find_block_index(&self, x: u64) -> Option<usize>
    {
        let mut l = 0usize;
        let mut r = self.as_ref().len();

        while l < r {
            let m = (l + r) / 2;
            if self.as_ref()[m].address <= x {
                l = m + 1;
            } else {
                r = m;
            }
        }

        if l == 0 {
            return None;
        }

        let h = &self.as_ref()[l - 1];
        if x < h.address + h.data.len() as u64 {
            Some(l - 1)
        } else {
            None
        }
    }
}

impl<B> BlockLocatorInMemory for B
where
    B: AsMut<[ChunkMetaInMemory]>
{
    fn find_block_in_memory(&mut self, x: u64) -> Option<&mut ChunkMetaInMemory> {
        for i in self.as_mut() {
            if x >= i.relocated && x < i.relocated + i.data.len() as u64 {
                return Some(i);
            }
        }

        None
    }

    fn find_block_out_memory(&mut self, x: u64) -> Option<&mut ChunkMetaInMemory> {
        for i in self.as_mut() {
            if x == i.origin_address {
                return Some(i);
            }
        }

        None
    }
}
