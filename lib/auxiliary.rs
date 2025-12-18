
use anyhow::{bail};
use goblin::elf::program_header::PT_LOAD;
use plain::{Plain};
use sha2::{Digest, Sha256};
use crate::elfdef::ProgramHeader;

#[allow(unused)]
const SUCC: &str = "\x1b[32m[+]\x1b[0m";
#[allow(unused)]
const FAIL: &str = "\x1b[31m[-]\x1b[0m";
#[allow(unused)]
const ALER: &str = "\x1b[31m[!]\x1b[0m";
#[allow(unused)]
const INFO: &str = "\x1b[34m[*]\x1b[0m";

pub trait ProgramHeaderExt {
    fn get_image_size(&self) -> usize;
    #[allow(unused)]
    fn locate(&self, address: usize) -> Option<&ProgramHeader>;
}

pub trait Flatten {
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

impl<T> Flatten for &[T]
    where T: Plain
{
    fn flatten(&self) -> Vec<u8>
    {
        let mut flattened: Vec<u8> = Vec::new();
        for i in self.iter()
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

pub fn hash_sha256(data: &[u8]) -> Vec<u8>
{
    let mut hasher = Sha256::new();
    hasher.update(data);
    let key: sha2::digest::generic_array::GenericArray<u8, sha2::digest::typenum::UInt<sha2::digest::typenum::UInt<sha2::digest::typenum::UInt<sha2::digest::typenum::UInt<sha2::digest::typenum::UInt<sha2::digest::typenum::UInt<sha2::digest::typenum::UTerm, sha2::digest::consts::B1>, sha2::digest::consts::B0>, sha2::digest::consts::B0>, sha2::digest::consts::B0>, sha2::digest::consts::B0>, sha2::digest::consts::B0>> = hasher.finalize();

    key.as_slice().to_owned()
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
