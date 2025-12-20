
use std::ffi::{CStr, CString};
use std::io::{Read, Write};
use std::os::raw::{c_char, c_int, c_void};
use std::{fs, slice};
use std::ops::DerefMut;
use std::str::FromStr;
use anyhow::{bail};
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use goblin::elf32::section_header::SHT_NOBITS;
use plain::Plain;
use crate::elfdef;

use once_cell::sync::Lazy;
use sha2::{Digest, Sha256};

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Chunk {
    pub name_hash: [u8; 32],
    pub vaddr: u64,
    pub chunk_type: u32,
    pub size: u64,
    pub flags: u64,
    pub align: u64,
    pub link: u32,
    pub info: u32,
    pub entsize: u64,
    pub o_offset: u64
}

unsafe impl Plain for Chunk {}

type CUlong = u64;
type Bytes = Vec<u8>;
static SEED: Lazy<Vec<u8>> = Lazy::new(|| { get_seed().unwrap() });

static CHUNK_TABLE: Lazy<Vec<Chunk>> = Lazy::new(|| {
    plain::slice_from_bytes::<Chunk>(get_chunk_by_name("ct").unwrap().as_slice()).unwrap().to_vec()
});

#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct ChunkInfo {
    pub data: *mut u8,
    pub size: CUlong,
    pub name: *mut c_char,
    pub vdata: CUlong,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct CbIo {
    pub name: *mut c_char,
    pub vdata: u64,
    pub addr: *const u8,
    pub size: u64,
}

type ChunkCallback = extern "C" fn(
    chunk_info: *const ChunkInfo,
    user_data: *mut c_void,
) -> c_int;

unsafe extern "C" {
    fn iter_chunks(
        cb: ChunkCallback,
        user_data: *mut c_void,
    ) -> c_int;
}

extern "C" fn iter_by_name(chunk_info: *const ChunkInfo, user_data: *mut c_void) -> c_int
{
    let chunk_info: &ChunkInfo = unsafe { &*chunk_info };
    let user_data: &mut CbIo = unsafe { &mut *(user_data as *mut CbIo) };

    let name_str = unsafe { CStr::from_ptr(chunk_info.name).to_str().unwrap() };
    let target_name = unsafe { CStr::from_ptr(user_data.name).to_str().unwrap() };

    if target_name == name_str {
        user_data.addr = chunk_info.data;
        user_data.size = chunk_info.size;
        return 0;
    }
    1
}

extern "C" fn iter_by_vdata(chunk_info: *const ChunkInfo, user_data: *mut c_void) -> c_int
{
    let chunk_info: &ChunkInfo = unsafe { &*chunk_info };
    let user_data: &mut CbIo = unsafe { &mut *(user_data as *mut CbIo) };

    if chunk_info.vdata == user_data.vdata {
        user_data.addr = chunk_info.data;
        user_data.size = chunk_info.size;
        return 0;
    }
    1
}

fn decompress(compressed_data: &[u8]) -> anyhow::Result<Vec<u8>>
{
    let mut decoder = GzDecoder::new(compressed_data);

    let mut decompressed_data = Vec::new();
    decoder.read_to_end(&mut decompressed_data)?;

    anyhow::Ok(decompressed_data)
}

fn get_seed() -> anyhow::Result<Vec<u8>>
{
    let name_cstr = CString::from_str("seed")?;

    let mut cb = CbIo {
        name: name_cstr.as_ptr() as *mut c_char,
        vdata: 0,
        addr: std::ptr::null_mut(),
        size: 0,
    };

    let r = unsafe {
        iter_chunks(iter_by_name, &mut cb as *mut CbIo as *mut c_void)
    };

    if r == 1 {
        return anyhow::Ok(unsafe { slice::from_raw_parts(cb.addr, cb.size as usize) }.to_vec());
    }

    bail!("Unable to find seed");
}

pub fn get_chunk_by_name(name: &str) -> anyhow::Result<Vec<u8>>
{
    let name_cstr = CString::from_str(name)?;

    let mut cb = CbIo {
        name: name_cstr.as_ptr() as *mut c_char,
        vdata: 0,
        addr: std::ptr::null_mut(),
        size: 0,
    };

    let r = unsafe {
        iter_chunks(iter_by_name, &mut cb as *mut CbIo as *mut c_void)
    };

    if r == 1 {
        let mut b = unsafe { slice::from_raw_parts(cb.addr, cb.size as usize) }.to_vec();
        for i in 0..b.len()
        {
            b[i] ^= SEED[i % 32];
        }
        return anyhow::Ok(decompress(&b)?);
    }

    bail!("Unable to find chunk by name");
}

pub fn get_chunk_by_vdata(vdata: u64) -> anyhow::Result<Vec<u8>>
{
    let mut cb = CbIo {
        name: std::ptr::null_mut(),
        vdata,
        addr: std::ptr::null_mut(),
        size: 0,
    };

    let r = unsafe {
        iter_chunks(iter_by_vdata, &mut cb as *mut CbIo as *mut c_void)
    };

    if r == 1 {
        let mut b = unsafe { slice::from_raw_parts(cb.addr, cb.size as usize) }.to_vec();
        for i in 0..b.len()
        {
            b[i] ^= SEED[i % 32];
        }
        return anyhow::Ok(decompress(&b)?);
    }

    bail!("Unable to find chunk by name");
}

pub fn get_chunks_by_filter<F>(filter: F) -> Vec<(Chunk, Option<Bytes>)>
where F: Fn(&Chunk) -> bool
{
    CHUNK_TABLE.iter()
        .filter(|x| filter(x))
        .filter_map(|x| {
            let v = get_chunk_by_vdata(x.vaddr).ok();
            if let Some(v) = v {
                return Some((x.to_owned(), Some(v)));
            }
            if x.chunk_type == SHT_NOBITS
            {
                return Some((x.to_owned(), None));
            }
            return None;
        })
        .collect::<Vec<(Chunk, Option<Bytes>)>>()
}

pub fn get_ehdr() -> anyhow::Result<elfdef::Header>
{
    let ehdr_bytes = get_chunk_by_name("ehdr")?;
    let Ok(ehdr) = plain::from_bytes::<elfdef::Header>(&ehdr_bytes) else { bail!("Could not parse ELF header") };

    Ok(ehdr.clone())
}

pub fn get_phdr() -> anyhow::Result<Vec<elfdef::ProgramHeader>>
{
    let phdr_bytes = get_chunk_by_name("phdr")?;
    let Ok(phdr) = plain::slice_from_bytes::<elfdef::ProgramHeader>(&phdr_bytes) else { bail!("Could not parse Program header") };

    Ok(phdr.to_vec())
}

fn confuse_data(data: &mut [u8], seed: &str) -> anyhow::Result<()>
{
    let key = hash_sha256(&seed.as_bytes());

    for i in 0..data.len() {
        let b = data[i] ^ key[i % 32];
        data[i] = b;
    }

    anyhow::Ok(())
}

pub fn write_compressed(path: &str, content: &[u8], seed: &str) -> anyhow::Result<()>
{
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(content)?;
    let mut compressed = encoder.finish()?;

    confuse_data(compressed.deref_mut(), seed)?;
    fs::write(path, compressed)?;
    anyhow::Ok(())
}


pub fn hash_sha256(data: &[u8]) -> Vec<u8>
{
    let mut hasher = Sha256::new();
    hasher.update(data);
    let key: sha2::digest::generic_array::GenericArray<u8, sha2::digest::typenum::UInt<sha2::digest::typenum::UInt<sha2::digest::typenum::UInt<sha2::digest::typenum::UInt<sha2::digest::typenum::UInt<sha2::digest::typenum::UInt<sha2::digest::typenum::UTerm, sha2::digest::consts::B1>, sha2::digest::consts::B0>, sha2::digest::consts::B0>, sha2::digest::consts::B0>, sha2::digest::consts::B0>, sha2::digest::consts::B0>> = hasher.finalize();

    key.as_slice().to_owned()
}
