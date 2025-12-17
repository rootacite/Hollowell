
use std::ffi::{CStr, CString};
use std::io::{Read};
use std::os::raw::{c_char, c_int, c_void};
use std::slice;
use std::str::FromStr;
use anyhow::*;
use flate2::read::GzDecoder;
use goblin::elf64::section_header::SHT_NOBITS;
use once_cell::sync::Lazy;
use plain::Plain;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct SectionChunk {
    pub name_hash: [u8; 32],
    pub vaddr: u64,
    pub chunk_type: u32,
    pub size: u64,
    pub flags: u32,
    pub align: u64,
    pub link: u32,
    pub info: u32,
    pub entsize: u64,
}

unsafe impl Plain for SectionChunk {}

type CUlong = u64;
type Bytes = Vec<u8>;
static SEED: Lazy<Vec<u8>> = Lazy::new(|| {
    get_seed().unwrap()
});

static CHUNK_TABLE: Lazy<Vec<SectionChunk>> = Lazy::new(|| {
    plain::slice_from_bytes::<SectionChunk>(get_chunk_by_name("ct").unwrap().as_slice()).unwrap().to_vec()
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

fn decompress(compressed_data: &[u8]) -> Result<Vec<u8>>
{
    let mut decoder = GzDecoder::new(compressed_data);

    let mut decompressed_data = Vec::new();
    decoder.read_to_end(&mut decompressed_data)?;

    Ok(decompressed_data)
}

fn get_seed() -> Result<Vec<u8>>
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
        return Ok(unsafe { slice::from_raw_parts(cb.addr, cb.size as usize) }.to_vec());
    }

    bail!("Unable to find seed");
}

#[allow(unused)]
pub fn get_chunk_by_name(name: &str) -> Result<Vec<u8>>
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
        return Ok(decompress(&b)?);
    }

    bail!("Unable to find chunk by name");
}

#[allow(unused)]
pub fn get_chunk_by_vdata(vdata: u64) -> Result<Vec<u8>>
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
        return Ok(decompress(&b)?);
    }

    bail!("Unable to find chunk by name");
}

#[allow(unused)]
pub fn get_chunks_by_filter<F>(filter: F) -> Vec<(SectionChunk, Option<Bytes>)>
    where F: Fn(&SectionChunk) -> bool
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
        .collect::<Vec<(SectionChunk, Option<Bytes>)>>()
}
