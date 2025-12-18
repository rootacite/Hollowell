
use std::collections::HashMap;
use std::ffi::{c_void, CStr, CString};
use std::ptr;

use goblin::elf64::header::SIZEOF_IDENT;
use nix::libc;
use nix::libc::{c_char, dlclose, dlopen, RTLD_LAZY};
use plain::Plain;
use crate::auxiliary::{Flatten, RandomLength};

#[derive(Clone, Debug)]
pub struct SectionHeader {
    pub sh_name: String,
    pub sh_type: u32,
    pub sh_flags: u64,
    pub sh_addr: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u64,
    pub sh_entsize: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Header {
    pub e_ident           : [u8; SIZEOF_IDENT],
    pub e_type            : u16,
    pub e_machine         : u16,
    pub e_version         : u32,
    pub e_entry           : u64,
    pub e_phoff           : u64,
    pub e_shoff           : u64,
    pub e_flags           : u32,
    pub e_ehsize          : u16,
    pub e_phentsize       : u16,
    pub e_phnum           : u16,
    pub e_shentsize       : u16,
    pub e_shnum           : u16,
    pub e_shstrndx        : u16,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct ProgramHeader {
    pub p_type  : u32,
    pub p_flags : u32,
    pub p_offset: u64,
    pub p_vaddr : u64,
    pub p_paddr : u64,
    pub p_filesz: u64,
    pub p_memsz : u64,
    pub p_align : u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Dyn {
    pub d_tag: u64,
    pub d_val: u64
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Rela {
    pub r_offset: u64,
    pub r_info: u64,
    pub r_addend: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Sym {
    pub st_name: u32,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: u16,
    pub st_value: u64,
    pub st_size: u64,
}


unsafe impl Plain for Header {}
unsafe impl Plain for ProgramHeader {}
unsafe impl Plain for Dyn {}
unsafe impl Plain for Rela {}
unsafe impl Plain for Sym {}

pub fn elf_hash(name: &[u8]) -> u32 {
    let mut h = 0u32;
    let mut g;

    for &byte in name {
        h = (h << 4).wrapping_add(byte as u32);
        g = h & 0xf000_0000;
        if g != 0 {
            h ^= g >> 24;
        }
        h &= !g;
    }
    h
}


pub struct DynamicHash 
{
    nbucket: u32,
    nchain: u32,
    bucket: Vec<u32>,
    chain: Vec<u32>,
}

impl DynamicHash
{
    pub fn new() -> Self {
        DynamicHash {
            nbucket: 0,
            nchain: 0,
            bucket: vec![],
            chain: vec![],
        }
    }

    pub fn flush(&mut self, syms: &Vec<Sym>, dynstr: &Vec<u8>) {
        // number of symbols (nchain)
        let nsyms = syms.len();
        let nsyms_u32 = nsyms as u32;

        let nbuckets = if nsyms <= 1 {
            1usize
        } else {
            Self::next_prime(nsyms)
        } as u32;

        self.nbucket = nbuckets;
        self.nchain = nsyms_u32;
        self.bucket = vec![0u32; nbuckets as usize];
        self.chain = vec![0u32; nsyms]; // chain length equals symbol count

        // helper to read NUL-terminated name from dymstr safely
        fn read_name(dymstr: &[u8], offset: usize) -> &[u8] {
            if offset >= dymstr.len() {
                &[]
            } else {
                let slice = &dymstr[offset..];
                match slice.iter().position(|&b| b == 0) {
                    Some(len) => &slice[..len],
                    None => slice, // no terminating NUL, take rest
                }
            }
        }

        // Insert symbols into buckets. Start from index 1 (STN_UNDEF = 0 is reserved).
        for i in 1..nsyms {
            let sym = &syms[i];
            let name_off = sym.st_name as usize;
            let name = read_name(&dynstr, name_off);
            let h = elf_hash(name);
            let bi = (h % nbuckets) as usize;

            let idx = i as u32;
            // chain[idx] = bucket[bi];
            self.chain[idx as usize] = self.bucket[bi];
            // bucket[bi] = idx;
            self.bucket[bi] = idx;
        }
    }

    fn is_prime(n: usize) -> bool {
        if n < 2 {
            return false;
        }
        if n % 2 == 0 {
            return n == 2;
        }
        let mut i = 3usize;
        while i * i <= n {
            if n % i == 0 {
                return false;
            }
            i += 2;
        }
        true
    }

    /// Return the smallest prime >= n (n >= 0).
    fn next_prime(mut n: usize) -> usize {
        if n <= 2 {
            return 2;
        }
        if n % 2 == 0 {
            n += 1;
        }
        while !Self::is_prime(n) {
            n += 2;
        }
        n
    }
}

impl Flatten for DynamicHash {
    fn flatten(&self) -> Vec<u8> {
        let mut flat: Vec<u8> = Vec::new();

        flat.append(&mut unsafe { plain::as_bytes(&self.nbucket) }.to_vec());
        flat.append(&mut unsafe { plain::as_bytes(&self.nchain) }.to_vec());
        flat.append(&mut self.bucket.as_slice().flatten());
        flat.append(&mut self.chain.as_slice().flatten());

        flat
    }
}

#[derive(Clone, Debug)]
pub struct SymbolTableEntry {
    pub sym_name: Option<String>,
    pub sym_type: u8,
    pub sym_bind: u8,

    pub sym_visibility: u8,
    pub sym_ndx: u16,
    pub sym_value: u64,
    pub sym_size: u64,
}

impl Sym
{
    pub fn as_entry(&self, dynstr: &[u8]) -> SymbolTableEntry {
        let mut name: Option<String> = None;

        if self.st_name != 0
        {
            let len = dynstr.strlen(self.st_name as usize);
            let bytes = dynstr[self.st_name as usize..self.st_name as usize + len].to_vec();
            let cstr = CString::new(bytes).unwrap_or_default();
            name = cstr.into_string().ok();
        }

        SymbolTableEntry {
            sym_name: name,
            sym_type: self.st_info & 0b1111,
            sym_bind: (self.st_info >> 4) & 0b1111,
            sym_visibility: self.st_other,
            sym_ndx: self.st_shndx,
            sym_value: self.st_value,
            sym_size: self.st_size
        }
    }

    pub fn as_entry_gtab(&self, dynstr: &goblin::strtab::Strtab) -> SymbolTableEntry {
        let mut name: Option<String> = None;

        if let Some(str) = dynstr.get_at(self.st_name as usize)
        {
            name = Some(str.to_string());
        }

        SymbolTableEntry {
            sym_name: name,
            sym_type: self.st_info & 0b1111,
            sym_bind: (self.st_info >> 4) & 0b1111,
            sym_visibility: self.st_other,
            sym_ndx: self.st_shndx,
            sym_value: self.st_value,
            sym_size: self.st_size
        }
    }
}

pub trait HashConverter
{
    fn as_hash_table(&self) -> HashMap<String, SymbolTableEntry>;
}

impl<T> HashConverter for T
where 
    T: AsRef<[SymbolTableEntry]>
{
    fn as_hash_table(&self) -> HashMap<String, SymbolTableEntry>
    {
        let mut h = HashMap::<String, SymbolTableEntry>::new();

        for i in self.as_ref()
        {
            if let Some(name) = &i.sym_name {
                h.insert(name.clone(), i.clone());
            }
        }

        h
    }
}

#[repr(C)]
struct LinkMap {
    l_addr: usize,
    l_name: *mut c_char, // The absolute path is stored here
    l_ld: *mut c_void,
    l_next: *mut LinkMap,
    l_prev: *mut LinkMap,
}

pub fn get_shared_object_path(lib_name: &str) -> Option<String>
{
    let lib_c_str = CString::new(lib_name).ok()?;

    let handle = unsafe {
        dlopen(lib_c_str.as_ptr(), RTLD_LAZY)
    };

    let path_result = unsafe {
        let mut link_map_ptr: *mut LinkMap = ptr::null_mut();

        let result = libc::dlinfo(
            handle,
            libc::RTLD_DI_LINKMAP,
            &mut link_map_ptr as *mut _ as *mut c_void,
        );

        if result == 0 && !link_map_ptr.is_null() {
            let l_name = (*link_map_ptr).l_name;
            if !l_name.is_null() {
                let c_str = CStr::from_ptr(l_name);
                Some(c_str.to_string_lossy().into_owned())
            } else {
                None
            }
        } else {
            None
        }
    };

    unsafe {
        let _ = dlclose(handle);
    }

    path_result
}

pub const SHT_RELR: u32 = 19; 