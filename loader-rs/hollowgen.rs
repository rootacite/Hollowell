use std::collections::HashMap;
use std::ffi::CString;
use goblin::elf::header::{EM_X86_64, ET_DYN};
use goblin::elf::program_header::{PF_R, PF_W, PT_DYNAMIC, PT_INTERP, PT_LOAD, PT_PHDR};
use crate::elfdef;
use std::mem::size_of;
use std::str::FromStr;
use goblin::elf32::dynamic::DT_NEEDED;
use goblin::elf::dynamic::{DT_HASH, DT_NULL, DT_RELA, DT_RELAENT, DT_RELASZ, DT_STRSZ, DT_STRTAB, DT_SYMENT, DT_SYMTAB};
use crate::auxiliary::Flatten;
type Bytes = Vec<u8>;

#[allow(unused)]
const SUCC: &str = "\x1b[32m[+]\x1b[0m";
#[allow(unused)]
const FAIL: &str = "\x1b[31m[-]\x1b[0m";
#[allow(unused)]
const ALER: &str = "\x1b[31m[!]\x1b[0m";
#[allow(unused)]
const INFO: &str = "\x1b[34m[*]\x1b[0m";

pub struct HollowGenerator {
    ehdr: elfdef::Header,
    phdr: Vec<elfdef::ProgramHeader>,
    dynamic: Vec<elfdef::Dyn>,
    interp: Option<CString>,
    dynstr: Bytes,
    rela: Vec<(elfdef::Rela, u32)>,
    syms: Vec<elfdef::Sym>,
    hash: elfdef::DynamicHash,
    segments: Vec<(Bytes, usize, u32, u32)>,
    entry: (u64, u32),
    building_hash: HashMap<String, u32>,
}

impl HollowGenerator {
    fn align_upwards(value: u64) -> u64
    {
        if value & 0xfff == 0 {
            value
        } else {
            (value + 0x1000) & (!0xfff)
        }
    }

    pub fn new_x86_64() -> Self
    {
        let ehdr = elfdef::Header {
            e_ident: [0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            e_type: ET_DYN,
            e_machine: EM_X86_64,
            e_version: 1,
            e_entry: 0, // set later
            e_phoff: 64,
            e_shoff: 0, // not used
            e_flags: 0, // not used
            e_ehsize: 64,
            e_phentsize: 56,
            e_phnum: 0, // set later
            e_shentsize: 64, // not used
            e_shnum: 0, // not used
            e_shstrndx: 0, // not used
        };

        let phdr_phdr = elfdef::ProgramHeader {
            p_type: PT_PHDR,
            p_flags: PF_R | PF_W,
            p_offset: 64,
            p_vaddr: 64,
            p_paddr: 64,
            p_filesz: 0,
            p_memsz: 0,
            p_align: 0x8,
        };

        let phdr_dyn = elfdef::ProgramHeader {
            p_type: PT_DYNAMIC,
            p_flags: PF_R | PF_W,
            p_offset: 0,
            p_vaddr: 0,
            p_paddr: 0,
            p_filesz: 0,
            p_memsz: 0,
            p_align: 0x8,
        };

        let phdr_header_load = elfdef::ProgramHeader {
            p_type: PT_LOAD,
            p_flags: PF_R | PF_W,
            p_offset: 0,
            p_vaddr: 0,
            p_paddr: 0,
            p_filesz: 0,
            p_memsz: 0,
            p_align: 0x1000,
        };

        HollowGenerator {
            ehdr,
            phdr: vec![phdr_phdr, phdr_dyn, phdr_header_load],
            dynamic: vec![],
            interp: None,
            dynstr: vec![0u8],
            rela: vec![],
            syms: vec![elfdef::Sym {
                st_name: 0,
                st_info: 0,
                st_other: 0,
                st_shndx: 0,
                st_value: 0,
                st_size: 0,
            }],
            hash: elfdef::DynamicHash::new(),
            segments: vec![],
            entry: (0, 0),
            building_hash: HashMap::new(),
        }
    }

    pub fn add_interp(&mut self, interp: &str)
    {
        let clean_interp = interp.trim_end_matches('\0');
        let cstr = CString::from_str(clean_interp).unwrap();

        self.interp = Some(cstr);
    }

    pub fn add_dynamic(&mut self, dynamic: elfdef::Dyn)
    {
        self.dynamic.push(dynamic);
    }

    pub fn add_segment(&mut self, segment: Bytes, size: usize, flags: u32, index: u32)
    {
        self.segments.push((segment, size, flags, index));
    }

    pub fn add_dependencies(&mut self, name: &CString)
    {
        let loc = self.dynstr.len();
        self.dynstr.append(&mut name.as_bytes_with_nul().to_vec());

        self.add_dynamic(elfdef::Dyn {
            d_tag: DT_NEEDED,
            d_val: loc as u64,
        });
    }

    #[allow(unused)]
    pub fn add_sym(&mut self, mut sym: elfdef::Sym, name: &CString)
    {
        let loc = self.dynstr.len();
        self.building_hash.insert(name.to_str().unwrap().to_string(), self.syms.len() as u32);

        self.dynstr.append(&mut name.as_bytes_with_nul().to_vec());

        sym.st_name = loc as u32;

        self.syms.push(sym);
    }

    #[allow(unused)]
    pub fn add_rela(&mut self, refer_segment: u32, offset: u64, symbol_info: Option<&str>, type_info: u32, addend: u32)
    {
        let mut symbol_index: u64 = 0;

        if let Some(symbol_info) = symbol_info {
            symbol_index = self.building_hash[&symbol_info.to_string()] as u64;
        }

        self.rela.push((elfdef::Rela {
            r_offset: offset,
            r_info: symbol_index << 32 | type_info as u64,
            r_addend: addend as u64,
        }, refer_segment));
    }

    pub fn set_entry(&mut self, offset: u64, refer_segment: u32)
    {
        self.entry = (offset, refer_segment);
    }

    pub fn build(mut self) -> Vec<u8>
    {
        let mut tobe_written = HashMap::<u64, Bytes>::new();
        let dyn_addr;
        let mut current = 64u64; // End of ehdr, start of phdr
        println!("{INFO} Header is at {:#0x}", 0);
        println!("{INFO} Program Header is at {:#0x}", 64);

        // 3 => A PT_PHDR, A PT_DYNAMIC, A PT_LOAD (Header cover)
        let mut phnum = 3 + self.segments.len();
        if self.interp.is_some() {
            phnum += 1;
        }

        let phsize = self.ehdr.e_phentsize as u64 * phnum as u64;
        self.ehdr.e_phnum = phnum as u16;
        self.phdr[0].p_filesz = phsize;
        self.phdr[0].p_memsz = phsize;

        current += phsize; // End of phdr, start of dyn

        // custom dynamic + DT_NULL + RELA related (3) + HASH + SYMTAM(2) + STRTAB(2)
        let dyn_size = (self.dynamic.len() as u64 + 1 + 4 + 1 + 2 + 2) * size_of::<elfdef::Dyn>() as u64;

        println!("{INFO} Dynamic Segment is at {:#0x}", current);
        dyn_addr = current;
        self.phdr[1].p_offset = current;
        self.phdr[1].p_vaddr = current;
        self.phdr[1].p_paddr = current;
        self.phdr[1].p_filesz = dyn_size;
        self.phdr[1].p_memsz = dyn_size;
        current += dyn_size; // End of dyn, start of interp

        if let Some(interp) = self.interp {
            println!("{INFO} Interp String is at {:#0x}", current);
            let interp_bytes = interp.as_bytes_with_nul().to_vec();
            self.phdr.push(elfdef::ProgramHeader {
                p_type: PT_INTERP,
                p_flags: PF_R | PF_W,
                p_offset: current,
                p_vaddr: current,
                p_paddr: current,
                p_filesz: interp_bytes.len() as u64,
                p_memsz: interp_bytes.len() as u64,
                p_align: 0x1,
            });
            tobe_written.insert(current, interp_bytes.clone());
            current += interp_bytes.len() as u64; // End of interp, start of rela
        }


        self.dynamic.push(elfdef::Dyn {
            d_tag: DT_RELAENT,
            d_val: 24,
        });

        self.dynamic.push(elfdef::Dyn {
            d_tag: DT_RELASZ,
            d_val: 24 * self.rela.len() as u64,
        });

        self.dynamic.push(elfdef::Dyn {
            d_tag: DT_RELA,
            d_val: current,
        });

        println!("{INFO} Rela table is at {:#0x}", current);
        let rela_addr = current;
        current += 24 * self.rela.len() as u64; // End of rela, start of dynsym

        self.dynamic.push(elfdef::Dyn {
            d_tag: DT_SYMENT,
            d_val: 24,
        });

        self.dynamic.push(elfdef::Dyn {
            d_tag: DT_SYMTAB,
            d_val: current,
        });

        println!("{INFO} Symbol table is at {:#0x}", current);
        tobe_written.insert(current, self.syms.as_slice().flatten());
        current += 24 * self.syms.len() as u64;

        self.dynamic.push(elfdef::Dyn {
            d_tag: DT_STRTAB,
            d_val: current,
        });
        self.dynamic.push(elfdef::Dyn {
            d_tag: DT_STRSZ,
            d_val: self.dynstr.len() as u64,
        });

        println!("{INFO} Dynamic String table is at {:#0x}", current);
        tobe_written.insert(current, self.dynstr.clone());
        current += self.dynstr.len() as u64; // End of dynstr, start of custom segments

        self.hash.flush(&self.syms, &self.dynstr);

        self.dynamic.push(elfdef::Dyn {
            d_tag: DT_HASH,
            d_val: current,
        });

        println!("{INFO} Hash table is at {:#0x}", current);
        let hash_table_bytes = self.hash.flatten();
        tobe_written.insert(current, hash_table_bytes.clone());
        current += hash_table_bytes.len() as u64;

        self.dynamic.push(elfdef::Dyn {
            d_tag: DT_NULL,
            d_val: 0,
        });
        tobe_written.insert(dyn_addr, self.dynamic.as_slice().flatten());

        self.phdr[2].p_filesz = current;
        self.phdr[2].p_memsz = current;

        current = Self::align_upwards(current);
        let mut fp = current;

        for (bytes, memsz, flags, index) in self.segments.iter()
        {
            for (rela, refer) in &mut self.rela
            {
                if *refer == *index
                {
                    rela.r_offset += current;
                }
            }
            
            if *index == self.entry.1 {
                self.ehdr.e_entry = self.entry.0 + current;
            }

            self.phdr.push(elfdef::ProgramHeader {
                p_type: PT_LOAD,
                p_flags: *flags,
                p_offset: current,
                p_vaddr: current,
                p_paddr: current,
                p_filesz: bytes.len() as u64,
                p_memsz: *memsz as u64,
                p_align: 0x1000,
            });

            tobe_written.insert(current, bytes.clone());
            current += *memsz as u64;
            fp += bytes.len() as u64;
            current = Self::align_upwards(current);
            fp = Self::align_upwards(fp);
        }
        
        tobe_written.insert(0, unsafe { plain::as_bytes(&self.ehdr).to_vec() });
        tobe_written.insert(64u64, self.phdr.as_slice().flatten());
        tobe_written.insert(rela_addr, self.rela.iter().map(|x| x.0).collect::<Vec<elfdef::Rela>>().as_slice().flatten());

        let mut r = vec![0u8; fp as usize];

        for block in tobe_written
        {
            let addr = block.0;
            let bytes = &block.1;

            r[addr as usize..addr as usize + bytes.len()].copy_from_slice(bytes);
        }

        r
    }
}