// map.rs

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use crate::elf::ExecuteLinkFile;

#[derive(Debug, Clone)]
pub struct ModuleMetadata {
    pub base_address: u64,
    pub short_name: String,
}

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub start_addr: u64,
    pub end_addr: u64,
    pub perms: String,
    pub offset: Option<u64>,
    #[allow(unused)]
    pub dev: Option<String>,
    #[allow(unused)]
    pub inode: Option<u64>,
    pub pathname: Option<String>,
}

impl MemoryRegion {
    pub fn parse(line: &str) -> Option<Self> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            return None;
        }

        let range_part = parts[0];
        let range_parts: Vec<&str> = range_part.split('-').collect();
        if range_parts.len() != 2 {
            return None;
        }
        let start_addr = u64::from_str_radix(range_parts[0], 16).ok()?;
        let end_addr = u64::from_str_radix(range_parts[1], 16).ok()?;

        let perms = parts[1].to_string();

        let offset = parts.get(2).and_then(|s| u64::from_str_radix(s, 16).ok());
        let dev = parts.get(3).map(|s| s.to_string());
        let inode = parts.get(4).and_then(|s| s.parse::<u64>().ok());
        let pathname = parts.get(5).map(|s| s.to_string());

        Some(Self {
            start_addr,
            end_addr,
            perms,
            offset,
            dev,
            inode,
            pathname,
        })
    }

    pub fn is_read_write(&self) -> bool {
        self.perms.starts_with("rw")
    }

    pub fn is_executable(&self) -> bool {
        self.perms.contains('x')
    }
}

#[derive(Debug, Clone)]
pub struct MemoryMap {
    regions: Vec<MemoryRegion>,
    module_cache: HashMap<String, ModuleMetadata>,
}

impl MemoryMap {
    pub fn new(lines: &Vec<&str>) -> Self {
        let regions: Vec<MemoryRegion> = lines
            .iter()
            .filter_map(|line| MemoryRegion::parse(line))
            .collect();

        let mut map = Self {
            regions,
            module_cache: HashMap::new(),
        };

        map.precompute_module_bases();
        map
    }

    fn precompute_module_bases(&mut self) {
        use std::collections::HashMap;

        let mut min_addr_map: HashMap<String, u64> = HashMap::new();
        for r in &self.regions {
            if let Some(ref path) = r.pathname {
                let entry = min_addr_map.entry(path.clone()).or_insert(u64::MAX);
                if r.start_addr < *entry {
                    *entry = r.start_addr;
                }
            }
        }

        for (path, min_addr) in min_addr_map {
            if path.starts_with('[') { continue; }

            let mut base_address = min_addr;

            let mut short_name = Path::new(&path)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or(&path)
                .replace(" (deleted)", "");

            let is_special = path.starts_with("/memfd:") || path.contains("(deleted)");

            if !is_special {
                if let Ok(elf) = ExecuteLinkFile::prase(&path) {
                    if let Ok(loads) = elf.get_loads() {
                        if let Some(first_load) = loads.iter().find(|p| p.is_executable()) {
                            if let Some(target_region) = self.regions.iter().find(|r| {
                                r.pathname.as_ref() == Some(&path) &&
                                    r.offset.unwrap_or(0) == first_load.p_offset
                            }) {
                                base_address = target_region.start_addr.saturating_sub(first_load.p_vaddr);
                            }
                        }
                    }
                }
            } else if path.starts_with("/memfd:") {
                if let Some(sub_name) = short_name.split(':').last() {
                    short_name = format!("memfd:{}", sub_name);
                }
            }

            self.module_cache.insert(path, ModuleMetadata {
                base_address,
                short_name,
            });
        }
    }

    pub fn find_region(&self, addr: u64) -> Option<&MemoryRegion> {
        let idx = self.regions.binary_search_by(|r| {
            if addr < r.start_addr {
                std::cmp::Ordering::Greater
            } else if addr >= r.end_addr {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        }).ok();

        idx.map(|i| &self.regions[i])
    }
    #[allow(unused)]
    pub fn first_rw_segment(&self, module: &str) -> Option<(u64, u64)> {
        self.regions
            .iter()
            .find(|r| r.is_read_write() && r.pathname.as_deref() == Some(module))
            .map(|r| (r.start_addr, r.end_addr))
    }

    #[allow(unused)]
    pub fn first_exec_segment(&self, module: &str) -> Option<(u64, u64)> {
        self.regions
            .iter()
            .find(|r| r.is_executable() && r.pathname.as_deref() == Some(module))
            .map(|r| (r.start_addr, r.end_addr))
    }

    fn same_file<P: AsRef<Path>, Q: AsRef<Path>>(p1: P, p2: Q) -> std::io::Result<bool> {
        let m1 = fs::metadata(p1)?;
        let m2 = fs::metadata(p2)?;

        Ok(m1.dev() == m2.dev() && m1.ino() == m2.ino())
    }

    #[allow(unused)]
    pub fn module_base_address(
        &self,
        module: &str, // Full path of module, like '/usr/lib/libc.so.6'
    ) -> Option<u64> {
        let elf = ExecuteLinkFile::prase(&module).ok()?;
        let loads = elf.get_loads().ok()?;
        let Some(first_load) = loads.iter().find(|p| p.is_executable()) else {
            return None;
        };

        let Some(map_item) = self
            .regions
            .iter()
            .filter(|x| {
                if let Some(pathname) = x.pathname.as_ref()
                {
                    if Self::same_file(pathname, module).unwrap_or(false)
                    {
                        return true;
                    }
                }
                false
            })
            .find(|r| {
                r.offset.unwrap_or(0) == first_load.p_offset && r.is_executable()
            })
        else {
            return None;
        };

        Some(map_item.start_addr - first_load.p_vaddr)
    }

    #[allow(unused)]
    pub fn collect_module(&self, module: &str) -> Vec<MemoryRegion> {
        let r = self
            .regions
            .iter()
            .filter_map(|r| {
                if r.pathname.as_deref() == Some(module) {
                    Some(r.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<MemoryRegion>>();

        r
    }

    pub fn format_address(&self, addr: usize) -> String {
        let addr_u64 = addr as u64;

        if let Some(region) = self.find_region(addr_u64) {
            if let Some(ref path) = region.pathname {
                if let Some(meta) = self.module_cache.get(path) {
                    let offset = addr_u64 as i128 - meta.base_address as i128;
                    return self.format_with_offset(&meta.short_name, offset);
                }

                let name = Path::new(path).file_name().and_then(|s| s.to_str()).unwrap_or(path);
                let offset = addr_u64 - region.start_addr;
                return format!("{}+0x{:x}", name, offset);
            }
        }

        self.find_nearest_module(addr_u64)
            .unwrap_or_else(|| format!("0x{:x}", addr))
    }

    #[inline]
    fn format_with_offset(&self, name: &str, offset: i128) -> String {
        if offset >= 0 {
            format!("{}+0x{:x}", name, offset as u64)
        } else {
            format!("{}-0x{:x}", name, (-offset) as u64)
        }
    }

    fn find_nearest_module(&self, addr: u64) -> Option<String> {
        self.module_cache.values()
            .map(|meta| {
                let dist = (addr as i128 - meta.base_address as i128).abs();
                (dist, meta)
            })
            .min_by_key(|t| t.0)
            .map(|(_, meta)| {
                let offset = addr as i128 - meta.base_address as i128;
                self.format_with_offset(&meta.short_name, offset)
            })
    }
}
