
#define _GNU_SOURCE

#include <stdio.h>
#include <elf.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <dlfcn.h>
#include <link.h>

#define DT_GNU_HASH_RED 49

#include <stdlib.h>

#include "sot.h"
#include "deobfuscate.h"

const char* SUCC = "\x1b[32m[+]\x1b[0m";
const char* FAIL = "\x1b[31m[-]\x1b[0m";
const char* ALER = "\x1b[31m[!]\x1b[0m";
const char* INFO = "\x1b[34m[*]\x1b[0m";

typedef void* JumpSlot;

// ................Embedded..................
struct ChunkInfo {
    unsigned char *data;
    unsigned long size;
    char* name;
    unsigned long vdata;
};

typedef struct ChunkInfo ChunkInfo_t;
typedef int(*chunk_callback)(ChunkInfo_t*, void*);

extern void iter_chunks(chunk_callback cb, void*);

struct cb_io {
    char* name;
    uint64_t vdata;
    const unsigned char *addr;
    uint64_t size;
};
// ............................................

struct DtHashDummy {
    uint32_t nbucket;
    uint32_t nchain;
};

static void do_rela_reloc(uint64_t base, Elf64_Rela *rela, size_t count, Elf64_Sym *dynsym, uint64_t dynstr)
{
    for (int i = 0; i < count ; i++)
    {
        uint32_t sym_index = (rela[i].r_info >> 32) & 0xffffffff;
        const char* sym_name = (const char *)(dynstr + dynsym[sym_index].st_name);
        uint64_t sym_value = 0;
        uint64_t sym_sz = dynsym[sym_index].st_size;

        switch (rela[i].r_info & 0xffffffff)
        {
            case R_X86_64_64:
                sym_value = sot_symbol_lookup(sym_name);
                *(uint64_t*)(rela[i].r_offset + base) = sym_value + rela[i].r_addend;
                break;
            case R_X86_64_GLOB_DAT:
            case R_X86_64_JUMP_SLOT:
                sym_value = sot_symbol_lookup(sym_name);
                *(uint64_t*)(rela[i].r_offset + base) = sym_value;
                break;
            case R_X86_64_COPY:
                sym_value = sot_symbol_lookup(sym_name);
                memcpy((void*)(rela[i].r_offset + base), (void*)sym_value, sym_sz);
                break;
            case R_X86_64_RELATIVE:
                *(uint64_t*)(rela[i].r_offset + base) = base + rela[i].r_addend;
                break;
            default:
                break;
        }
    }
}

static void do_relr_reloc(uint64_t base, Elf64_Relr *relr, size_t count)
{
    const size_t bits = (sizeof(Elf64_Relr) * 8) - 1; /* 63 on ILP64/typical x86_64 */
    uint64_t *where = NULL;

    for (size_t i = 0; i < count; ++i) {
        Elf64_Relr entry = relr[i];

        if ((entry & 1u) == 0) {
            uintptr_t addr = (uintptr_t)base + (uintptr_t)entry;
            where = (uint64_t *)addr;
            *where = *where + base;
            ++where;
        } else {
            uint64_t bitmap = (uint64_t)(entry >> 1);
            for (size_t b = 0; b < bits; ++b) {
                if (where && (bitmap & 1u)) {
                    where[b] = where[b] + base;
                }
                bitmap >>= 1;
            }

            where += bits;
        }
    }
}

static int cb_find_vdata(ChunkInfo_t *ci, void *data) {
    struct cb_io *r = data;

    if (ci->vdata == r->vdata) {
        r->addr = ci->data;
        r->size = ci->size;
        return 0;
    }

    return 1;
}

static int cb_find_name(ChunkInfo_t *ci, void *data) {
    struct cb_io *r = data;

    if (strcmp(ci->name, r->name) == 0) {
        r->addr = ci->data;
        r->size = ci->size;
        return 0;
    }

    return 1;
}

static void do_parse_auxv(Elf64_auxv_t* auxv, Elf64_auxv_t* auxv_table[]) {
    printf("%s Current pid = %d\n", INFO, getpid());
    for (int i = 0; auxv[i].a_type != AT_NULL; i++) {
        auxv_table[auxv[i].a_type] = &auxv[i];
    }
}

static int do_load_segment(void* base, Elf64_Phdr* p) {
    struct cb_io r = { .name = "seed", .addr = 0 };
    if (p->p_type != PT_LOAD)
        return 0;

    iter_chunks(cb_find_name, &r);
    const uint8_t *p_seed = r.addr;

    uint64_t load_base = (uint64_t)base + p->p_vaddr;
    r.vdata = p->p_vaddr;
    iter_chunks(cb_find_vdata, &r);

    // Deobfuscate
    uint8_t *compressed_buffer = malloc(r.size);
    deobfuscate_at(p_seed, r.addr, compressed_buffer, r.size);

    uint8_t *buffer = NULL;
    const size_t buffer_size = decompress_gzip(compressed_buffer, r.size, &buffer);

    if (!buffer_size)
        return 1;
    free(compressed_buffer);

    memcpy((void*)load_base, buffer, buffer_size);
    free(buffer);

    printf("%s Segment(vaddr = %lx, memsz = %lx) loaded to %lx\n", SUCC, p->p_vaddr, p->p_memsz, load_base);

    uint64_t load_page = load_base & ~0xfffULL;
    uint64_t page_size = p->p_memsz + (load_base & 0xfffULL);
    uint8_t prot = 0;
    if (p->p_flags & PF_X)
        prot |= PROT_EXEC;
    if (p->p_flags & PF_W)
        prot |= PROT_WRITE;
    if (p->p_flags & PF_R)
        prot |= PROT_READ;

    page_size += 0x1000ULL;
    page_size &= ~0xfffULL;

    mprotect((void*)load_page, page_size, prot);
    printf("%s Protect of %lu page(s) at %lx adjusted to %d. \n", SUCC, page_size / 0x1000, load_page, prot);

    return 0;
}

static void do_parse_dynamic(uint64_t base, Elf64_Dyn *dynamic, Elf64_Dyn *dynamic_table[]) {
    for (int i = 0; dynamic[i].d_tag != DT_NULL; i++) {
        switch (dynamic[i].d_tag) {
            case DT_PLTGOT:
            case DT_HASH:
            case DT_GNU_HASH:
            case DT_STRTAB:
            case DT_SYMTAB:
            case DT_RELA:
            case DT_RELR:
            case DT_REL:
            case DT_INIT:
            case DT_FINI:
            case DT_JMPREL:
            case DT_VERDEF:
            case DT_VERNEED:
            case DT_VERSYM:
                dynamic[i].d_un.d_ptr += base;
                break;
            default:
                break;
        }

        if (dynamic[i].d_tag >= 50) {
            if (dynamic[i].d_tag == DT_GNU_HASH) {
                dynamic_table[DT_GNU_HASH_RED] = &dynamic[i];
            }
            continue;
        }

        dynamic_table[dynamic[i].d_tag] = &dynamic[i];
    }
}

static size_t gnu_hash_sym_count(const void *gnu_hash_base) {
    if (!gnu_hash_base) return 0;

    const unsigned char *p = gnu_hash_base;
    const uint32_t *u32 = (const uint32_t *)p;

    uint32_t nbucket    = u32[0];
    uint32_t symoffset  = u32[1];
    uint32_t bloom_size = u32[2];

    const unsigned char *after_header = p + 4 * 4 + (size_t)bloom_size * 8;
    const uint32_t *buckets = (const uint32_t *)after_header;
    const uint32_t *chain = buckets + nbucket;

    uint32_t max_index = 0;
    int found_any = 0;

    for (uint32_t i = 0; i < nbucket; ++i) {
        uint32_t idx = buckets[i];
        if (idx == 0) continue;

        uint32_t cur = idx;
        while (1) {
            if (cur < symoffset) {
                break;
            }
            size_t chain_idx = (size_t)(cur - symoffset);
            uint32_t h = chain[chain_idx];
            if (cur > max_index) max_index = cur;
            found_any = 1;
            if (h & 1U) break; /* end of this bucket's chain */
            ++cur;
        }
    }

    if (!found_any) {
        return 0;
    }

    return (size_t)max_index + 1;
}

JumpSlot loader(Elf64_auxv_t* auxv) {
    Elf64_auxv_t* auxv_table[100] = { NULL };
    do_parse_auxv(auxv, auxv_table);

    struct cb_io r = { .name = "seed", .addr = 0 };
    iter_chunks(cb_find_name, &r);
    uint8_t seed[32];
    memcpy(seed, r.addr, 32);

    // Origin Ehdr
    r.name = "ehdr";
    iter_chunks(cb_find_name, &r);
    uint8_t *compressed_ehdr = malloc(r.size);
    deobfuscate_at(seed, r.addr, compressed_ehdr, r.size);

    Elf64_Ehdr* ehdr = NULL;
    if (!decompress_gzip(compressed_ehdr, r.size, (uint8_t**)&ehdr))
        return NULL;
    free(compressed_ehdr);
    // ...

    // Origin Phdr
    r.name = "phdr";
    iter_chunks(cb_find_name, &r);
    uint8_t *compressed_phdr = malloc(r.size);
    deobfuscate_at(seed, r.addr, compressed_phdr, r.size);

    Elf64_Phdr* phdr = NULL;
    if (!decompress_gzip(compressed_phdr, r.size, (uint8_t**)&phdr))
        return NULL;
    free(compressed_phdr);
    // ...

    uint64_t sz_embedded = 0;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        Elf64_Phdr* p = &phdr[i];

        if (p->p_type == PT_LOAD && p->p_vaddr + p->p_memsz >= sz_embedded)
            sz_embedded = p->p_vaddr + p->p_memsz;
    }

    sz_embedded += 0x1000ULL;
    sz_embedded &= ~0xfffULL;
    printf("%s sz_embedded determined to %lx\n", INFO, sz_embedded);

    void *embedded_base = mmap(NULL, sz_embedded, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    printf("%s Embedded base address determined to %p\n", INFO, embedded_base);

    Elf64_Dyn *dynamic = embedded_base;
    Elf64_Dyn *dynamic_table[50] = { NULL };

    for (int i = 0; i < ehdr->e_phnum; i++) {
        Elf64_Phdr* p = &phdr[i];
        if (p->p_type == PT_DYNAMIC) {
            *(uint64_t*)&dynamic += p->p_vaddr;
            printf("%s Dynamic address determined to %lx\n", INFO, (uint64_t)dynamic);
        }
        if (do_load_segment(embedded_base, p))
            return NULL;
    }

    do_parse_dynamic((uint64_t)embedded_base, dynamic, dynamic_table);
    for (int i = 0; dynamic[i].d_tag != DT_NULL; i++) {
        if (dynamic[i].d_tag == DT_NEEDED) {
            uint64_t p_str = dynamic[i].d_un.d_ptr + dynamic_table[DT_STRTAB]->d_un.d_ptr;
            printf("%s Found DT_NEEDED %s\n", INFO, (char*)p_str);

            void *dh = dlopen((char*)p_str, RTLD_NOW | RTLD_GLOBAL);
            if (dh == NULL) {
                __asm("int3");
                continue;
            }
            struct link_map* map;
            if (dlinfo(dh, RTLD_DI_LINKMAP, &map) == 0) {
                printf("%s Shared object \"%s\" loaded to %p \n", SUCC, (char*)p_str, (void*)map->l_addr);
                sot_so_add(dh);
            }
        }
    }

    uint32_t n_sym = 0;
    if (dynamic_table[DT_HASH]) {
        n_sym = ((struct DtHashDummy*)dynamic_table[DT_HASH]->d_un.d_ptr)->nchain;
    } else if (dynamic_table[DT_GNU_HASH_RED]) {
        n_sym = gnu_hash_sym_count((void*)dynamic_table[DT_GNU_HASH_RED]->d_un.d_ptr);
    }

    Elf64_Sym *dynsym = (Elf64_Sym*)dynamic_table[DT_SYMTAB]->d_un.d_ptr;
    for (int i = 0; i < n_sym; i++) {
        if (dynsym[i].st_shndx != SHN_UNDEF) {
            lst_ls_add(dynsym[i].st_value + (uint64_t)embedded_base, (const char *)(dynamic_table[DT_STRTAB]->d_un.d_ptr + dynsym[i].st_name));
        }
    }

    if (dynamic_table[DT_RELA])
        do_rela_reloc(
            (uint64_t)embedded_base,
            (Elf64_Rela*)dynamic_table[DT_RELA]->d_un.d_ptr,
            dynamic_table[DT_RELASZ]->d_un.d_val / dynamic_table[DT_RELAENT]->d_un.d_val,
            (Elf64_Sym*)dynamic_table[DT_SYMTAB]->d_un.d_ptr,
            dynamic_table[DT_STRTAB]->d_un.d_ptr);

    if (dynamic_table[DT_RELR])
        do_relr_reloc(
            (uint64_t)embedded_base,
            (Elf64_Relr*)dynamic_table[DT_RELR]->d_un.d_ptr,
            dynamic_table[DT_RELRSZ]->d_un.d_val / dynamic_table[DT_RELRENT]->d_un.d_val);
    
    uint64_t oep = ehdr->e_entry + (uint64_t)embedded_base;

    if (auxv_table[AT_PHDR])
    {
        auxv_table[AT_PHDR]->a_un.a_val = (uint64_t)phdr;
        auxv_table[AT_PHENT]->a_un.a_val = ehdr->e_phentsize;
        auxv_table[AT_PHNUM]->a_un.a_val = ehdr->e_phnum;
    }

    if (auxv_table[AT_ENTRY])
    {
        auxv_table[AT_ENTRY]->a_un.a_val = oep;
    }

    free(ehdr);

    return (void*)oep;
}
