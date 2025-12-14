
#include "relocation.h"
#include "sot.h"
#include "loader.h"

#define _GNU_SOURCE

#include <stdio.h>
#include <elf.h>
#include <string.h>
#include <sys/mman.h>
#include <dlfcn.h>

#include <stdlib.h>

static const char* FAIL = "\x1b[31m[-]\x1b[0m";
static const char* INFO = "\x1b[34m[*]\x1b[0m";

static void do_rela_reloc(
    const uint64_t base,
    const Elf64_Rela *rela,
    const size_t count,
    const Elf64_Sym *dynsym,
    const uint64_t dynstr
    )
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

static void do_relr_reloc(
    const uint64_t base,
    const Elf64_Relr *relr,
    const size_t count
    )
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
        } else if (where) {
            uint64_t bitmap = (uint64_t)(entry >> 1);
            for (size_t b = 0; b < bits; ++b) {
                if (bitmap & 1u) {
                    where[b] = where[b] + base;
                }
                bitmap >>= 1;
            }

            where += bits;
        }
    }
}

static void do_parse_dynamic(
    const uint64_t base,
    Elf64_Dyn *dynamic,
    Elf64_Dyn *dynamic_table[]
    )
{
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

static size_t gnu_hash_sym_count(
    const void *gnu_hash_base
    )
{
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

static int do_load_dependencies(
    const Elf64_Dyn *dynamic,
    Elf64_Dyn *dynamic_table[]
) {
    for (int i = 0; dynamic[i].d_tag != DT_NULL; i++) {
        if (dynamic[i].d_tag == DT_NEEDED) {
            const uint64_t p_str = dynamic[i].d_un.d_ptr + dynamic_table[DT_STRTAB]->d_un.d_ptr;
            printf("%s Found DT_NEEDED %s\n", INFO, (char*)p_str);

            void *dh = dlopen((char*)p_str, RTLD_NOW | RTLD_GLOBAL);
            if (dh == NULL) {
                printf("%s Fail to load: %s\n", FAIL, (char*)p_str);
                return 0;
            }

            sot_so_add(dh);
        }
    }

    return 1;
}

static void do_parse_load_symbols(
    const uint64_t image_base,
    Elf64_Dyn *dynamic_table[]
) {
    uint32_t n_sym = 0;
    if (dynamic_table[DT_HASH]) {
        n_sym = ((struct DtHashDummy*)dynamic_table[DT_HASH]->d_un.d_ptr)->nchain;
    } else if (dynamic_table[DT_GNU_HASH_RED]) {
        n_sym = gnu_hash_sym_count((void*)dynamic_table[DT_GNU_HASH_RED]->d_un.d_ptr);
    }

    const Elf64_Sym *dynsym = (const Elf64_Sym*)dynamic_table[DT_SYMTAB]->d_un.d_ptr;
    for (int i = 0; i < n_sym; i++) {
        if (dynsym[i].st_shndx != SHN_UNDEF) {
            lst_ls_add(dynsym[i].st_value + image_base, (const char *)(dynamic_table[DT_STRTAB]->d_un.d_ptr + dynsym[i].st_name));
        }
    }
}

int do_relocate(
    _in const uint64_t image_base,
    _in _out Elf64_Dyn *dynamic,
    _out Elf64_Dyn *dynamic_table[]
) {

    do_parse_dynamic(image_base, dynamic, dynamic_table);
    if (!do_load_dependencies(dynamic, dynamic_table))
        return 0;

    do_parse_load_symbols(image_base, dynamic_table);

    if (dynamic_table[DT_RELA])
        do_rela_reloc(
            image_base,
            (const Elf64_Rela*)dynamic_table[DT_RELA]->d_un.d_ptr,
            dynamic_table[DT_RELASZ]->d_un.d_val / dynamic_table[DT_RELAENT]->d_un.d_val,
            (const Elf64_Sym*)dynamic_table[DT_SYMTAB]->d_un.d_ptr,
            dynamic_table[DT_STRTAB]->d_un.d_ptr);

    if (dynamic_table[DT_RELR])
        do_relr_reloc(
            image_base,
            (const Elf64_Relr*)dynamic_table[DT_RELR]->d_un.d_ptr,
            dynamic_table[DT_RELRSZ]->d_un.d_val / dynamic_table[DT_RELRENT]->d_un.d_val);

    return 1;
}
