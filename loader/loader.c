
#define _GNU_SOURCE

#include <stdio.h>
#include <elf.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <dlfcn.h>
#include <link.h>

#include "sot.h"

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
};
// ............................................

static void do_rela_reloc(uint64_t base, Elf64_Rela *rela, size_t count)
{
    for (int i = 0; i < count ; i++)
    {
        switch (rela[i].r_info & 0xffffffff)
        {
            case R_X86_64_RELATIVE:
                *(uint64_t*)(rela[i].r_offset + base) = base + rela[i].r_addend;
                break;
            default:
                break;
        }
    }
}

static int cb_find_vdata(ChunkInfo_t *ci, void *data) {
    struct cb_io *r = data;

    if (ci->vdata == r->vdata) {
        r->addr = ci->data;
        return 0;
    }

    return 1;
}

static int cb_find_name(ChunkInfo_t *ci, void *data) {
    struct cb_io *r = data;

    if (strcmp(ci->name, r->name) == 0) {
        r->addr = ci->data;
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

static void do_load_segment(void* base, Elf64_Phdr* p) {
    struct cb_io r = { .name = "ehdr", .addr = 0 };
    if (p->p_type != PT_LOAD)
        return;

    uint64_t load_base = (uint64_t)base + p->p_vaddr;
    r.vdata = p->p_vaddr;
    iter_chunks(cb_find_vdata, &r);

    memcpy((void*)load_base, r.addr, p->p_filesz);
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
}

static void do_parse_dynamic(uint64_t base, Elf64_Dyn *dynamic, Elf64_Dyn *dynamic_table[]) {
    for (int i = 0; dynamic[i].d_tag != DT_NULL; i++) {
        if (dynamic[i].d_tag >= 50)
            continue;

        dynamic_table[dynamic[i].d_tag] = &dynamic[i];

        switch (dynamic[i].d_tag) {
            case DT_PLTGOT:
            case DT_HASH:
            case DT_GNU_HASH:
            case DT_STRTAB:
            case DT_SYMTAB:
            case DT_RELA:
            case DT_INIT:
            case DT_FINI:
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
    }
}

JumpSlot loader(Elf64_auxv_t* auxv) {
    Elf64_auxv_t* auxv_table[100];
    do_parse_auxv(auxv, auxv_table);

    struct cb_io r = { .name = "ehdr", .addr = 0 };
    iter_chunks(cb_find_name, &r);
    Elf64_Ehdr* ehdr = (Elf64_Ehdr*)r.addr;

    r.name = "phdr";
    iter_chunks(cb_find_name, &r);
    Elf64_Phdr* phdr = (Elf64_Phdr*)r.addr;

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
    Elf64_Dyn *dynamic_table[50];

    for (int i = 0; i < ehdr->e_phnum; i++) {
        Elf64_Phdr* p = &phdr[i];
        if (p->p_type == PT_DYNAMIC) {
            *(uint64_t*)&dynamic += p->p_vaddr;
            printf("%s Dynamic address determined to %lx\n", INFO, (uint64_t)dynamic);
        }
        do_load_segment(embedded_base, p);
    }

    do_parse_dynamic((uint64_t)embedded_base, dynamic, dynamic_table);
    for (int i = 0; dynamic[i].d_tag != DT_NULL; i++) {
        if (dynamic[i].d_tag == DT_NEEDED) {
            uint64_t p_str = dynamic[i].d_un.d_ptr + dynamic_table[DT_STRTAB]->d_un.d_ptr;
            printf("%s Found DT_NEEDED %s\n", INFO, (char*)p_str);

            void *dh = dlopen("libgssapi_krb5.so.2", RTLD_NOW | RTLD_GLOBAL);
            if (dh == NULL) {
                __asm("int3");
                continue;
            }
            struct link_map* map;
            if (dlinfo(dh, RTLD_DI_LINKMAP, &map) == 0) {
                printf("%s Shared object \"%s\" loaded to %p \n", SUCC, (char*)p_str, (void*)map->l_addr);
            }
        }
    }

    getchar();
    return NULL;
}
