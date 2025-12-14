
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <link.h>

#include <stdlib.h>

#include "loader.h"
#include "deobfuscate.h"
#include "relocation.h"

static const char* SUCC = "\x1b[32m[+]\x1b[0m";
static const char* INFO = "\x1b[34m[*]\x1b[0m";

static uint8_t *seed = NULL;

static void do_parse_auxv(Elf64_auxv_t* auxv, Elf64_auxv_t* auxv_table[]) {
    printf("%s Current pid = %d\n", INFO, getpid());
    for (int i = 0; auxv[i].a_type != AT_NULL; i++) {
        auxv_table[auxv[i].a_type] = &auxv[i];
    }
}

static int do_load_segment(
    void* base,
    const Elf64_Phdr* p
    )
{
    if (p->p_type != PT_LOAD)
        return 0;

    const uint64_t load_base = (uint64_t)base + p->p_vaddr;
    uint8_t *buffer = NULL;
    const size_t buffer_size = get_chunk_by_vdata(p->p_vaddr, &buffer, seed);
    if (!buffer || !buffer_size)
        return 1;

    memcpy((void*)load_base, buffer, buffer_size);
    free(buffer);

    printf("%s Segment(vaddr = %lx, memsz = %lx) loaded to %lx\n", SUCC, p->p_vaddr, p->p_memsz, load_base);

    const uint64_t load_page = load_base & ~0xfffULL;
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

uint64_t do_load(
    _in const Elf64_Ehdr* ehdr,
    _in const Elf64_Phdr* phdr,
    _out Elf64_Dyn **dynamic
    ) {
    uint64_t image_size = 0;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        const Elf64_Phdr* p = &phdr[i];

        if (p->p_type == PT_LOAD && p->p_vaddr + p->p_memsz >= image_size)
            image_size = p->p_vaddr + p->p_memsz;
    }

    image_size += 0x1000ULL;
    image_size &= ~0xfffULL;
    printf("%s Image size determined to %lx\n", INFO, image_size);

    void *image_base = mmap(NULL, image_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    printf("%s Image base address determined to %p\n", INFO, image_base);

    *dynamic = image_base;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        const Elf64_Phdr* p = &phdr[i];
        if (p->p_type == PT_DYNAMIC) {
            *dynamic = (Elf64_Dyn*)((uint64_t)*dynamic + p->p_vaddr);
            printf("%s Dynamic address determined to %lx\n", INFO, (uint64_t)*dynamic);
            continue; // PT_DYNAMIC is covered by a PT_LOAD, so continue here.
        }
        if (do_load_segment(image_base, p))
            return 0;
    }

    return (uint64_t)image_base;
}

JumpSlot loader(Elf64_auxv_t* auxv) {
    Elf64_auxv_t* auxv_table[100] = { NULL };
    do_parse_auxv(auxv, auxv_table);

    uint64_t sz = get_chunk_by_name("seed", &seed, NULL);
    if (!seed || !sz)
        return NULL;

    // Origin Ehdr
    Elf64_Ehdr* ehdr = NULL;
    sz = get_chunk_by_name("ehdr", (uint8_t**)&ehdr, seed);
    if (!ehdr || !sz)
        return NULL;

    // Origin Phdr
    Elf64_Phdr* phdr = NULL;
    sz = get_chunk_by_name("phdr", (uint8_t**)&phdr, seed);
    if (!phdr || !sz)
        return NULL;

    // Load segments
    Elf64_Dyn *dynamic = NULL;
    Elf64_Dyn *dynamic_table[50] = { NULL };
    const uint64_t inner_base = do_load(ehdr, phdr, &dynamic);
    if (!inner_base)
        return NULL;

    if (!do_relocate(inner_base, dynamic, dynamic_table))
        return NULL;
    
    const uint64_t oep = ehdr->e_entry + inner_base;

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

    for (struct link_map *lm = _r_debug.r_map; lm != NULL; lm = lm->l_next) {
        if (lm->l_name == NULL || lm->l_name[0] == '\0') {
            lm->l_addr = inner_base;
            lm->l_ld = dynamic;

            // link_map + 0x40 is ElfW(Dyn) *l_info, but this is internal to the dynamic linker.
            // Considering a cleaner approach.

            // Pseudocode code of __libc_start_main:
            // v12 = rtld_global;
            // v13 = rtld_global[20];
            // if ( v13 )
            // {
            //     v19 = environ;
            //     ((void (__fastcall *)(_QWORD, char **, _QWORD, void (*)(void), void (*)(void)))(*rtld_global + *(_QWORD *)(v13 + 8)))(
            //       (unsigned int)argc,
            //       ubp_av,
            //       environ,
            //       init,
            //       fini);
            //     v11 = v19;
            // }

            // __libc_start_main uses _rtld_global_ptr to get the main module's link_map,
            // then computes init functions from its data.
            // We must adjust this struct's data

            uint64_t* l_info = (uint64_t*)((uint8_t*)lm + 0x40);
            for (int i = 0; i < 40; i++) { // Iter to 40 to avoid DT_GNU_HASH_RED
                if (dynamic_table[i])
                    l_info[i] = (uint64_t)dynamic_table[i];
            }
        }
    }

    free(ehdr);
    return (void*)oep;
}