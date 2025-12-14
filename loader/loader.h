
#pragma once
#include <elf.h>

#define _in
#define _out

uint64_t do_load(
    _in const Elf64_Ehdr* ehdr,
    _in const Elf64_Phdr* phdr,
    _out Elf64_Dyn **dynamic
    );

struct DtHashDummy {
    uint32_t nbucket;
    uint32_t nchain;
};

typedef void* JumpSlot;