
#pragma once
#include "loader.h"

#define DT_GNU_HASH_RED 49

int do_relocate(
    _in uint64_t image_base,
    _in _out Elf64_Dyn *dynamic,
    _out Elf64_Dyn *dynamic_table[]
);