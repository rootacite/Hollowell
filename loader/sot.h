
#pragma once

struct SharedObjectTable {
    void* hDl;
    const char* name;
    struct SharedObjectTable* next;
};

struct LocalSymbolTable {
    uint64_t value;
    const char* name;
    struct LocalSymbolTable* next;
};

void sot_so_add(void *hDl);
void lst_ls_add(uint64_t value, const char *name);
uint64_t sot_symbol_lookup(const char *name);
