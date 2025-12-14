
#define _GNU_SOURCE

#include <stdlib.h>
#include <elf.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <link.h>

#include "sot.h"

static struct SharedObjectTable sot_head = { .next = NULL };
static struct LocalSymbolTable  lst_head = { .next = NULL };

static struct SharedObjectTable* sot_get_end() {
    struct SharedObjectTable* sot = &sot_head;

    while (sot->next != NULL) {
        sot = sot->next;
    }

    return sot;
}

static struct LocalSymbolTable* lst_get_end() {
    struct LocalSymbolTable* lst = &lst_head;

    while (lst->next != NULL) {
        lst = lst->next;
    }

    return lst;
}

void sot_so_add(void *hDl) {
    struct SharedObjectTable* sot = malloc(sizeof(struct SharedObjectTable));

    struct link_map* map;
    if (dlinfo(hDl, RTLD_DI_LINKMAP, &map) == 0) {
        sot->name = map->l_name;
        sot->hDl = hDl;
        sot->next = NULL;
    }

    struct SharedObjectTable* end = sot_get_end();
    end->next = sot;
}

void lst_ls_add(uint64_t value, const char *name) {
    struct LocalSymbolTable* lst = malloc(sizeof(struct LocalSymbolTable));

    lst->name = name;
    lst->value = value;
    lst->next = NULL;

    struct LocalSymbolTable* end = lst_get_end();
    end->next = lst;
}

// ReSharper disable once CppDeclaratorNeverUsed
static uint64_t lst_symbol_lookup(const char *name) {
    struct LocalSymbolTable* lst = lst_head.next;

    while (lst != NULL) {
        if (strcmp(lst->name, name) == 0) {
            return lst->value;
        }

        lst = lst->next;
    }

    return 0;
}

uint64_t sot_symbol_lookup(const char *name) {
    // uint64_t sym = lst_symbol_lookup(name);
    // FIXME: If symbol versions are not considered,
    // FIXME: prioritize searching for potentially incorrect symbols in the local symbol table
    // if (sym)
    //     return sym;

    uint64_t sym = 0;
    struct SharedObjectTable* sot = sot_head.next;
    while (sot != NULL) {
        void *ds = dlsym(sot->hDl, name);
        if (ds) {
            sym = (uint64_t)ds;
            return sym;
        }
        sot = sot->next;
    }

    return 0;
}
