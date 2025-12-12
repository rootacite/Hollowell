
#pragma once

struct SharedObjectTable {
    void* hDl;
    const char* name;
    struct SharedObjectTable* next;
};
