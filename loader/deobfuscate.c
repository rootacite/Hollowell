
#include "deobfuscate.h"

#include <stdlib.h>
#include <string.h>
#include <zlib.h>

// ................Embedded..................
struct ChunkInfo {
    unsigned char *data;
    unsigned long size;
    char* name;
    unsigned long vdata;
};

typedef struct ChunkInfo ChunkInfo_t;
typedef int(*chunk_callback)(const ChunkInfo_t*, void*);

extern int iter_chunks(chunk_callback cb, void*);

struct cb_io {
    char* name;
    uint64_t vdata;
    const unsigned char *addr;
    uint64_t size;
};
// ............................................


static int cb_find_vdata(const ChunkInfo_t *ci, void *data) {
    struct cb_io *r = data;

    if (ci->vdata == r->vdata) {
        r->addr = ci->data;
        r->size = ci->size;
        return 0;
    }

    return 1;
}

static int cb_find_name(const ChunkInfo_t *ci, void *data) {
    struct cb_io *r = data;

    if (strcmp(ci->name, r->name) == 0) {
        r->addr = ci->data;
        r->size = ci->size;
        return 0;
    }

    return 1;
}

static void deobfuscate_at(const uint8_t* seed, const uint8_t* deobfuscated, uint8_t* buffer, const size_t size) {
    for (int i = 0; i < size; i++) {
        buffer[i] = deobfuscated[i] ^ seed[i % 32];
    }
}

static size_t decompress_gzip(const uint8_t *compressed_data, const size_t compressed_len, uint8_t **decompressed_data) {
    z_stream strm = {0};

    strm.next_in = (Bytef *)compressed_data;
    strm.avail_in = (uInt)compressed_len;

    if (inflateInit2(&strm, 16 + MAX_WBITS) != Z_OK) {
        return 0;
    }

    size_t out_capacity = compressed_len * 2 + 1024;
    uint8_t *out_ptr = (uint8_t *)malloc(out_capacity);
    if (!out_ptr) {
        inflateEnd(&strm);
        return 0;
    }

    int ret;
    size_t total_out = 0;

    do {
        if (total_out >= out_capacity) {
            size_t new_capacity = out_capacity * 2;
            uint8_t *new_ptr = (uint8_t *)realloc(out_ptr, new_capacity);
            if (!new_ptr) {
                free(out_ptr);
                inflateEnd(&strm);
                return 0;
            }
            out_ptr = new_ptr;
            out_capacity = new_capacity;
        }

        strm.next_out = out_ptr + total_out;
        strm.avail_out = (uInt)(out_capacity - total_out);

        ret = inflate(&strm, Z_NO_FLUSH);

        total_out = strm.total_out;

        if (ret == Z_MEM_ERROR || ret == Z_DATA_ERROR) {
            free(out_ptr);
            inflateEnd(&strm);
            return 0;
        }
    } while (ret != Z_STREAM_END);

    inflateEnd(&strm);

    *decompressed_data = out_ptr;
    return total_out;
}

size_t get_chunk_by_name(_in const char *name, _out uint8_t **ppData, _in const uint8_t *seed) {
    if (!name || !ppData)
        return 0;

    struct cb_io r = { .name = (char*)name, .addr = 0 };
    const int found = iter_chunks(cb_find_name, &r);
    if (!found)
        return 0;

    if (!seed) {
        *ppData = (uint8_t*)r.addr;
        return r.size;
    }

    uint8_t *compressed_buffer = malloc(r.size);
    if (!compressed_buffer)
        return 0;

    deobfuscate_at(seed, r.addr, compressed_buffer, r.size);

    uint8_t *buffer = NULL;
    const size_t buffer_size = decompress_gzip(compressed_buffer, r.size, &buffer);
    free(compressed_buffer);

    if (!buffer_size)
        return 0;

    *ppData = buffer;

    return buffer_size;
}

size_t get_chunk_by_vdata(_in uint64_t vdata, _out uint8_t **ppData, _in const uint8_t *seed) {
    if (!ppData)
        return 0;

    struct cb_io r = { .vdata = vdata, .addr = 0 };
    const int found = iter_chunks(cb_find_vdata, &r);
    if (!found)
        return 0;

    if (!seed) {
        *ppData = (uint8_t*)r.addr;
        return r.size;
    }

    uint8_t *compressed_buffer = malloc(r.size);
    if (!compressed_buffer)
        return 0;

    deobfuscate_at(seed, r.addr, compressed_buffer, r.size);

    uint8_t *buffer = NULL;
    const size_t buffer_size = decompress_gzip(compressed_buffer, r.size, &buffer);
    free(compressed_buffer);

    if (!buffer_size)
        return 0;

    *ppData = buffer;

    return buffer_size;
}
