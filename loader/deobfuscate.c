
#include "deobfuscate.h"

#include <stdlib.h>

void deobfuscate_at(const uint8_t* seed, const uint8_t* deobfuscated, uint8_t* buffer, size_t size) {
    for (int i = 0; i < size; i++) {
        buffer[i] = deobfuscated[i] ^ seed[i % 32];
    }
}

size_t decompress_gzip(const uint8_t *compressed_data, size_t compressed_len, uint8_t **decompressed_data) {
    if (!compressed_data || !compressed_len || !decompressed_data) return 0;

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