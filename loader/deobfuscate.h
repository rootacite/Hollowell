
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <zlib.h>

#define CHUNK_SIZE 16384

void deobfuscate_at(const uint8_t* seed, const uint8_t* deobfuscated, uint8_t* buffer, size_t size);
size_t decompress_gzip(const uint8_t *compressed_data, size_t compressed_len, uint8_t **decompressed_data);