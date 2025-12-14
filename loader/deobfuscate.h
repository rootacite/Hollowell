
#pragma once

#include <stddef.h>
#include <stdint.h>
#include "loader.h"

#define CHUNK_SIZE 16384

/**
 *
 * @param name chunk name
 * @param ppData output pointer to data, needs to free
 * @param seed the deobfuscate seed, set to NULL to return raw data
 * @return size of data, returns 0 when fail
 */
size_t get_chunk_by_name(_in const char *name, _out uint8_t **ppData, _in const uint8_t *seed);


/**
 *
 * @param vdata chunk vdata
 * @param ppData output pointer to data, needs to free
 * @param seed the deobfuscate seed, set to NULL to return raw data
 * @return size of data, returns 0 when fail
 */
size_t get_chunk_by_vdata(_in uint64_t vdata, _out uint8_t **ppData, _in const uint8_t *seed);