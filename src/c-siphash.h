#pragma once

/**
 * Standalone SipHash Implementation in Standard ISO-C11
 *
 * This library provides a SipHash API, that is fully implemented in ISO-C11
 * and has no external dependencies. The library performs no memory allocation,
 * and provides a streaming API where data to be hashed can be appended
 * piecemeal.
 *
 * A streaming-capable hash state is represented by the "CSipHash" structure,
 * which should be initialized with a unique seed before use.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

typedef struct CSipHash CSipHash;

/**
 * struct CSipHash - SipHash state object
 * @v0-@v3:             internal state
 * @padding:            pending bytes that were not a multiple of 8
 * @n_bytes:            number of hashed bytes
 *
 * The state of an inflight hash is represenetd by a CSipHash object. Before
 * hashing, it must be initialized with c_siphash_init(), providing a unique
 * random hash seed. Data is hashed by appending it to the state object, using
 * c_siphash_append(). Finally, the hash is read out by calling
 * c_siphash_finalize().
 *
 * This state object has no allocated resources. It is safe to release its
 * backing memory without any further action.
 */
struct CSipHash {
        uint64_t v0;
        uint64_t v1;
        uint64_t v2;
        uint64_t v3;
        uint64_t padding;
        size_t n_bytes;
};

#define C_SIPHASH_NULL {}

void c_siphash_init(CSipHash *state, const uint8_t seed[16]);
void c_siphash_append(CSipHash *state, const uint8_t *bytes, size_t n_bytes);
uint64_t c_siphash_finalize(CSipHash *state);

#ifdef __cplusplus
}
#endif
