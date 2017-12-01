/*
 * SipHash24 Implementation
 *
 * For highlevel documentation of the API see the header file and the docbook
 * comments.
 */

#include <stddef.h>
#include "c-siphash.h"

#define _public_ __attribute__((__visibility__("default")))

static inline uint64_t c_siphash_read_le64(const uint8_t bytes[8]) {
        return  ((uint64_t) bytes[0]) |
               (((uint64_t) bytes[1]) <<  8) |
               (((uint64_t) bytes[2]) << 16) |
               (((uint64_t) bytes[3]) << 24) |
               (((uint64_t) bytes[4]) << 32) |
               (((uint64_t) bytes[5]) << 40) |
               (((uint64_t) bytes[6]) << 48) |
               (((uint64_t) bytes[7]) << 56);
}

static inline uint64_t c_siphash_rotate_left(uint64_t x, uint8_t b) {
        return (x << b) | (x >> (64 - b));
}

static inline void c_siphash_sipround(CSipHash *state) {
        state->v0 += state->v1;
        state->v1 = c_siphash_rotate_left(state->v1, 13);
        state->v1 ^= state->v0;
        state->v0 = c_siphash_rotate_left(state->v0, 32);
        state->v2 += state->v3;
        state->v3 = c_siphash_rotate_left(state->v3, 16);
        state->v3 ^= state->v2;
        state->v0 += state->v3;
        state->v3 = c_siphash_rotate_left(state->v3, 21);
        state->v3 ^= state->v0;
        state->v2 += state->v1;
        state->v1 = c_siphash_rotate_left(state->v1, 17);
        state->v1 ^= state->v2;
        state->v2 = c_siphash_rotate_left(state->v2, 32);
}

_public_ void c_siphash_init(CSipHash *state, const uint8_t seed[16]) {
        uint64_t k0, k1;

        k0 = c_siphash_read_le64(seed);
        k1 = c_siphash_read_le64(seed + 8);

        *state = (CSipHash) {
                /* "somepseudorandomlygeneratedbytes" */
                .v0 = 0x736f6d6570736575ULL ^ k0,
                .v1 = 0x646f72616e646f6dULL ^ k1,
                .v2 = 0x6c7967656e657261ULL ^ k0,
                .v3 = 0x7465646279746573ULL ^ k1,
                .padding = 0,
                .n_bytes = 0,
        };
}

_public_ void c_siphash_append(CSipHash *state, const uint8_t *bytes, size_t n_bytes) {
        const uint8_t *end = bytes + n_bytes;
        size_t left = state->n_bytes & 7;
        uint64_t m;

        /* Update total length */
        state->n_bytes += n_bytes;

        /* If padding exists, fill it out */
        if (left > 0) {
                for ( ; bytes < end && left < 8; bytes ++, left ++)
                        state->padding |= ((uint64_t) *bytes) << (left * 8);

                if (bytes == end && left < 8)
                        /* We did not have enough input to fill out the padding completely */
                        return;

                state->v3 ^= state->padding;
                c_siphash_sipround(state);
                c_siphash_sipround(state);
                state->v0 ^= state->padding;

                state->padding = 0;
        }

        end -= (state->n_bytes % sizeof(uint64_t));

        for ( ; bytes < end; bytes += 8) {
                m = c_siphash_read_le64(bytes);

                state->v3 ^= m;
                c_siphash_sipround(state);
                c_siphash_sipround(state);
                state->v0 ^= m;
        }

        left = state->n_bytes & 7;
        switch (left) {
                case 7:
                        state->padding |= ((uint64_t) bytes[6]) << 48;
                        /* fallthrough */
                case 6:
                        state->padding |= ((uint64_t) bytes[5]) << 40;
                        /* fallthrough */
                case 5:
                        state->padding |= ((uint64_t) bytes[4]) << 32;
                        /* fallthrough */
                case 4:
                        state->padding |= ((uint64_t) bytes[3]) << 24;
                        /* fallthrough */
                case 3:
                        state->padding |= ((uint64_t) bytes[2]) << 16;
                        /* fallthrough */
                case 2:
                        state->padding |= ((uint64_t) bytes[1]) <<  8;
                        /* fallthrough */
                case 1:
                        state->padding |= ((uint64_t) bytes[0]);
                        /* fallthrough */
                case 0:
                        break;
        }
}

_public_ uint64_t c_siphash_finalize(CSipHash *state) {
        uint64_t b;

        b = state->padding | (((uint64_t) state->n_bytes) << 56);

        state->v3 ^= b;
        c_siphash_sipround(state);
        c_siphash_sipround(state);
        state->v0 ^= b;

        state->v2 ^= 0xff;

        c_siphash_sipround(state);
        c_siphash_sipround(state);
        c_siphash_sipround(state);
        c_siphash_sipround(state);

        return state->v0 ^ state->v1 ^ state->v2  ^ state->v3;
}
