#include <iostream>
#include <cstdlib>
#include <cstring>
#include <cstdio>

#include "md5.h"

using namespace myhash;

static const uint32_t k[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

static const uint32_t r[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

static inline void crypto_uint32_to_4_bytes(uint32_t val, uint8_t *bytes)
{
    bytes[0] = (uint8_t) val;
    bytes[1] = (uint8_t) (val >> 8);
    bytes[2] = (uint8_t) (val >> 16);
    bytes[3] = (uint8_t) (val >> 24);
}

static inline uint32_t crypto_4_bytes_to_uint32(const uint8_t *bytes)
{
    return (uint32_t) bytes[0]
        | ((uint32_t) bytes[1] << 8)
        | ((uint32_t) bytes[2] << 16)
        | ((uint32_t) bytes[3] << 24);
}

int md5_hasher::hash(const uint8_t *src, size_t src_len, uint8_t *buf)
{
    size_t new_len, offset;
    uint8_t *new_src;
    uint32_t hash_val[4] = {
        0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
    };

    /* make (len + 64) % 512 == 0 */
    for (new_len = src_len; new_len % (512 / 8) != (448 / 8); new_len ++) {
        // do nothing;
    }

    /* integer overflow checking */
    if (new_len < src_len || (new_len + 8) < new_len) {
        return -EFAULT;
    }

    new_src = new uint8_t[new_len + 8];
    if (new_src == NULL) {
        return -ENOMEM;
    }

    memcpy(new_src, src, src_len);
    new_src[src_len] = 0x80;    /* '1' bit */
    for (offset = src_len + 1; src_len < new_len; src_len++) {
        new_src[offset] = 0;    /* '0' bit */
    }

    /* 'len' bits are appended at the end of buffer */
    crypto_uint32_to_4_bytes(src_len * 8, &new_src[new_len]);
    crypto_uint32_to_4_bytes(src_len >> 29, &new_src[new_len + 4]);

    /* 512 bits as a block to be hashed */
    for (offset = 0; offset < new_len; offset += (512 / 8)) {
        uint32_t a, b, c, d;
        uint32_t i, f, g, temp;
        uint32_t w[16];

        for (i = 0; i < 16; i++) {
            w[i] = crypto_4_bytes_to_uint32(&new_src[offset + i * 4]);
        }

        a = hash_val[0];
        b = hash_val[1];
        c = hash_val[2];
        d = hash_val[3];

        for (i = 0; i < 64; i++) {
            if (i < 16) {
                f = (b & c) | ((~b) & d);
                g = i;
            } else if (i < 32) {
                f = (d & b) | ((~d) & c);
                g = (5 * i + 1) % 16;
            } else if (i < 48) {
                f = b ^ c ^ d;
                g = (3 * i + 5) % 16;
            } else {
                f = c ^ (b | (~d));
                g = (7 * i) % 16;
            }

            temp = d;
            d = c;
            c = b;
            b = LEFTROTATE((a + f + k[i] + w[g]), r[i]) + b;
            a = temp;
        }

        hash_val[0] += a;
        hash_val[1] += b;
        hash_val[2] += c;
        hash_val[3] += d;
    }

    /* copy result back to caller */
    crypto_uint32_to_4_bytes(hash_val[0], &buf[0]);
    crypto_uint32_to_4_bytes(hash_val[1], &buf[4]);
    crypto_uint32_to_4_bytes(hash_val[2], &buf[8]);
    crypto_uint32_to_4_bytes(hash_val[3], &buf[12]);

    delete new_src;

    return 0;
}
