#ifndef HASHER_MD5_H
#define HASHER_MD5_H

#include <cstdint>

#include "hasher.h"

namespace myhash {
    class md5_hasher : public hasher {
    private:
    public:
        int hash(const uint8_t *src, size_t src_len, uint8_t *buf);
    };
};

#endif