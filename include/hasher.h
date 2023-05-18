#ifndef HASHER_HASHER_H
#define HASHER_HASHER_H

#include <cstdint>

namespace myhash {
    class hasher {
    private:
    public:
        virtual int hash(const uint8_t *src, size_t src_len, uint8_t *buf) = 0;
    };
};

#endif