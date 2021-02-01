#include "bitmapdb.hpp"

namespace silkworm::bitmapdb{

std::optional<uint64_t> seek_in_bitmap(roaring::Roaring64Map &bitmap, uint64_t cap) {
    for (auto it = bitmap.begin(); it != bitmap.end(); ++it) {
        if (*it > cap) return *it;
    }
    return std::nullopt;
}

};