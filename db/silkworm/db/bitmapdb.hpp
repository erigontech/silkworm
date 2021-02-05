#include "roaring64map.hh"
#include <optional>

namespace silkworm::bitmapdb{
// Return value in bitmap that is higher than cap
std::optional<uint64_t> seek_in_bitmap(roaring::Roaring64Map &bitmap, uint64_t cap);
};
