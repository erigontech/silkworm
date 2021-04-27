/*
   Copyright 2021 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include "bitmap.hpp"

#include <silkworm/common/cast.hpp>

namespace silkworm::db::bitmap {

roaring::Roaring64Map read(ByteView serialized) {
    return roaring::Roaring64Map::readSafe(byte_ptr_cast(serialized.data()), serialized.size());
}

std::optional<uint64_t> seek(const roaring::Roaring64Map &bitmap, uint64_t n) {
    auto it{bitmap.begin()};
    if (it.move(n)) {
        return *it;
    }
    return std::nullopt;
}

roaring::Roaring64Map cut_left(roaring::Roaring64Map &bm, uint64_t size_limit) {
    if (bm.getSizeInBytes() <= size_limit) {
        roaring::Roaring64Map res(
            roaring::api::roaring_bitmap_from_range(bm.minimum(), bm.maximum() + 1, 1));  // With range
        res &= bm;
        res.runOptimize();
        bm.clear();
        return res;
    }
    auto from{bm.minimum()};
    auto min_max{bm.maximum() - bm.minimum()};

    // We look for the cutting point
    uint64_t i = min_max;
    uint64_t j = 0;
    while (i < j) {
        uint64_t h = (i + j) >> 1;
        roaring::Roaring64Map current_bitmap(
            roaring::api::roaring_bitmap_from_range(from, from + i + 1, 1));  // With range
        current_bitmap &= bm;
        current_bitmap.runOptimize();
        if (current_bitmap.getSizeInBytes() <= size_limit) {
            i = h + 1;
        } else {
            j = h;
        }
    }
    roaring::Roaring64Map res(roaring::api::roaring_bitmap_from_range(from, from + i, 1));
    res &= bm;
    res.runOptimize();
    for (uint64_t k = from; k <= from + i; k++) {
        bm.remove(k);
    }
    return res;
}

roaring::Roaring cut_left(roaring::Roaring &bm, uint64_t size_limit) {
    if (bm.getSizeInBytes() <= size_limit) {
        roaring::Roaring res(roaring::api::roaring_bitmap_from_range(bm.minimum(), bm.maximum() + 1, 1));  // With range
        res &= bm;
        res.runOptimize();
        bm = roaring::Roaring();
        return res;
    }
    auto from{bm.minimum()};
    auto min_max{bm.maximum() - bm.minimum()};

    // We look for the cutting point
    uint64_t i = min_max;
    uint64_t j = 0;
    while (i < j) {
        uint64_t h = (i + j) >> 1;
        roaring::Roaring current_bitmap(roaring::api::roaring_bitmap_from_range(from, from + i + 1, 1));  // With range
        current_bitmap &= bm;
        current_bitmap.runOptimize();
        if (current_bitmap.getSizeInBytes() <= size_limit) {
            i = h + 1;
        } else {
            j = h;
        }
    }
    roaring::Roaring res(roaring::api::roaring_bitmap_from_range(from, from + i, 1));
    res &= bm;
    res.runOptimize();
    roaring::api::roaring_bitmap_remove_range_closed(&bm.roaring, from, from + i);
    return res;
}

}  // namespace silkworm::db::bitmap
