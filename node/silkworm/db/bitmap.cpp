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

#include <silkworm/common/binary_search.hpp>
#include <silkworm/common/cast.hpp>

namespace silkworm::db::bitmap {

roaring::Roaring64Map read(ByteView serialized) {
    return roaring::Roaring64Map::readSafe(byte_ptr_cast(serialized.data()), serialized.size());
}

std::optional<uint64_t> seek(const roaring::Roaring64Map& bitmap, uint64_t n) {
    auto it{bitmap.begin()};
    if (it.move(n)) {
        return *it;
    }
    return std::nullopt;
}

static void remove_range_impl(roaring::Roaring& bm, uint64_t min, uint64_t max) {
    roaring::api::roaring_bitmap_remove_range(&bm.roaring, min, max);
}

static void remove_range_impl(roaring::Roaring64Map& bm, uint64_t min, uint64_t max) {
    for (uint64_t k = min; k < max; ++k) {
        bm.remove(k);
    }
}

template <typename RoaringMap>
RoaringMap cut_left_impl(RoaringMap& bm, uint64_t size_limit) {
    if (bm.getSizeInBytes() <= size_limit) {
        RoaringMap res = bm;
        res.runOptimize();
        bm = RoaringMap();
        return res;
    }

    const auto from{bm.minimum()};
    const auto min_max{bm.maximum() - bm.minimum()};

    const auto cutting_point{binary_find_if(min_max, [&](size_t i) {
        RoaringMap current_bitmap(roaring::api::roaring_bitmap_from_range(from, from + i + 1, 1));
        current_bitmap &= bm;
        current_bitmap.runOptimize();
        return current_bitmap.getSizeInBytes() > size_limit;
    })};

    // no +1 because binary_find_if returns the element which is just above the threshold - but we need <=
    RoaringMap res(roaring::api::roaring_bitmap_from_range(from, from + cutting_point, 1));
    res &= bm;
    res.runOptimize();
    remove_range_impl(bm, from, from + cutting_point);
    return res;
}

roaring::Roaring cut_left(roaring::Roaring& bm, uint64_t size_limit) { return cut_left_impl(bm, size_limit); }

roaring::Roaring64Map cut_left(roaring::Roaring64Map& bm, uint64_t size_limit) { return cut_left_impl(bm, size_limit); }

}  // namespace silkworm::db::bitmap
