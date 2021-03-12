/*
   Copyright 2020-2021 The Silkworm Authors

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

#include <vector>

#include <catch2/catch.hpp>

#include "access_layer.hpp"

namespace silkworm::db::bitmap {
TEST_CASE("cut_left") {
    roaring::Roaring64Map bitmap(roaring::api::roaring_bitmap_from_range(0, 100000, 1));
    roaring::Roaring64Map expected(roaring::api::roaring_bitmap_from_range(0, 100000, 1));
    roaring::Roaring64Map actual;
    std::vector<roaring::Roaring64Map> bitmap_chunks;
    while (bitmap.cardinality() != 0) {
        bitmap_chunks.push_back(cut_left(bitmap, kBitmapChunkLimit));
    }
    for (const auto &chunk : bitmap_chunks) {
        actual |= chunk;
    }
    CHECK(actual == expected);
}
}  // namespace silkworm::db::bitmap
