/*
   Copyright 2022 The Silkworm Authors

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

namespace silkworm::db::bitmap {

static void cut_everything(roaring::Roaring& bm, uint64_t limit) {
    while (bm.cardinality() > 0) {
        const auto original{bm};
        const auto left{cut_left(bm, limit)};

        CHECK((left & bm).isEmpty());
        CHECK((left | bm) == original);

        const auto left_size{left.getSizeInBytes()};
        CHECK(left_size <= limit);
        if (bm.isEmpty()) {
            CHECK(left_size > 0);
        } else {
            CHECK(left_size > limit - 256);
        }
    }
}

TEST_CASE("Roaring Bitmaps") {
    SECTION("Operator -=") {
        // Building from ranges implies [a,b)
        auto minuend_bitmap{roaring::Roaring64Map(roaring::api::roaring_bitmap_from_range(1, 101, 1))};
        auto subtrahend_bitmap{roaring::Roaring64Map(roaring::api::roaring_bitmap_from_range(1, 25, 1))};
        minuend_bitmap -= subtrahend_bitmap;
        REQUIRE(minuend_bitmap.minimum() == 25);
        REQUIRE(minuend_bitmap.cardinality() == 76);

        minuend_bitmap = roaring::Roaring64Map(roaring::api::roaring_bitmap_from_range(1, 101, 1));
        subtrahend_bitmap = roaring::Roaring64Map(roaring::api::roaring_bitmap_from_range(1, 110, 1));
        minuend_bitmap -= subtrahend_bitmap;
        REQUIRE(minuend_bitmap.isEmpty());
    }

    SECTION("To/From Bytes") {
        auto original_bitmap{roaring::Roaring64Map(roaring::api::roaring_bitmap_from_range(1, 101, 1))};
        Bytes bitmap_data{db::bitmap::to_bytes(original_bitmap)};
        auto loaded_bitmap{db::bitmap::parse(bitmap_data)};
        REQUIRE(original_bitmap == loaded_bitmap);
        original_bitmap.clear();
        REQUIRE(db::bitmap::to_bytes(original_bitmap).empty());
    }

    SECTION("cut_left1") {
        roaring::Roaring64Map bitmap(roaring::api::roaring_bitmap_from_range(0, 100000, 1));
        roaring::Roaring64Map expected(roaring::api::roaring_bitmap_from_range(0, 100000, 1));
        roaring::Roaring64Map actual;
        std::vector<roaring::Roaring64Map> bitmap_chunks;
        while (bitmap.cardinality() != 0) {
            bitmap_chunks.push_back(cut_left(bitmap, kBitmapChunkLimit));
        }
        for (const auto& chunk : bitmap_chunks) {
            actual |= chunk;
        }
        CHECK(actual == expected);
    }

    SECTION("cut_left2") {
        roaring::Roaring bm;
        for (uint64_t j{0}; j < 10'000; j += 20) {
            bm.addRange(j, j + 10);
        }

        SECTION("limit=1024") { cut_everything(bm, 1024); }
        SECTION("limit=2048") { cut_everything(bm, 2048); }
    }

    SECTION("cut_left3") {
        roaring::Roaring bm;
        bm.add(1);

        const uint64_t limit{2048};
        const auto lft{cut_left(bm, limit)};

        CHECK(lft.getSizeInBytes() > 0);
        CHECK(lft.cardinality() == 1);
        CHECK(bm.cardinality() == 0);
    }
}

}  // namespace silkworm::db::bitmap
