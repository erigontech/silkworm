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

#include <map>
#include <vector>

#include <absl/container/btree_map.h>
#include <catch2/catch.hpp>

#include <silkworm/common/test_context.hpp>
#include <silkworm/etl/collector.hpp>

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
        for (size_t mdbx_page_size{1_Kibi}; mdbx_page_size < 32_Kibi; mdbx_page_size *= 2) {
            static const size_t bitmap_chunk_limit{db::max_value_size_for_leaf_page(mdbx_page_size, 0)};
            roaring::Roaring64Map bitmap(roaring::api::roaring_bitmap_from_range(0, 100000, 1));
            roaring::Roaring64Map expected(roaring::api::roaring_bitmap_from_range(0, 100000, 1));
            roaring::Roaring64Map actual;
            std::vector<roaring::Roaring64Map> bitmap_chunks;
            while (bitmap.cardinality() != 0) {
                bitmap_chunks.push_back(cut_left(bitmap, bitmap_chunk_limit));
            }
            for (const auto& chunk : bitmap_chunks) {
                actual |= chunk;
            }
            CHECK(actual == expected);
        }
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

TEST_CASE("Bitmap Index Loader") {
    test::Context context;
    db::RWTxn txn{context.txn()};

    const auto address1{0x00000000000000000001_address};
    const auto address2{0x00000000000000000002_address};
    const auto address3{0x00000000000000000003_address};

    // Note range is [min,max)
    roaring::Roaring64Map roaring1{roaring::api::roaring_bitmap_from_range(1, 20'001, 1)};
    roaring::Roaring64Map roaring2{roaring::api::roaring_bitmap_from_range(1, 50'001, 1)};
    roaring::Roaring64Map roaring3{roaring::api::roaring_bitmap_from_range(40'000, 50'001, 1)};

    absl::btree_map<Bytes, roaring::Roaring64Map> bitmaps{
        {Bytes(address1.bytes, kAddressLength), roaring1},
        {Bytes(address2.bytes, kAddressLength), roaring2},
        {Bytes(address3.bytes, kAddressLength), roaring3},
    };

    etl::Collector collector(context.node_settings().data_directory->etl().path());
    db::bitmap::IndexLoader bm_loader(db::table::kLogAddressIndex);
    bm_loader.flush_bitmaps_to_etl(bitmaps, &collector, /*flush_count=*/1);
    REQUIRE(collector.bytes_size());

    // Load into LogAddressIndex
    REQUIRE_NOTHROW(bm_loader.merge_bitmaps(txn, kAddressLength, &collector));
    Cursor log_addresses(txn, table::kLogAddressIndex);
    REQUIRE(log_addresses.size() > static_cast<size_t>(bitmaps.size()));

    // Check we have an incomplete shard for each key
    Bytes key(address1.bytes, kAddressLength);
    key.append(db::block_key(UINT64_MAX));
    auto data{log_addresses.find(db::to_slice(key), /*throw_notfound=*/false)};
    REQUIRE(data.done);
    auto loaded_bitmap{bitmap::parse(data.value)};
    REQUIRE(loaded_bitmap.maximum() == 20'000);

    key.assign(address2.bytes, kAddressLength);
    key.append(db::block_key(UINT64_MAX));
    data = log_addresses.find(db::to_slice(key), /*throw_notfound=*/false);
    REQUIRE(data.done);
    loaded_bitmap = bitmap::parse(data.value);
    REQUIRE(loaded_bitmap.maximum() == 50'000);

    key.assign(address3.bytes, kAddressLength);
    key.append(db::block_key(UINT64_MAX));
    data = log_addresses.find(db::to_slice(key), /*throw_notfound=*/false);
    REQUIRE(data.done);
    loaded_bitmap = bitmap::parse(data.value);
    REQUIRE(loaded_bitmap.maximum() == 50'000);

    // Unwind to 30'000
    std::map<Bytes, bool> ubm{
        {Bytes(address1.bytes, kAddressLength), false},
        {Bytes(address2.bytes, kAddressLength), false},
        {Bytes(address3.bytes, kAddressLength), false},
    };
    REQUIRE_NOTHROW(bm_loader.unwind_bitmaps(txn, 30'000, ubm));

    // First address stays the same
    key.assign(address1.bytes, kAddressLength);
    key.append(db::block_key(UINT64_MAX));
    data = log_addresses.find(db::to_slice(key), /*throw_notfound=*/false);
    REQUIRE(data.done);
    loaded_bitmap = bitmap::parse(data.value);
    REQUIRE(loaded_bitmap.maximum() == 20'000);

    // Second address has decreased to 30'000
    key.assign(address2.bytes, kAddressLength);
    key.append(db::block_key(UINT64_MAX));
    data = log_addresses.find(db::to_slice(key), /*throw_notfound=*/false);
    REQUIRE(data.done);
    loaded_bitmap = bitmap::parse(data.value);
    REQUIRE(loaded_bitmap.maximum() == 30'000);

    // Third address should be gone
    key.assign(address3.bytes, kAddressLength);
    key.append(db::block_key(UINT64_MAX));
    data = log_addresses.find(db::to_slice(key), /*throw_notfound=*/false);
    REQUIRE_FALSE(data.done);

    // Now prune up to 25000
    // Note that all blocks <= threshold are removed
    REQUIRE_NOTHROW(bm_loader.prune_bitmaps(txn, 25'000));

    // First address is gone
    key.assign(address1.bytes, kAddressLength);
    key.append(db::block_key(UINT64_MAX));
    data = log_addresses.find(db::to_slice(key), /*throw_notfound=*/false);
    REQUIRE_FALSE(data.done);

    // Second address has a new minimum
    key.assign(address2.bytes, kAddressLength);
    key.append(db::block_key(UINT64_MAX));
    data = log_addresses.find(db::to_slice(key), /*throw_notfound=*/false);
    REQUIRE(data.done);
    loaded_bitmap = bitmap::parse(data.value);
    REQUIRE(loaded_bitmap.maximum() == 30'000);
    REQUIRE(loaded_bitmap.minimum() == 25'001);

    REQUIRE(bm_loader.get_current_key().empty());
}

}  // namespace silkworm::db::bitmap
