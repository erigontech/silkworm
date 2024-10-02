/*
   Copyright 2024 The Silkworm Authors

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

#include "btree_index.hpp"

#include <filesystem>
#include <sstream>
#include <string_view>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/db/snapshots/seg/compressor.hpp>
#include <silkworm/db/snapshots/seg/decompressor.hpp>
#include <silkworm/infra/test_util/temporary_file.hpp>

namespace silkworm::snapshots::index {

using namespace silkworm::test_util;

using KeyAndValue = std::pair<std::string_view, std::string_view>;

static std::filesystem::path sample_kv_file(const std::filesystem::path& tmp_dir_path, std::span<const KeyAndValue> kv_pairs) {
    const auto kv_file_path = TemporaryDirectory::get_unique_temporary_path();
    seg::Compressor kv_compressor{kv_file_path, tmp_dir_path};
    for (const auto& kv_pair : kv_pairs) {
        kv_compressor.add_word(*from_hex(kv_pair.first), /*is_compressed=*/false);
        kv_compressor.add_word(*from_hex(kv_pair.second), /*is_compressed=*/false);
    }
    seg::Compressor::compress(std::move(kv_compressor));
    return kv_file_path;
}

static std::filesystem::path sample_bt_index_file(const EliasFanoList32& key_offsets) {
    TemporaryFile index_file;
    std::stringstream str_stream;
    str_stream << key_offsets;
    const std::string stream = str_stream.str();
    Bytes ef_bytes{stream.cbegin(), stream.cend()};
    index_file.write(ef_bytes);
    return index_file.path();
}

using KvAndBtPaths = std::tuple<std::filesystem::path, std::filesystem::path>;

static KvAndBtPaths sample_3_keys_kv_and_bt_files(const std::filesystem::path& tmp_dir_path) {
    // Prepare sample uncompressed KV file containing some key-value pairs
    const auto kv_file_path = sample_kv_file(
        tmp_dir_path,
        std::vector<KeyAndValue>{
            KeyAndValue{"0000000000000000000000000000000000000000"sv, "000a0269024e3c8decd159600000"sv},
            KeyAndValue{"0000000000000000000000000000000000000004"sv, "0008cf2fa48840ba8add0000"sv},
            KeyAndValue{"0000000000000000000000000000000000000008"sv, "0008146c4643c28ed8200000"sv},
        });

    // Prepare the BT index for such KV file
    // Note: key offsets can be computed from KV file layout
    // 000000000000000600000000000000000000000000000000000000000000000801000215030F030D
    // 01
    // 0000000000000000000000000000000000000000 <- 1st key, offset 0
    // 03
    // 000A0269024E3C8DECD159600000
    // 01
    // 0000000000000000000000000000000000000004 <- 2nd key, offset 0 + 20 + 1 + 14 + 1
    // 07
    // 0008CF2FA48840BA8ADD0000
    // 01
    // 0000000000000000000000000000000000000008 <- 3rd key, offset 0 + 20 + 1 + 14 + 1 + 20 + 1 + 12 + 1
    // 07
    // 0008146C4643C28ED8200000
    EliasFanoList32 encoded_key_offsets{3, 70};
    encoded_key_offsets.add_offset(0);
    encoded_key_offsets.add_offset(0 + 20 + 1 + 14 + 1);
    encoded_key_offsets.add_offset(0 + 20 + 1 + 14 + 1 + 20 + 1 + 12 + 1);
    encoded_key_offsets.build();
    const auto bt_file_path = sample_bt_index_file(encoded_key_offsets);

    return {kv_file_path, bt_file_path};
}

TEST_CASE("BTreeIndex", "[db]") {
    TemporaryDirectory tmp_dir;

    SECTION("empty") {
        // Prepare empty KV and BT index files
        const auto kv_file_path = sample_kv_file(tmp_dir.path(), {});
        TemporaryFile index_file;
        index_file.write(Bytes{});

        // Open the KV and BT index files
        seg::Decompressor kv_decompressor{kv_file_path};
        kv_decompressor.open();
        CHECK_THROWS_AS(BTreeIndex(kv_decompressor, index_file.path()), std::runtime_error);
    }

    // Prepare sample uncompressed KV file containing 3 key-value pairs and its BT index file
    const auto [kv_file_path, bt_file_path] = sample_3_keys_kv_and_bt_files(tmp_dir.path());

    // Open the KV and BT index files
    seg::Decompressor kv_decompressor{kv_file_path};
    kv_decompressor.open();
    BTreeIndex bt_index{kv_decompressor, bt_file_path};
    REQUIRE(bt_index.key_count() == 3);

    SECTION("BTreeIndex::get") {
        // Check that all values retrieved through BT index match
        size_t key_count{0};
        bool is_key{true};
        Bytes key, value;
        auto kv_iterator = kv_decompressor.begin();
        while (kv_iterator != kv_decompressor.end()) {
            if (is_key) {
                key = *kv_iterator;
                ++key_count;
            } else {
                value = *kv_iterator;
                const auto v = bt_index.get(key, kv_iterator);
                CHECK(v == value);
            }
            ++kv_iterator;
            is_key = !is_key;
        }
        CHECK(key_count == bt_index.key_count());
    }

    SECTION("BTreeIndex::seek") {
        auto kv_iterator = kv_decompressor.begin();

        // Seek using exact keys starting from the first one
        auto index_it = bt_index.seek(ByteView{}, kv_iterator);
        REQUIRE(index_it);
        REQUIRE(index_it->key() == *from_hex("0000000000000000000000000000000000000000"sv));
        REQUIRE(index_it->value() == *from_hex("000a0269024e3c8decd159600000"sv));
        REQUIRE(index_it->data_index() == 0);
        REQUIRE(index_it->next());
        REQUIRE(index_it->key() == *from_hex("0000000000000000000000000000000000000004"sv));
        REQUIRE(index_it->value() == *from_hex("0008cf2fa48840ba8add0000"sv));
        REQUIRE(index_it->data_index() == 1);
        REQUIRE(index_it->next());
        REQUIRE(index_it->key() == *from_hex("0000000000000000000000000000000000000008"sv));
        REQUIRE(index_it->value() == *from_hex("0008146c4643c28ed8200000"sv));
        REQUIRE(index_it->data_index() == 2);
        REQUIRE(!index_it->next());

        // Seek using lower keys than existing ones
        index_it = bt_index.seek(*from_hex("0000000000000000000000000000000000000003"sv), kv_iterator);
        REQUIRE(index_it->key() == *from_hex("0000000000000000000000000000000000000004"sv));
        REQUIRE(index_it->value() == *from_hex("0008cf2fa48840ba8add0000"sv));
        REQUIRE(index_it->data_index() == 1);
        index_it = bt_index.seek(*from_hex("0000000000000000000000000000000000000007"sv), kv_iterator);
        REQUIRE(index_it->key() == *from_hex("0000000000000000000000000000000000000008"sv));
        REQUIRE(index_it->value() == *from_hex("0008146c4643c28ed8200000"sv));
        REQUIRE(index_it->data_index() == 2);

        // Seek beyond the last key
        CHECK(!bt_index.seek(*from_hex("0000000000000000000000000000000000000009"), kv_iterator));
        CHECK(!bt_index.seek(*from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"), kv_iterator));
    }
}

}  // namespace silkworm::snapshots::index
