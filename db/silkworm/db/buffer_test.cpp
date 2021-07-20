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

#include "buffer.hpp"

#include <catch2/catch.hpp>

#include <silkworm/common/temp_dir.hpp>

#include "tables.hpp"

namespace silkworm::db {

TEST_CASE("Storage update") {
    TemporaryDirectory tmp_dir;
    EnvConfig db_config{tmp_dir.path(), /*create*/ true};
    db_config.inmemory = true;
    auto env{open_env(db_config)};
    auto txn{env.start_write()};
    table::create_all(txn);

    const auto address{0xbe00000000000000000000000000000000000000_address};
    const Bytes key{storage_prefix(full_view(address), kDefaultIncarnation)};

    const auto location_a{0x0000000000000000000000000000000000000000000000000000000000000013_bytes32};
    const auto value_a1{0x000000000000000000000000000000000000000000000000000000000000006b_bytes32};
    const auto value_a2{0x0000000000000000000000000000000000000000000000000000000000000085_bytes32};

    const auto location_b{0x0000000000000000000000000000000000000000000000000000000000000002_bytes32};
    const auto value_b{0x0000000000000000000000000000000000000000000000000000000000000132_bytes32};

    auto state{db::open_cursor(txn, table::kPlainState)};

    Bytes data_a{full_view(location_a)};
    data_a.append(zeroless_view(value_a1));
    state.upsert(to_slice(key), to_slice(data_a));

    Bytes data_b{full_view(location_b)};
    data_b.append(zeroless_view(value_b));
    state.upsert(to_slice(key), to_slice(data_b));

    Buffer buffer{txn};

    CHECK(buffer.read_storage(address, kDefaultIncarnation, location_a) == value_a1);

    // Update only location A
    buffer.update_storage(address, kDefaultIncarnation, location_a,
                          /*initial=*/value_a1, /*curren=*/value_a2);
    buffer.write_to_db();

    // Location A should have the new value
    const std::optional<ByteView> db_value_a{find_value_suffix(state, key, full_view(location_a))};
    REQUIRE(db_value_a.has_value());
    CHECK(db_value_a == zeroless_view(value_a2));

    // Location B should not change
    const std::optional<ByteView> db_value_b{find_value_suffix(state, key, full_view(location_b))};
    REQUIRE(db_value_b.has_value());
    CHECK(db_value_b == zeroless_view(value_b));
}

}  // namespace silkworm::db
