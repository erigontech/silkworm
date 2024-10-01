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

#include "db_utils.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/infra/common/directories.hpp>

namespace silkworm::db {

TEST_CASE("db access layer addendum") {
    TemporaryDirectory tmp_dir;

    db::EnvConfig db_config{.path = tmp_dir.path().string(), .create = true, .in_memory = true};

    auto env = db::open_env(db_config);
    db::RWAccess rw_access{env};
    db::RWTxnManaged tx = rw_access.start_rw_tx();

    db::table::check_or_create_chaindata_tables(tx);

    uint64_t block_num{11'054'435};

    BlockHeader header;
    header.number = block_num;
    header.beneficiary = 0x09ab1303d3ccaf5f018cd511146b07a240c70294_address;
    header.gas_limit = 12'451'080;
    header.gas_used = 12'443'619;

    SECTION("read/write header") {
        CHECK_NOTHROW(db::write_header(tx, header, false));
        auto read_header = db::read_header(tx, header.number, header.hash());

        REQUIRE(read_header != std::nullopt);           // Warning: this is a limited test, we only test that
        REQUIRE(read_header->number == header.number);  // read and write are implemented in a symmetric way
        REQUIRE(read_header->beneficiary == header.beneficiary);
        REQUIRE(read_header->gas_limit == header.gas_limit);
        REQUIRE(read_header->gas_used == header.gas_used);
    }

    SECTION("read/write head header") {
        auto hash = header.hash();
        CHECK_NOTHROW(db::write_head_header_hash(tx, hash));
        auto read_hash = db::read_head_header_hash(tx);

        REQUIRE(read_hash != std::nullopt);
        REQUIRE(read_hash == hash);
    }

    SECTION("read/write canonical hash") {
        CHECK_NOTHROW(db::write_canonical_hash(tx, header.number, header.hash()));
        auto read_hash = db::read_canonical_header_hash(tx, header.number);

        REQUIRE(read_hash != std::nullopt);   // Warning: this is a limited test, we only test that
        REQUIRE(read_hash == header.hash());  // read and write are implemented in a symmetric way
    }

    SECTION("read/write total difficulty") {
        CHECK_NOTHROW(db::write_total_difficulty(tx, header.number, header.hash(), 1234));
        auto read_td = db::read_total_difficulty(tx, header.number, header.hash());

        REQUIRE(read_td != std::nullopt);  // Warning: this is a limited test, we only test that
        REQUIRE(read_td == 1234);          // read and write are implemented in a symmetric way
    }

    SECTION("read/write stage progress") {
        BlockNum stage_progress = 1234;
        CHECK_NOTHROW(db::stages::write_stage_progress(tx, db::stages::kHeadersKey, stage_progress));
        BlockNum read_stage_progress = db::stages::read_stage_progress(tx, db::stages::kHeadersKey);

        REQUIRE(read_stage_progress == stage_progress);
    }

    SECTION("write/read/delete canonical hash") {
        REQUIRE_NOTHROW(db::write_canonical_hash(tx, header.number, header.hash()));
        REQUIRE_NOTHROW(db::delete_canonical_hash(tx, header.number));

        auto read_hash = db::read_canonical_header_hash(tx, header.number);

        REQUIRE(read_hash == std::nullopt);
    }

    SECTION("header with biggest td") {
        CHECK_NOTHROW(db::write_total_difficulty(tx, header.number, header.hash(), 1234));

        ++header.number;
        CHECK_NOTHROW(db::write_total_difficulty(tx, header.number, header.hash(), 100'000'001'000'000));
        auto expected_max_bn = header.number;
        auto expected_max_hash = header.hash();

        ++header.number;
        CHECK_NOTHROW(db::write_total_difficulty(tx, header.number, header.hash(), 34'000'000'000));

        auto [max_bn, max_hash] = header_with_biggest_td(tx);

        REQUIRE(max_bn == expected_max_bn);
        REQUIRE(max_hash == expected_max_hash);
    }

    SECTION("header with biggest td having bad headers") {
        std::set<Hash> bad_headers;

        CHECK_NOTHROW(db::write_total_difficulty(tx, header.number, header.hash(), 1234));

        ++header.number;
        CHECK_NOTHROW(db::write_total_difficulty(tx, header.number, header.hash(), 100'000'001'000'000));
        bad_headers.insert(header.hash());

        ++header.number;
        CHECK_NOTHROW(db::write_total_difficulty(tx, header.number, header.hash(), 34'000'000'000));
        auto expected_max_bn = header.number;
        auto expected_max_hash = header.hash();

        auto [max_bn, max_hash] = header_with_biggest_td(tx, &bad_headers);

        REQUIRE(max_bn == expected_max_bn);
        REQUIRE(max_hash == expected_max_hash);
    }

    SECTION("read/write body") {
        BlockBody body{};  // a void body, access_layer already has test on body read/write

        CHECK_NOTHROW(db::write_body(tx, body, header.hash(), header.number));

        BlockBody read_body{};
        bool present = db::read_body(tx, header.hash(), header.number, read_body);

        REQUIRE(present);
        REQUIRE(body == read_body);
    }
}

}  // namespace silkworm::db
