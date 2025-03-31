// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "db_utils.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/infra/common/directories.hpp>

namespace silkworm::db {

using namespace silkworm::datastore::kvdb;

TEST_CASE("db access layer addendum") {
    TemporaryDirectory tmp_dir;

    EnvConfig db_config{.path = tmp_dir.path().string(), .create = true, .in_memory = true};

    auto env = open_env(db_config);
    RWAccess rw_access{env};
    RWTxnManaged tx = rw_access.start_rw_tx();

    table::check_or_create_chaindata_tables(tx);

    uint64_t block_num{11'054'435};

    BlockHeader header;
    header.number = block_num;
    header.beneficiary = 0x09ab1303d3ccaf5f018cd511146b07a240c70294_address;
    header.gas_limit = 12'451'080;
    header.gas_used = 12'443'619;

    SECTION("read/write header") {
        CHECK_NOTHROW(write_header(tx, header, false));
        auto read_header = db::read_header(tx, header.number, header.hash());

        REQUIRE(read_header != std::nullopt);           // Warning: this is a limited test, we only test that
        REQUIRE(read_header->number == header.number);  // read and write are implemented in a symmetric way
        REQUIRE(read_header->beneficiary == header.beneficiary);
        REQUIRE(read_header->gas_limit == header.gas_limit);
        REQUIRE(read_header->gas_used == header.gas_used);
    }

    SECTION("read/write head header") {
        auto hash = header.hash();
        CHECK_NOTHROW(write_head_header_hash(tx, hash));
        auto read_hash = read_head_header_hash(tx);

        REQUIRE(read_hash != std::nullopt);
        REQUIRE(read_hash == hash);
    }

    SECTION("read/write canonical hash") {
        CHECK_NOTHROW(write_canonical_hash(tx, header.number, header.hash()));
        auto read_hash = read_canonical_header_hash(tx, header.number);

        REQUIRE(read_hash != std::nullopt);   // Warning: this is a limited test, we only test that
        REQUIRE(read_hash == header.hash());  // read and write are implemented in a symmetric way
    }

    SECTION("read/write total difficulty") {
        CHECK_NOTHROW(write_total_difficulty(tx, header.number, header.hash(), 1234));
        auto read_td = read_total_difficulty(tx, header.number, header.hash());

        REQUIRE(read_td != std::nullopt);  // Warning: this is a limited test, we only test that
        REQUIRE(read_td == 1234);          // read and write are implemented in a symmetric way
    }

    SECTION("read/write stage progress") {
        BlockNum stage_progress = 1234;
        CHECK_NOTHROW(stages::write_stage_progress(tx, stages::kHeadersKey, stage_progress));
        BlockNum read_stage_progress = stages::read_stage_progress(tx, stages::kHeadersKey);

        REQUIRE(read_stage_progress == stage_progress);
    }

    SECTION("write/read/delete canonical hash") {
        REQUIRE_NOTHROW(write_canonical_hash(tx, header.number, header.hash()));
        REQUIRE_NOTHROW(delete_canonical_hash(tx, header.number));

        auto read_hash = read_canonical_header_hash(tx, header.number);

        REQUIRE(read_hash == std::nullopt);
    }

    SECTION("header with biggest td") {
        CHECK_NOTHROW(write_total_difficulty(tx, header.number, header.hash(), 1234));

        ++header.number;
        CHECK_NOTHROW(write_total_difficulty(tx, header.number, header.hash(), 100'000'001'000'000));
        auto expected_max_block_num = header.number;
        auto expected_max_hash = header.hash();

        ++header.number;
        CHECK_NOTHROW(write_total_difficulty(tx, header.number, header.hash(), 34'000'000'000));

        auto [max_block_num, max_hash] = header_with_biggest_td(tx);

        REQUIRE(max_block_num == expected_max_block_num);
        REQUIRE(max_hash == expected_max_hash);
    }

    SECTION("header with biggest td having bad headers") {
        std::set<Hash> bad_headers;

        CHECK_NOTHROW(write_total_difficulty(tx, header.number, header.hash(), 1234));

        ++header.number;
        CHECK_NOTHROW(write_total_difficulty(tx, header.number, header.hash(), 100'000'001'000'000));
        bad_headers.insert(header.hash());

        ++header.number;
        CHECK_NOTHROW(write_total_difficulty(tx, header.number, header.hash(), 34'000'000'000));
        auto expected_max_block_num = header.number;
        auto expected_max_hash = header.hash();

        auto [max_block_num, max_hash] = header_with_biggest_td(tx, &bad_headers);

        REQUIRE(max_block_num == expected_max_block_num);
        REQUIRE(max_hash == expected_max_hash);
    }

    SECTION("read/write body") {
        BlockBody body{};  // a void body, access_layer already has test on body read/write

        CHECK_NOTHROW(write_body(tx, body, header.hash(), header.number));

        BlockBody read_body{};
        bool present = db::read_body(tx, header.hash(), header.number, read_body);

        REQUIRE(present);
        REQUIRE(body == read_body);
    }
}

}  // namespace silkworm::db
