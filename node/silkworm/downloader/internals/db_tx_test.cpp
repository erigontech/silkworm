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

#include "db_tx.hpp"

#include <catch2/catch.hpp>

#include <silkworm/common/directories.hpp>

namespace silkworm {

namespace db {

    TEST_CASE("db access layer addendum") {
        TemporaryDirectory tmp_dir;

        db::EnvConfig db_config{tmp_dir.path().string(), /*create*/ true};
        db_config.inmemory = true;

        Db db{db::open_env(db_config)};
        Db::ReadWriteAccess rw_access(db);
        Db::ReadWriteAccess::Tx tx(rw_access);

        table::check_or_create_chaindata_tables(tx.raw());

        uint64_t block_num{11'054'435};

        BlockHeader header;
        header.number = block_num;
        header.beneficiary = 0x09ab1303d3ccaf5f018cd511146b07a240c70294_address;
        header.gas_limit = 12'451'080;
        header.gas_used = 12'443'619;

        SECTION("read/write header") {
            CHECK_NOTHROW(tx.write_header(header, false));
            auto read_header = tx.read_header(header.number, header.hash());

            REQUIRE(read_header != std::nullopt);           // Warning: this is a limited test, we only test that
            REQUIRE(read_header->number == header.number);  // read and write are implemented in a symmetric way
            REQUIRE(read_header->beneficiary == header.beneficiary);
            REQUIRE(read_header->gas_limit == header.gas_limit);
            REQUIRE(read_header->gas_used == header.gas_used);
        }

        SECTION("read/write header") {
            auto hash = header.hash();
            CHECK_NOTHROW(tx.write_head_header_hash(hash));
            auto read_hash = tx.read_head_header_hash();

            REQUIRE(read_hash != std::nullopt);
            REQUIRE(read_hash == hash);
        }

        SECTION("read/write canonical hash") {
            CHECK_NOTHROW(tx.write_canonical_hash(header.number, header.hash()));
            auto read_hash = tx.read_canonical_hash(header.number);

            REQUIRE(read_hash != std::nullopt);   // Warning: this is a limited test, we only test that
            REQUIRE(read_hash == header.hash());  // read and write are implemented in a symmetric way
        }

        SECTION("read/write total difficulty") {
            CHECK_NOTHROW(tx.write_total_difficulty(header.number, header.hash(), 1234));
            auto read_td = tx.read_total_difficulty(header.number, header.hash());

            REQUIRE(read_td != std::nullopt);  // Warning: this is a limited test, we only test that
            REQUIRE(read_td == 1234);          // read and write are implemented in a symmetric way
        }

        SECTION("read/write stage progress") {
            BlockNum stage_progress = 1234;
            CHECK_NOTHROW(tx.write_stage_progress(db::stages::kHeadersKey, stage_progress));
            BlockNum read_stage_progress = tx.read_stage_progress(db::stages::kHeadersKey);

            REQUIRE(read_stage_progress == stage_progress);
        }

        SECTION("write/read/delete canonical hash") {
            REQUIRE_NOTHROW(tx.write_canonical_hash(header.number, header.hash()));
            REQUIRE_NOTHROW(tx.delete_canonical_hash(header.number));

            auto read_hash = tx.read_canonical_hash(header.number);

            REQUIRE(read_hash == std::nullopt);
        }

        SECTION("header with biggest td") {
            CHECK_NOTHROW(tx.write_total_difficulty(header.number, header.hash(), 1234));

            header.number++;
            CHECK_NOTHROW(tx.write_total_difficulty(header.number, header.hash(), 100'000'001'000'000));
            auto expected_max_bn = header.number;
            auto expected_max_hash = header.hash();

            header.number++;
            CHECK_NOTHROW(tx.write_total_difficulty(header.number, header.hash(), 34'000'000'000));

            auto [max_bn, max_hash] = tx.header_with_biggest_td();

            REQUIRE(max_bn == expected_max_bn);
            REQUIRE(max_hash == expected_max_hash);
        }

        SECTION("header with biggest td having bad headers") {
            std::set<Hash> bad_headers;

            CHECK_NOTHROW(tx.write_total_difficulty(header.number, header.hash(), 1234));

            header.number++;
            CHECK_NOTHROW(tx.write_total_difficulty(header.number, header.hash(), 100'000'001'000'000));
            bad_headers.insert(header.hash());

            header.number++;
            CHECK_NOTHROW(tx.write_total_difficulty(header.number, header.hash(), 34'000'000'000));
            auto expected_max_bn = header.number;
            auto expected_max_hash = header.hash();

            auto [max_bn, max_hash] = tx.header_with_biggest_td(&bad_headers);

            REQUIRE(max_bn == expected_max_bn);
            REQUIRE(max_hash == expected_max_hash);
        }
    }

}  // namespace db

}  // namespace silkworm