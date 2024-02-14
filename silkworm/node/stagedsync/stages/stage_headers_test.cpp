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

#include "stage_headers.hpp"

#include <catch2/catch.hpp>

#include <silkworm/core/chain/genesis.hpp>
#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/node/db/genesis.hpp>
#include <silkworm/node/db/test_util/temp_chain_data.hpp>

namespace silkworm {

class HeadersStage_ForTest : public stagedsync::HeadersStage {
  public:
    using stagedsync::HeadersStage::HeaderDataModel;
};
using HeaderDataModel_ForTest = HeadersStage_ForTest::HeaderDataModel;

TEST_CASE("HeadersStage - data model") {
    db::test_util::TempChainData context;
    context.add_genesis_data();
    context.commit_txn();

    /* status:
     *         h0
     * input:
     *         h0 <----- h1
     */
    SECTION("one header after the genesis") {
        db::RWTxnManaged tx(context.env());

        auto header0_hash = db::read_canonical_hash(tx, 0);
        REQUIRE(header0_hash.has_value());

        auto header0 = db::read_canonical_header(tx, 0);
        REQUIRE(header0.has_value());

        BlockNum headers_stage_height = 0;
        HeaderDataModel_ForTest hm(tx, headers_stage_height);

        REQUIRE(hm.highest_height() == 0);
        REQUIRE(hm.highest_hash() == header0_hash);
        REQUIRE(hm.total_difficulty() == header0->difficulty);

        BlockHeader header1;
        header1.number = 1;
        header1.difficulty = 17'171'480'576;
        header1.parent_hash = *header0_hash;
        auto header1_hash = header1.hash();

        auto td = header0->difficulty + header1.difficulty;

        hm.update_tables(header1);  // note that this will NOT write header1 on db

        // check internal status
        REQUIRE(hm.highest_height() == header1.number);
        REQUIRE(hm.highest_hash() == header1_hash);
        REQUIRE(hm.total_difficulty() == td);

        // check db content
        // REQUIRE(db::read_head_header_hash(tx) == header1_hash);
        REQUIRE(db::read_total_difficulty(tx, header1.number, header1.hash()) == td);
        // REQUIRE(db::read_block_number(tx, header1.hash()) == header1.number); block numbers will be added by stage block-hashes
    }

    /* status:
     *         h0 (persisted)
     * input:
     *        (h0) <----- h1 <----- h2
     *                |-- h1'
     */
    SECTION("some header after the genesis") {
        db::RWTxnManaged tx(context.env());

        // starting from an initial status
        auto header0 = db::read_canonical_header(tx, 0);
        auto header0_hash = header0->hash();

        // receiving 3 headers from a peer
        BlockHeader header1;
        header1.number = 1;
        header1.difficulty = 1'000'000;
        header1.parent_hash = header0_hash;
        auto header1_hash = header1.hash();

        BlockHeader header2;
        header2.number = 2;
        header2.difficulty = 1'100'000;
        header2.parent_hash = header1_hash;
        auto header2_hash = header2.hash();

        BlockHeader header1b;
        header1b.number = 1;
        header1b.difficulty = 2'000'000;
        header1b.parent_hash = header0_hash;
        header1b.extra_data = string_view_to_byte_view("I'm different");
        auto header1b_hash = header1b.hash();

        // updating the data model
        BlockNum headers_stage_height = 0;
        HeaderDataModel_ForTest hm(tx, headers_stage_height);

        hm.update_tables(header1);
        hm.update_tables(header2);

        // check internal status
        intx::uint256 expected_td = header0->difficulty + header1.difficulty + header2.difficulty;

        REQUIRE(hm.total_difficulty() == expected_td);
        REQUIRE(hm.highest_height() == 2);
        REQUIRE(hm.highest_hash() == header2_hash);

        // check db content
        // REQUIRE(db::read_head_header_hash(tx) == header2_hash);
        REQUIRE(db::read_total_difficulty(tx, 2, header2.hash()) == expected_td);

        // Now we suppose CL triggers an unwind, resetting to h0
        BlockNum headers_stage_height_fork = 0;
        HeaderDataModel_ForTest hm_fork(tx, headers_stage_height_fork);

        hm_fork.update_tables(header1b);  // suppose it arrives after header2

        // check internal status
        intx::uint256 expected_td_fork = header0->difficulty + header1b.difficulty;

        REQUIRE(hm_fork.total_difficulty() == expected_td_fork);
        REQUIRE(hm_fork.highest_height() == 1);
        REQUIRE(hm_fork.highest_hash() == header1b_hash);

        // check db content
        // REQUIRE(db::read_head_header_hash(tx) == header1b_hash);
        REQUIRE(db::read_total_difficulty(tx, 1, header1b_hash) == expected_td_fork);
        REQUIRE(db::read_total_difficulty(tx, 2, header2.hash()) == expected_td);  // this should remain
    }
}

}  // namespace silkworm