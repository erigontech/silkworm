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

#include "body_persistence.hpp"

#include <algorithm>
#include <iostream>

#include <catch2/catch.hpp>

#include <silkworm/chain/genesis.hpp>
#include <silkworm/common/cast.hpp>
#include <silkworm/common/test_context.hpp>
#include <silkworm/db/genesis.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/types/block.hpp>

#include "body_sequence.hpp"

namespace silkworm {

TEST_CASE("BodyPersistence - body persistence") {
    test::Context context;
    auto& txn{context.txn()};

    bool allow_exceptions = false;

    auto chain_config{kMainnetConfig};
    chain_config.genesis_hash.emplace(kMainnetGenesisHash);

    auto source_data = silkworm::read_genesis_data(chain_config.chain_id);
    auto genesis_json = nlohmann::json::parse(source_data, nullptr, allow_exceptions);
    db::initialize_genesis(txn, genesis_json, allow_exceptions);
    context.commit_txn();

    /* status:
     *         h0
     * input:
     *         h0 <----- h1
     */
    SECTION("one invalid body after the genesis") {
        db::RWTxn tx(context.env());

        auto header0_hash = db::read_canonical_hash(tx, 0);
        REQUIRE(header0_hash.has_value());

        auto header0 = db::read_canonical_header(tx, 0);
        REQUIRE(header0.has_value());

        Block block1;
        block1.header.number = 1;
        block1.header.difficulty = 17'171'480'576;  // a random value
        block1.header.parent_hash = *header0_hash;
        auto header1_hash = block1.header.hash();
        block1.ommers.push_back(BlockHeader{});  // generate error InvalidOmmerHeader

        BodyPersistence bp(tx, chain_config);

        REQUIRE(bp.initial_height() == 0);
        REQUIRE(bp.highest_height() == 0);
        REQUIRE(bp.unwind_needed() == false);
        REQUIRE(bp.unwind_point() == 0);

        bp.persist(block1);

        // check internal status
        REQUIRE(bp.highest_height() == 0);    // block is not valid so no progress
        REQUIRE(bp.unwind_needed() == true);  // block is not valid -> unwind
        REQUIRE(bp.unwind_point() == 0);      // block-num - 1
        REQUIRE(bp.bad_block() == header1_hash);

        // check db content
        BlockBody saved_body;
        bool present = db::read_body(tx, block1.header.hash(), saved_body);

        REQUIRE(!present);

        bp.close();
    }

    SECTION("one valid body after the genesis") {
        db::RWTxn tx(context.env());

        auto header0_hash = db::read_canonical_hash(tx, 0);
        REQUIRE(header0_hash.has_value());

        auto header0 = db::read_canonical_header(tx, 0);
        REQUIRE(header0.has_value());

        std::string raw_header1 =
            "f90211a0d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3a01dcc4de8dec75d7aab85b567b6ccd41a"
            "d312451b948a7413f0a142fd40d493479405a56e2d52c817161883f50c441c3228cfe54d9fa0d67e4d450343046425ae4271474353"
            "857ab860dbc0a1dde64b41b5cd3a532bf3a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e8"
            "1f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b901000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000008503ff80000001821388808455ba422499476574682f76312e302e302f"
            "6c696e75782f676f312e342e32a0969b900de27b6ac6a67742365dd65f55a0526c41fd18e1b16f1a1215c2e66f5988539bd4979fef"
            "1ec4";
        std::optional<Bytes> encoded_header1 = from_hex(raw_header1);

        Block block1;
        ByteView encoded_view = encoded_header1.value();
        auto decoding_result = rlp::decode(encoded_view, block1.header);
        // Note: block1 has zero transactions and zero ommers on mainnet
        REQUIRE(decoding_result == DecodingResult::kOk);

        BodyPersistence bp(tx, chain_config);

        // check internal status
        REQUIRE(bp.initial_height() == 0);
        REQUIRE(bp.highest_height() == 0);
        REQUIRE(bp.unwind_needed() == false);
        REQUIRE(bp.unwind_point() == 0);

        bp.persist(block1);  // validation must pass

        // check internal status
        REQUIRE(bp.highest_height() == 1);
        REQUIRE(bp.unwind_needed() == false);
        REQUIRE(bp.unwind_point() == 0);

        // check db content
        BlockBody saved_body;
        bool present = db::read_body(tx, block1.header.hash(), block1.header.number, saved_body);

        REQUIRE(present);
        REQUIRE(saved_body == block1);

        auto bodies_stage_height = db::stages::read_stage_progress(tx, db::stages::kBlockBodiesKey);

        REQUIRE(bodies_stage_height == block1.header.number);

        // close
        bp.close();

        // re-opening
        BodyPersistence bp2(tx, chain_config);

        // check internal status
        REQUIRE(bp2.initial_height() == 1);
        REQUIRE(bp2.highest_height() == 1);

        // close
        bp2.close();

        // removing a block
        BodyPersistence::remove_bodies(0, block1.header.hash(), tx);

        // check internal status
        BodyPersistence bp3(tx, chain_config);
        REQUIRE(bp3.initial_height() == 0);
        REQUIRE(bp3.highest_height() == 0);
    }
}

}  // namespace silkworm
