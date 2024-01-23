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

#include "stage_bodies.hpp"

#include <iostream>

#include <catch2/catch.hpp>

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/node/db/genesis.hpp>
#include <silkworm/node/db/stages.hpp>
#include <silkworm/node/db/test_util/temp_chain_data.hpp>

namespace silkworm {

class BodiesStage_ForTest : public stagedsync::BodiesStage {
  public:
    using stagedsync::BodiesStage::BodyDataModel;
};
using BodyDataModel_ForTest = BodiesStage_ForTest::BodyDataModel;

TEST_CASE("BodiesStage - data model") {
    db::test_util::TempChainData context;
    context.add_genesis_data();
    context.commit_txn();

    auto& chain_config = context.chain_config();

    /* status:
     *         h0
     * input:
     *         h0 <----- h1
     */
    SECTION("one invalid body after the genesis") {
        db::RWTxnManaged tx(context.env());

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

        BlockNum bodies_stage_height = 0;
        BodyDataModel_ForTest bm(tx, bodies_stage_height, chain_config);

        REQUIRE(bm.initial_height() == 0);
        REQUIRE(bm.highest_height() == 0);
        REQUIRE(bm.unwind_needed() == false);
        REQUIRE(bm.unwind_point() == 0);

        bm.update_tables(block1);

        // check internal status
        REQUIRE(bm.highest_height() == 0);    // block is not valid so no progress
        REQUIRE(bm.unwind_needed() == true);  // block is not valid -> unwind
        REQUIRE(bm.unwind_point() == 0);      // block-num - 1
        REQUIRE(bm.bad_block() == header1_hash);

        bm.close();
    }

    SECTION("one valid body after the genesis") {
        db::RWTxnManaged tx(context.env());

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
        REQUIRE(decoding_result);

        BlockNum bodies_stage_height = 0;
        BodyDataModel_ForTest bm(tx, bodies_stage_height, chain_config);

        // check internal status
        REQUIRE(bm.initial_height() == 0);
        REQUIRE(bm.highest_height() == 0);
        REQUIRE(bm.unwind_needed() == false);
        REQUIRE(bm.unwind_point() == 0);

        bm.update_tables(block1);  // validation must pass

        // check internal status
        REQUIRE(bm.highest_height() == 1);
        REQUIRE(bm.unwind_needed() == false);
        REQUIRE(bm.unwind_point() == 0);

        // close
        bm.close();
    }
}

}  // namespace silkworm
