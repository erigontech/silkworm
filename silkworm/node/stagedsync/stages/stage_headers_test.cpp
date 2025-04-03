// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "stage_headers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/chain/genesis.hpp>
#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/db/genesis.hpp>
#include <silkworm/db/test_util/temp_chain_data.hpp>
#include <silkworm/infra/test_util/log.hpp>

namespace silkworm {

using namespace silkworm::db;

class HeadersStageForTest : public stagedsync::HeadersStage {
  public:
    using stagedsync::HeadersStage::HeaderDataModel;
};
using HeaderDataModelForTest = HeadersStageForTest::HeaderDataModel;

TEST_CASE("HeadersStage - data model") {
    db::test_util::TempChainDataStore context;
    context.add_genesis_data();
    context.commit_txn();

    auto chaindata = context.chaindata_rw();
    auto data_model_factory = context.data_model_factory();

    /* status:
     *         h0
     * input:
     *         h0 <----- h1
     */
    SECTION("one header after the genesis") {
        auto tx = chaindata.start_rw_tx();
        DataModel data_model = data_model_factory(tx);

        auto header0_hash = read_canonical_header_hash(tx, 0);
        REQUIRE(header0_hash.has_value());

        auto header0 = read_canonical_header(tx, 0);
        REQUIRE(header0.has_value());

        BlockNum headers_stage_block_num = 0;
        HeaderDataModelForTest hm{tx, data_model, headers_stage_block_num};

        REQUIRE(hm.max_block_num() == 0);
        REQUIRE(hm.max_hash() == header0_hash);
        REQUIRE(hm.total_difficulty() == header0->difficulty);

        BlockHeader header1;
        header1.number = 1;
        header1.difficulty = 17'171'480'576;
        header1.parent_hash = *header0_hash;
        auto header1_hash = header1.hash();

        auto td = header0->difficulty + header1.difficulty;

        hm.update_tables(header1);  // note that this will NOT write header1 on db

        // check internal status
        REQUIRE(hm.max_block_num() == header1.number);
        REQUIRE(hm.max_hash() == header1_hash);
        REQUIRE(hm.total_difficulty() == td);

        // check db content
        // REQUIRE(read_head_header_hash(tx) == header1_hash);
        REQUIRE(read_total_difficulty(tx, header1.number, header1.hash()) == td);
        // REQUIRE(read_block_num(tx, header1.hash()) == header1.number); block numbers will be added by stage block-hashes
    }

    /* status:
     *         h0 (persisted)
     * input:
     *        (h0) <----- h1 <----- h2
     *                |-- h1'
     */
    SECTION("some header after the genesis") {
        auto tx = chaindata.start_rw_tx();
        DataModel data_model = data_model_factory(tx);

        // starting from an initial status
        auto header0 = read_canonical_header(tx, 0);
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
        BlockNum headers_stage_block_num = 0;
        HeaderDataModelForTest hm{tx, data_model, headers_stage_block_num};

        hm.update_tables(header1);
        hm.update_tables(header2);

        // check internal status
        intx::uint256 expected_td = header0->difficulty + header1.difficulty + header2.difficulty;

        REQUIRE(hm.total_difficulty() == expected_td);
        REQUIRE(hm.max_block_num() == 2);
        REQUIRE(hm.max_hash() == header2_hash);

        // check db content
        // REQUIRE(read_head_header_hash(tx) == header2_hash);
        REQUIRE(read_total_difficulty(tx, 2, header2.hash()) == expected_td);

        // Now we suppose CL triggers an unwind, resetting to h0
        BlockNum headers_stage_block_num_fork = 0;
        HeaderDataModelForTest hm_fork{tx, data_model, headers_stage_block_num_fork};

        hm_fork.update_tables(header1b);  // suppose it arrives after header2

        // check internal status
        intx::uint256 expected_td_fork = header0->difficulty + header1b.difficulty;

        REQUIRE(hm_fork.total_difficulty() == expected_td_fork);
        REQUIRE(hm_fork.max_block_num() == 1);
        REQUIRE(hm_fork.max_hash() == header1b_hash);

        // check db content
        // REQUIRE(read_head_header_hash(tx) == header1b_hash);
        REQUIRE(read_total_difficulty(tx, 1, header1b_hash) == expected_td_fork);
        REQUIRE(read_total_difficulty(tx, 2, header2.hash()) == expected_td);  // this should remain
    }
}

}  // namespace silkworm