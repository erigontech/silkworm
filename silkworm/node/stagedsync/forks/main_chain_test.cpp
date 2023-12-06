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

#include "main_chain.hpp"

#include <iostream>

#include <boost/asio/io_context.hpp>
#include <catch2/catch.hpp>

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/infra/common/environment.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/node/common/preverified_hashes.hpp>
#include <silkworm/node/db/genesis.hpp>
#include <silkworm/node/db/stages.hpp>
#include <silkworm/node/test/context.hpp>

namespace silkworm {

namespace asio = boost::asio;
using namespace stagedsync;
using namespace intx;  // just for literals

class MainChain_ForTest : public stagedsync::MainChain {
  public:
    using stagedsync::MainChain::canonical_chain_;
    using stagedsync::MainChain::canonical_head_status_;
    using stagedsync::MainChain::current_head;
    using stagedsync::MainChain::insert_block;
    using stagedsync::MainChain::MainChain;
    using stagedsync::MainChain::pipeline_;
    using stagedsync::MainChain::tx_;
};

static Block generateSampleChildrenBlock(const BlockHeader& parent) {
    Block block;
    auto parent_hash = parent.hash();

    // BlockHeader
    block.header.number = parent.number + 1;
    block.header.difficulty = 17'000'000'000 + block.header.number;
    block.header.parent_hash = parent_hash;
    block.header.beneficiary = 0xc8ebccc5f5689fa8659d83713341e5ad19349448_address;
    block.header.state_root = kEmptyRoot;
    block.header.receipts_root = kEmptyRoot;
    block.header.gas_limit = 10'000'000;
    block.header.gas_used = 0;
    block.header.timestamp = parent.timestamp + 12;
    block.header.extra_data = {};

    return block;
}

TEST_CASE("MainChain") {
    test_util::SetLogVerbosityGuard log_guard(log::Level::kNone);

    asio::io_context io;
    asio::executor_work_guard<decltype(io.get_executor())> work{io.get_executor()};

    test::Context context;
    context.add_genesis_data();
    context.commit_txn();

    PreverifiedHashes::current.clear();                           // disable preverified hashes
    Environment::set_stop_before_stage(db::stages::kSendersKey);  // only headers, block hashes and bodies

    db::RWAccess db_access{context.env()};
    MainChain_ForTest main_chain{io, context.node_settings(), db_access};
    main_chain.open();

    auto& tx = main_chain.tx();

    auto header0_hash = db::read_canonical_hash(tx, 0);
    REQUIRE(header0_hash.has_value());

    auto header0 = db::read_canonical_header(tx, 0);
    REQUIRE(header0.has_value());

    BlockId block0_id{0, *header0_hash};

    // initial status
    auto initial_progress = main_chain.get_block_progress();
    REQUIRE(initial_progress == 0);

    auto initial_canonical_head = main_chain.current_head();
    REQUIRE(initial_canonical_head == block0_id);
    REQUIRE(main_chain.last_chosen_head() == block0_id);
    REQUIRE(initial_canonical_head.number == initial_progress);
    REQUIRE(main_chain.canonical_chain_.current_head() == initial_canonical_head);

    /* status:
     *         h0
     * input:
     *         h0 <----- h1
     */

    SECTION("one invalid body after the genesis") {
        Block block1;
        block1.header.number = 1;
        block1.header.difficulty = 17'171'480'576;  // a random value
        block1.header.parent_hash = *header0_hash;
        block1.ommers.push_back(BlockHeader{});  // generate error InvalidOmmerHeader
        auto block1_hash = block1.header.hash();
        BlockId block1_id{1, block1_hash};

        // inserting headers & bodies
        main_chain.insert_block(block1);

        // check db
        BlockBody saved_body;
        bool present = db::read_body(tx, block1_hash, block1.header.number, saved_body);
        REQUIRE(present);

        auto progress = main_chain.get_block_progress();
        REQUIRE(progress == 1);

        auto canonical_head = main_chain.current_head();
        REQUIRE(canonical_head == initial_canonical_head);  // doesn't change

        // verifying the chain
        auto verification = main_chain.verify_chain(block1_hash);

        CHECK(db::stages::read_stage_progress(tx, db::stages::kHeadersKey) == 1);
        CHECK(db::stages::read_stage_progress(tx, db::stages::kBlockHashesKey) == 1);
        CHECK(db::stages::read_stage_progress(tx, db::stages::kBlockBodiesKey) == 1);
        CHECK(db::stages::read_stage_progress(tx, db::stages::kSendersKey) == 0);
        CHECK(db::stages::read_stage_progress(tx, db::stages::kExecutionKey) == 0);

        CHECK(!holds_alternative<ValidationError>(verification));
        REQUIRE(holds_alternative<InvalidChain>(verification));
        auto invalid_chain = std::get<InvalidChain>(verification);

        REQUIRE(invalid_chain.unwind_point == block0_id);
        REQUIRE(invalid_chain.bad_block.has_value());
        REQUIRE(invalid_chain.bad_block.value() == block1_hash);
        REQUIRE(invalid_chain.bad_headers.size() == 1);
        REQUIRE(*(invalid_chain.bad_headers.begin()) == block1_hash);

        // check status
        auto final_progress = main_chain.get_block_progress();
        REQUIRE(final_progress == block1.header.number);

        auto final_canonical_head = main_chain.current_head();
        REQUIRE(final_canonical_head == block1_id);
        REQUIRE(main_chain.canonical_chain_.current_head() == block1_id);
        REQUIRE(main_chain.last_chosen_head() == block0_id);  // not changed

        auto current_status = main_chain.canonical_head_status_;
        REQUIRE(holds_alternative<InvalidChain>(current_status));

        // check canonical
        auto present_in_canonical = main_chain.get_finalized_canonical_hash(block1.header.number);
        REQUIRE(!present_in_canonical);

        // reverting the chain
        auto updated = main_chain.notify_fork_choice_update(*header0_hash);
        CHECK(updated);

        // checking the status
        present_in_canonical = main_chain.get_finalized_canonical_hash(block1.header.number);
        REQUIRE(!present_in_canonical);

        final_canonical_head = main_chain.current_head();
        CHECK(final_canonical_head == block1_id);           // still block1 even if invalid
        CHECK(main_chain.last_chosen_head() == block0_id);  // not changed

        current_status = main_chain.canonical_head_status_;
        CHECK(holds_alternative<InvalidChain>(current_status));
        CHECK(std::get<InvalidChain>(current_status).unwind_point == block0_id);
    }

    SECTION("one valid body after the genesis") {
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
        auto block1_hash = block1.header.hash();
        BlockId block1_id{1, block1_hash};

        // inserting & verifying the block
        main_chain.insert_block(block1);
        auto verification = main_chain.verify_chain(block1_hash);

        REQUIRE(holds_alternative<ValidChain>(verification));
        auto valid_chain = std::get<ValidChain>(verification);
        REQUIRE(valid_chain.current_head == block1_id);

        // check status
        REQUIRE(main_chain.pipeline_.head_header_number() == block1.header.number);
        REQUIRE(main_chain.pipeline_.head_header_hash() == block1_hash);

        auto final_canonical_head = main_chain.current_head();
        REQUIRE(final_canonical_head == block1_id);
        REQUIRE(main_chain.last_chosen_head() == block0_id);  // not changed

        REQUIRE(main_chain.canonical_chain_.current_head() == block1_id);

        auto current_status = main_chain.canonical_head_status_;
        REQUIRE(holds_alternative<ValidChain>(current_status));
        REQUIRE(std::get<ValidChain>(current_status).current_head == block1_id);

        // check db content
        BlockBody saved_body;
        bool present = db::read_body(tx, block1_hash, block1.header.number, saved_body);
        REQUIRE(present);

        auto present_in_canonical = main_chain.get_finalized_canonical_hash(block1.header.number);
        REQUIRE(!present_in_canonical);  // not yet

        // confirming the chain
        auto updated = main_chain.notify_fork_choice_update(block1_hash);
        CHECK(updated);

        // checking the status
        present_in_canonical = main_chain.get_finalized_canonical_hash(block1.header.number);
        REQUIRE(present_in_canonical);

        final_canonical_head = main_chain.current_head();
        REQUIRE(final_canonical_head == block1_id);
        REQUIRE(main_chain.last_chosen_head() == block1_id);

        // testing other methods
        Block block1b;
        block1b.header.number = 1;
        block1b.header.difficulty = 1'000'000'000;  // a random value
        block1b.header.parent_hash = *header0_hash;
        main_chain.insert_block(block1b);
        bool extends_canonical = main_chain.extends_last_fork_choice(block1b.header.number, block1b.header.hash());
        CHECK(!extends_canonical);
        Block block2;
        block2.header.number = 2;
        block2.header.difficulty = 1'171'480'576;  // a random value
        block2.header.parent_hash = block1_hash;
        main_chain.insert_block(block2);
        extends_canonical = main_chain.extends_last_fork_choice(block2.header.number, block2.header.hash());
        CHECK(extends_canonical);
        Block block3;
        block3.header.number = 3;
        block3.header.difficulty = 1'171'480'576;  // a random value
        block3.header.parent_hash = block2.header.hash();
        main_chain.insert_block(block3);
        extends_canonical = main_chain.extends_last_fork_choice(block3.header.number, block3.header.hash());
        CHECK(extends_canonical);

        // Testing a mini re-org
        Block new_block1 = generateSampleChildrenBlock(*header0);
        const auto new_block1_hash{new_block1.header.hash()};
        BlockId new_block1_id{1, new_block1_hash};

        // inserting & verifying the block
        main_chain.insert_block(new_block1);
        const auto new_verification1 = main_chain.verify_chain(new_block1_hash);
        CHECK(holds_alternative<ValidChain>(new_verification1));
        CHECK(std::get<ValidChain>(new_verification1).current_head == new_block1_id);

        // confirming the chain
        const auto new_block1_updated = main_chain.notify_fork_choice_update(new_block1_hash);
        CHECK(new_block1_updated);
    }

    SECTION("diverting the head") {
        Block block1 = generateSampleChildrenBlock(*header0);

        Block block2 = generateSampleChildrenBlock(block1.header);

        Block block3 = generateSampleChildrenBlock(block2.header);
        auto block3_hash = block3.header.hash();
        BlockId block3_id{3, block3_hash};

        // inserting & verifying the block
        main_chain.insert_block(block1);
        main_chain.insert_block(block2);
        main_chain.insert_block(block3);

        auto block_progress = main_chain.get_block_progress();
        REQUIRE(block_progress == block3.header.number);

        auto verification = main_chain.verify_chain(block3_hash);

        REQUIRE(holds_alternative<ValidChain>(verification));
        auto valid_chain = std::get<ValidChain>(verification);
        CHECK(valid_chain.current_head == BlockId{3, block3_hash});

        // confirming the chain
        auto fcu_updated = main_chain.notify_fork_choice_update(block3_hash);
        CHECK(fcu_updated);

        auto final_canonical_head = main_chain.current_head();
        CHECK(final_canonical_head == block3_id);
        CHECK(main_chain.canonical_chain_.current_head() == block3_id);
        REQUIRE(main_chain.last_chosen_head() == block3_id);  // not changed

        // Creating a fork and changing the head (trigger unwind)
        {
            Block block2b = generateSampleChildrenBlock(block1.header);
            block2b.header.extra_data = string_view_to_byte_view("I'm different");  // to make it different from block2
            auto block2b_hash = block2b.header.hash();
            BlockId block2b_id{2, block2b_hash};

            // inserting & verifying the block
            main_chain.insert_block(block2b);
            verification = main_chain.verify_chain(block2b_hash);

            REQUIRE(holds_alternative<ValidChain>(verification));
            valid_chain = std::get<ValidChain>(verification);
            CHECK(valid_chain.current_head == block2b_id);

            // confirming the chain
            fcu_updated = main_chain.notify_fork_choice_update(block2b_hash);
            CHECK(fcu_updated);

            final_canonical_head = main_chain.current_head();
            CHECK(final_canonical_head == block2b_id);
            CHECK(main_chain.canonical_chain_.current_head() == block2b_id);
            REQUIRE(main_chain.last_chosen_head() == block2b_id);  // not changed
        }
    }

    SECTION("starting after fcu") {
        Block block1;
        block1.header.number = 1;
        block1.header.difficulty = 17'171'480'576;  // a random value
        block1.header.parent_hash = *header0_hash;
        auto block1_hash = block1.header.hash();
        BlockId block1_id{1, block1_hash};

        // inserting, verifying & confirming
        main_chain.insert_block(block1);
        auto verification = main_chain.verify_chain(block1_hash);
        REQUIRE(holds_alternative<ValidChain>(verification));
        auto fcu_updated = main_chain.notify_fork_choice_update(block1_hash);
        CHECK(fcu_updated);

        // closing the chain (-> application shutdown)
        main_chain.close();

        // opening another main chain (-> application start up)
        MainChain_ForTest main_chain2{io, context.node_settings(), db_access};
        main_chain2.open();

        // checking that the initial state sees the prev fcu
        // auto& tx2 = main_chain2.tx();
        CHECK(main_chain2.last_chosen_head() == block1_id);
        CHECK(main_chain2.last_finalized_head() == block0_id);

        CHECK(holds_alternative<ValidChain>(main_chain2.canonical_head_status_));
    }
}

}  // namespace silkworm
