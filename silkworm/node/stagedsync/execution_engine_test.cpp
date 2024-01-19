/*
   Copyright 2023 The Silkworm Authors

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

#include "execution_engine.hpp"

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
#include <silkworm/node/db/test_util/temp_chain_data.hpp>
#include <silkworm/node/test_util/temp_chain_data_node_settings.hpp>

namespace silkworm {

namespace asio = boost::asio;
using namespace stagedsync;

static std::shared_ptr<Block> generateSampleChildrenBlock(const BlockHeader& parent) {
    auto block = std::make_shared<Block>();
    auto parent_hash = parent.hash();

    // BlockHeader
    block->header.number = parent.number + 1;
    block->header.difficulty = 17'000'000'000 + block->header.number;
    block->header.parent_hash = parent_hash;
    block->header.beneficiary = 0xc8ebccc5f5689fa8659d83713341e5ad19349448_address;
    block->header.state_root = kEmptyRoot;
    block->header.receipts_root = kEmptyRoot;
    block->header.gas_limit = 10'000'000;
    block->header.gas_used = 0;
    block->header.timestamp = parent.timestamp + 12;
    block->header.extra_data = {};

    /*
    // BlockBody: transactions
    block.transactions.resize(1);
    if (block.header.number % 2 == 0) {
        block.transactions[0].nonce = 172339;
        block.transactions[0].max_priority_fee_per_gas = 50 * kGiga;
        block.transactions[0].max_fee_per_gas = 50 * kGiga;
        block.transactions[0].gas_limit = 90'000;
        block.transactions[0].to = 0xe5ef458d37212a06e3f59d40c454e76150ae7c32_address;
        block.transactions[0].value = 1'027'501'080 * kGiga;
        block.transactions[0].data = {};
        CHECK(block.transactions[0].set_v(27));
        block.transactions[0].r = 0x48b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d495a36649353_u256;
        block.transactions[0].s = 0x1fffd310ac743f371de3b9f7f9cb56c0b28ad43601b4ab949f53faa07bd2c804_u256;
    }
    else {
        block.transactions[0].type = TransactionType::kEip1559;
        block.transactions[0].nonce = 1;
        block.transactions[0].max_priority_fee_per_gas = 5 * kGiga;
        block.transactions[0].max_fee_per_gas = 30 * kGiga;
        block.transactions[0].gas_limit = 1'000'000;
        block.transactions[0].to = {};
        block.transactions[0].value = 0;
        block.transactions[0].data = *from_hex("602a6000556101c960015560068060166000396000f3600035600055");
        CHECK(block.transactions[0].set_v(37));
        block.transactions[0].r = 0x52f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afb_u256;
        block.transactions[0].s = 0x52f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afb_u256;
    }

    block.header.transactions_root = protocol::compute_transaction_root(block);

    // BlockBody: ommers
    block.ommers.resize(1);
    block.ommers[0].parent_hash = parent_hash;
    block.ommers[0].ommers_hash = kEmptyListHash;
    block.ommers[0].beneficiary = 0x0c729be7c39543c3d549282a40395299d987cec2_address;
    block.ommers[0].state_root = 0xc2bcdfd012534fa0b19ffba5fae6fc81edd390e9b7d5007d1e92e8e835286e9d_bytes32;

    block.header.ommers_hash = protocol::compute_ommers_hash(block);
    */

    return block;
}

class ExecutionEngine_ForTest : public stagedsync::ExecutionEngine {
  public:
    using stagedsync::ExecutionEngine::ExecutionEngine;
    using stagedsync::ExecutionEngine::forks_;
    using stagedsync::ExecutionEngine::main_chain_;
};

TEST_CASE("ExecutionEngine") {
    test_util::SetLogVerbosityGuard log_guard(log::Level::kNone);

    asio::io_context io;
    asio::executor_work_guard<decltype(io.get_executor())> work{io.get_executor()};

    db::test_util::TempChainData context;
    context.add_genesis_data();
    context.commit_txn();

    PreverifiedHashes::current.clear();                           // disable preverified hashes
    Environment::set_stop_before_stage(db::stages::kSendersKey);  // only headers, block hashes and bodies

    NodeSettings node_settings = node::test_util::make_node_settings_from_temp_chain_data(context);
    db::RWAccess db_access{context.env()};
    ExecutionEngine_ForTest exec_engine{io, node_settings, db_access};
    exec_engine.open();

    auto& tx = exec_engine.main_chain_.tx();  // mdbx refuses to open a ROTxn when there is a RWTxn in the same thread

    auto header0_hash = db::read_canonical_hash(tx, 0);
    REQUIRE(header0_hash.has_value());

    auto header0 = db::read_canonical_header(tx, 0);
    REQUIRE(header0.has_value());

    BlockId block0_id{0, *header0_hash};

    // check db
    BlockBody block0_body;
    const bool block0_present = db::read_body(tx, *header0_hash, block0_id.number, block0_body);
    CHECK(block0_present);

    /* status:
     *         h0
     * input:
     *         h0 <----- h1
     */

    SECTION("one invalid body after the genesis") {
        auto block1 = std::make_shared<Block>();
        block1->header.number = 1;
        block1->header.difficulty = 17'171'480'576;  // a random value
        block1->header.parent_hash = *header0_hash;
        // auto header1_hash = block1.header.hash();
        block1->ommers.push_back(BlockHeader{});  // generate error InvalidOmmerHeader
        auto header1_hash = block1->header.hash();

        // getting initial status
        auto initial_progress = exec_engine.block_progress();
        CHECK(initial_progress == 0);
        auto last_fcu_at_start_time = exec_engine.last_fork_choice();
        CHECK(last_fcu_at_start_time == block0_id);

        // inserting headers & bodies
        exec_engine.insert_block(block1);

        // check db
        BlockBody saved_body;
        const bool block1_present = db::read_body(tx, header1_hash, block1->header.number, saved_body);
        CHECK(block1_present);

        auto progress = exec_engine.block_progress();
        CHECK(progress == 1);

        // verifying the chain
        auto verification = exec_engine.verify_chain(header1_hash).get();

        CHECK(db::stages::read_stage_progress(tx, db::stages::kHeadersKey) == 1);
        CHECK(db::stages::read_stage_progress(tx, db::stages::kBlockHashesKey) == 1);
        CHECK(db::stages::read_stage_progress(tx, db::stages::kBlockBodiesKey) == 1);
        CHECK(db::stages::read_stage_progress(tx, db::stages::kSendersKey) == 0);
        CHECK(db::stages::read_stage_progress(tx, db::stages::kExecutionKey) == 0);

        CHECK(!holds_alternative<ValidationError>(verification));
        REQUIRE(holds_alternative<InvalidChain>(verification));
        auto invalid_chain = std::get<InvalidChain>(verification);

        CHECK(invalid_chain.unwind_point == BlockId{0, *header0_hash});
        CHECK(invalid_chain.bad_block.has_value());
        CHECK(invalid_chain.bad_block.value() == header1_hash);
        CHECK(invalid_chain.bad_headers.size() == 1);
        CHECK(*(invalid_chain.bad_headers.begin()) == header1_hash);

        // check status
        auto final_progress = exec_engine.block_progress();
        CHECK(final_progress == block1->header.number);
        CHECK(exec_engine.last_fork_choice() == last_fcu_at_start_time);  // not changed

        auto present_in_canonical = exec_engine.is_canonical(header1_hash);
        CHECK(!present_in_canonical);

        // reverting the chain
        bool updated = exec_engine.notify_fork_choice_update(*header0_hash);
        CHECK(updated);

        CHECK(exec_engine.last_fork_choice() == last_fcu_at_start_time);  // not changed

        present_in_canonical = exec_engine.is_canonical(header1_hash);
        CHECK(!present_in_canonical);
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

        auto block1 = std::make_shared<Block>();
        ByteView encoded_view = encoded_header1.value();
        auto decoding_result = rlp::decode(encoded_view, block1->header);
        // Note: block1 has zero transactions and zero ommers on mainnet
        REQUIRE(decoding_result);
        auto block1_hash = block1->header.hash();
        BlockId block1_id{1, block1_hash};

        // getting initial status
        auto initial_progress = exec_engine.block_progress();
        CHECK(initial_progress == 0);
        auto last_fcu_at_start_time = exec_engine.last_fork_choice();
        CHECK(last_fcu_at_start_time == block0_id);

        // inserting & verifying the block
        exec_engine.insert_block(block1);
        auto verification = exec_engine.verify_chain(block1_hash).get();

        REQUIRE(holds_alternative<ValidChain>(verification));
        auto valid_chain = std::get<ValidChain>(verification);
        CHECK(valid_chain.current_head == block1_id);

        // check status
        auto final_progress = exec_engine.block_progress();
        CHECK(final_progress == block1->header.number);
        CHECK(exec_engine.last_fork_choice() == last_fcu_at_start_time);  // not changed

        // check db content
        BlockBody saved_body;
        bool present = db::read_body(tx, block1_hash, block1->header.number, saved_body);
        CHECK(present);

        auto present_in_canonical = exec_engine.is_canonical(block1_hash);
        CHECK(!present_in_canonical);  // the current head is not yet accepted

        // confirming the chain
        exec_engine.notify_fork_choice_update(block1_hash, header0_hash);

        // checking the status
        CHECK(exec_engine.last_fork_choice() == block1_id);
        CHECK(exec_engine.last_finalized_block() == block0_id);

        present_in_canonical = exec_engine.is_canonical(block1_hash);
        CHECK(present_in_canonical);
    }

    SECTION("a block that creates a fork") {
        auto block1 = generateSampleChildrenBlock(*header0);
        auto block1_hash = block1->header.hash();

        auto block2 = generateSampleChildrenBlock(block1->header);
        auto block2_hash = block2->header.hash();

        auto block3 = generateSampleChildrenBlock(block2->header);
        auto block3_hash = block3->header.hash();

        // inserting & verifying the block
        exec_engine.insert_block(block1);
        exec_engine.insert_block(block2);
        exec_engine.insert_block(block3);
        auto verification = exec_engine.verify_chain(block3_hash).get();

        REQUIRE(holds_alternative<ValidChain>(verification));
        auto valid_chain = std::get<ValidChain>(verification);
        CHECK(valid_chain.current_head == BlockId{3, block3_hash});

        // confirming the chain
        auto fcu_updated = exec_engine.notify_fork_choice_update(block3_hash, block1_hash);
        CHECK(fcu_updated);

        CHECK(exec_engine.last_fork_choice() == BlockId{3, block3_hash});
        CHECK(exec_engine.last_finalized_block() == BlockId{1, block1_hash});

        CHECK(exec_engine.get_canonical_hash(2) == block2_hash);
        CHECK(exec_engine.get_canonical_header(2).has_value());
        CHECK(exec_engine.get_canonical_hash(3) == block3_hash);
        CHECK(exec_engine.get_canonical_header(3).has_value());

        auto [head_height, head_hash] = db::read_canonical_head(tx);
        CHECK(head_height == 3);
        CHECK(head_hash == block3_hash);

        // creating and reintegrating a fork
        auto block4 = generateSampleChildrenBlock(block3->header);
        auto block4_hash = block4->header.hash();
        {
            // inserting & verifying the block
            exec_engine.insert_block(block4);
            verification = exec_engine.verify_chain(block4_hash).get();

            REQUIRE(holds_alternative<ValidChain>(verification));
            valid_chain = std::get<ValidChain>(verification);
            CHECK(valid_chain.current_head == BlockId{4, block4_hash});

            // confirming the chain (i.e. flushing the memory mutation on the main db)
            fcu_updated = exec_engine.notify_fork_choice_update(block4_hash, block1_hash);
            CHECK(fcu_updated);

            CHECK(exec_engine.last_fork_choice() == BlockId{4, block4_hash});
            CHECK(exec_engine.last_finalized_block() == BlockId{1, block1_hash});

            CHECK(exec_engine.get_canonical_hash(2) == block2_hash);
            CHECK(exec_engine.get_canonical_header(2).has_value());
            CHECK(exec_engine.get_canonical_hash(3) == block3_hash);
            CHECK(exec_engine.get_canonical_header(3).has_value());
            CHECK(exec_engine.get_canonical_hash(4) == block4_hash);
            CHECK(exec_engine.get_canonical_header(4).has_value());

            std::tie(head_height, head_hash) = db::read_canonical_head(tx);
            CHECK(head_height == 4);
            CHECK(head_hash == block4_hash);
        }

        // creating a fork and changing the head (trigger unwind)
        auto block2b = generateSampleChildrenBlock(block1->header);
        block2b->header.extra_data = string_view_to_byte_view("I'm different");  // to make it different from block2
        auto block2b_hash = block2b->header.hash();
        {
            // inserting & verifying the block
            exec_engine.insert_block(block2b);
            verification = exec_engine.verify_chain(block2b_hash).get();

            REQUIRE(holds_alternative<ValidChain>(verification));
            valid_chain = std::get<ValidChain>(verification);
            CHECK(valid_chain.current_head == BlockId{2, block2b_hash});

            // confirming the chain
            fcu_updated = exec_engine.notify_fork_choice_update(block2b_hash, header0_hash);
            CHECK(fcu_updated);

            CHECK(exec_engine.last_fork_choice() == BlockId{2, block2b_hash});
            CHECK(exec_engine.last_finalized_block() == block0_id);
            CHECK(exec_engine.main_chain_.last_chosen_head() == BlockId{2, block2b_hash});

            CHECK(exec_engine.get_canonical_hash(2) == block2b_hash);
            CHECK(exec_engine.get_canonical_header(2).has_value());
            CHECK(not exec_engine.get_canonical_header(3).has_value());
            CHECK(not exec_engine.get_canonical_header(4).has_value());

            std::tie(head_height, head_hash) = db::read_canonical_head(tx);
            CHECK(head_height == 2);
            CHECK(head_hash == block2b_hash);
        }

        CHECK(exec_engine.get_header(block2b_hash).has_value());  // we do not remove old blocks
        CHECK(exec_engine.get_header(block2_hash).has_value());   // we do not remove old blocks
        CHECK(exec_engine.get_header(block3_hash).has_value());   // we do not remove old blocks
        CHECK(exec_engine.get_header(block4_hash).has_value());   // we do not remove old blocks
    }
}

}  // namespace silkworm
