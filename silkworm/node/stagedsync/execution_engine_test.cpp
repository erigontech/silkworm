
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

#include "execution_engine.hpp"

#include <iostream>

#include <boost/asio/io_context.hpp>
#include <catch2/catch.hpp>

#include <silkworm/core/types/block.hpp>
#include <silkworm/infra/common/environment.hpp>
#include <silkworm/infra/test/log.hpp>
#include <silkworm/node/common/preverified_hashes.hpp>
#include <silkworm/node/db/genesis.hpp>
#include <silkworm/node/db/stages.hpp>
#include <silkworm/node/test/context.hpp>

namespace silkworm {

class ExecutionEngine_ForTest : public stagedsync::ExecutionEngine {
  public:
    using stagedsync::ExecutionEngine::ExecutionEngine;
    using stagedsync::ExecutionEngine::forks_;
    using stagedsync::ExecutionEngine::main_chain_;
    using stagedsync::ExecutionEngine::tx_;
};

namespace asio = boost::asio;
using namespace stagedsync;

TEST_CASE("MainChain") {
    test::SetLogVerbosityGuard log_guard(log::Level::kNone);

    asio::io_context io;
    asio::executor_work_guard<decltype(io.get_executor())> work{io.get_executor()};

    test::Context context;
    context.add_genesis_data();
    context.commit_txn();

    PreverifiedHashes::current.clear();                           // disable preverified hashes
    Environment::set_stop_before_stage(db::stages::kSendersKey);  // only headers, block hashes and bodies

    db::RWAccess db_access{context.env()};
    ExecutionEngine_ForTest exec_engine{io, context.node_settings(), db_access};
    exec_engine.open();

    auto& tx = exec_engine.tx_;  // mdbx refuses to open a ROTxn when there is a RWTxn in the same thread

    /* status:
     *         h0
     * input:
     *         h0 <----- h1
     */

    SECTION("one invalid body after the genesis") {
        auto header0_hash = db::read_canonical_hash(tx, 0);
        REQUIRE(header0_hash.has_value());

        auto header0 = db::read_canonical_header(tx, 0);
        REQUIRE(header0.has_value());

        auto block1 = std::make_shared<Block>();
        block1->header.number = 1;
        block1->header.difficulty = 17'171'480'576;  // a random value
        block1->header.parent_hash = *header0_hash;
        // auto header1_hash = block1.header.hash();
        block1->ommers.push_back(BlockHeader{});  // generate error InvalidOmmerHeader
        auto header1_hash = block1->header.hash();

        // getting initial status
        auto initial_progress = exec_engine.block_progress();
        REQUIRE(initial_progress == 0);
        auto initial_canonical_head = exec_engine.main_chain_.canonical_head();
        auto last_fcu_at_start_time = exec_engine.last_fork_choice();

        // inserting headers & bodies
        exec_engine.insert_block(block1);

        // check db
        BlockBody saved_body;
        bool present = db::read_body(tx, header1_hash, block1->header.number, saved_body);
        REQUIRE(present);

        auto progress = exec_engine.block_progress();
        REQUIRE(progress == 1);

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

        REQUIRE(invalid_chain.unwind_point == BlockId{0, *header0_hash});
        REQUIRE(invalid_chain.bad_block.has_value());
        REQUIRE(invalid_chain.bad_block.value() == header1_hash);
        REQUIRE(invalid_chain.bad_headers.size() == 1);
        REQUIRE(*(invalid_chain.bad_headers.begin()) == header1_hash);

        // check status
        auto final_progress = exec_engine.block_progress();
        REQUIRE(final_progress == block1->header.number);

        auto final_canonical_head = exec_engine.main_chain_.canonical_head();
        REQUIRE(final_canonical_head.number == block1->header.number);
        REQUIRE(final_canonical_head.hash == block1->header.hash());

        // reverting the chain
        exec_engine.notify_fork_choice_update(*header0_hash);

        // checking the status
        // auto present_in_canonical = exec_engine.is_canonical_hash(header1_hash);
        // REQUIRE(!present_in_canonical);

        final_canonical_head = exec_engine.main_chain_.canonical_head();
        REQUIRE(final_canonical_head == initial_canonical_head);

        REQUIRE(last_fcu_at_start_time == exec_engine.last_fork_choice());
    }

    SECTION("one valid body after the genesis") {
        auto block0_hash = db::read_canonical_hash(tx, 0);
        REQUIRE(block0_hash.has_value());

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

        auto block1 = std::make_shared<Block>();
        ByteView encoded_view = encoded_header1.value();
        auto decoding_result = rlp::decode(encoded_view, block1->header);
        // Note: block1 has zero transactions and zero ommers on mainnet
        REQUIRE(decoding_result);
        auto block1_hash = block1->header.hash();

        // getting initial status
        auto initial_progress = exec_engine.block_progress();
        REQUIRE(initial_progress == 0);

        auto initial_canonical_head = exec_engine.main_chain_.canonical_head();
        REQUIRE(initial_canonical_head.number == 0);
        REQUIRE(initial_canonical_head.hash == *block0_hash);

        REQUIRE(initial_canonical_head.number == initial_progress);

        // inserting & verifying the block
        exec_engine.insert_block(block1);
        auto verification = exec_engine.verify_chain(block1_hash).get();

        REQUIRE(holds_alternative<ValidChain>(verification));
        auto valid_chain = std::get<ValidChain>(verification);
        REQUIRE(valid_chain.current_head == BlockId{1, block1_hash});

        // check status
        auto final_canonical_head = exec_engine.main_chain_.canonical_head();
        REQUIRE(final_canonical_head.number == block1->header.number);
        REQUIRE(final_canonical_head.hash == block1_hash);

        // check db content
        BlockBody saved_body;
        bool present = db::read_body(tx, block1_hash, block1->header.number, saved_body);
        REQUIRE(present);

        // auto present_in_canonical = exec_engine.is_canonical_hash(block1.header.number);
        // REQUIRE(present_in_canonical);

        // confirming the chain
        exec_engine.notify_fork_choice_update(block1_hash, block0_hash);

        // checking the status
        // present_in_canonical = exec_engine.is_canonical_hash(block1.header.number);
        // REQUIRE(present_in_canonical);

        final_canonical_head = exec_engine.main_chain_.canonical_head();
        REQUIRE(final_canonical_head.number == block1->header.number);
        REQUIRE(final_canonical_head.hash == block1_hash);

        REQUIRE(exec_engine.last_fork_choice() == BlockId{block1->header.number, block1_hash});
        REQUIRE(exec_engine.last_finalized_block() == BlockId{0, *block0_hash});
    }

    // todo: add tests on fork management
}

}  // namespace silkworm
