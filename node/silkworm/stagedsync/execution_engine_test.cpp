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

#include "silkworm/stagedsync/execution_engine.hpp"

#include <iostream>

#include <catch2/catch.hpp>

#include <silkworm/common/environment.hpp>
#include <silkworm/common/test_context.hpp>
#include <silkworm/db/genesis.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/test/log.hpp>
#include <silkworm/types/block.hpp>

namespace silkworm {

class ExecutionEngine_ForTest : public stagedsync::ExecutionEngine {
  public:
    using stagedsync::ExecutionEngine::canonical_chain_;
    using stagedsync::ExecutionEngine::pipeline_;
    using stagedsync::ExecutionEngine::CanonicalChain;
    using stagedsync::ExecutionEngine::ExecutionEngine;
    using stagedsync::ExecutionEngine::tx_;
};

TEST_CASE("ExecutionEngine") {
    test::SetLogVerbosityGuard log_guard(log::Level::kNone);

    test::Context context;
    context.add_genesis_data();
    context.commit_txn();

    Environment::set_pre_verified_hashes_disabled();

    db::RWAccess db_access{context.env()};
    ExecutionEngine_ForTest execution_engine{context.node_settings(), db_access};

    auto& tx = execution_engine.tx_;  // mdbx refuses to open a ROTxn when there is a RWTxn in the same thread

    using ValidChain = stagedsync::ExecutionEngine::ValidChain;
    using InvalidChain = stagedsync::ExecutionEngine::InvalidChain;

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

        Block block1;
        block1.header.number = 1;
        block1.header.difficulty = 17'171'480'576;  // a random value
        block1.header.parent_hash = *header0_hash;
        //auto header1_hash = block1.header.hash();
        block1.ommers.push_back(BlockHeader{});  // generate error InvalidOmmerHeader

        // getting initial status
        auto [initial_headers_head_height, initial_headers_head_hash, initial_headers_head_td] =
            execution_engine.get_headers_head();
        REQUIRE(initial_headers_head_height == 0);
        REQUIRE(initial_headers_head_hash == *header0_hash);
        REQUIRE(initial_headers_head_td == header0->difficulty);

        auto [initial_bodies_head_height, initial_head_bodies_hash] =
            execution_engine.get_bodies_head();
        REQUIRE(initial_bodies_head_height == 0);
        REQUIRE(initial_head_bodies_hash == *header0_hash);

        auto initial_canonical_head = execution_engine.get_canonical_head();
        REQUIRE(initial_canonical_head == std::tuple(initial_headers_head_height, initial_headers_head_hash));
        REQUIRE(execution_engine.canonical_chain_.current_head().number == initial_headers_head_height);
        REQUIRE(execution_engine.canonical_chain_.current_head().hash == initial_headers_head_hash);

        // inserting headers
        execution_engine.insert_header(block1.header);

        auto [final_headers_head_height, final_headers_head_hash, final_headers_head_td] =
            execution_engine.get_headers_head();
        REQUIRE(final_headers_head_height == 0);  // doesn't change
        REQUIRE(final_headers_head_hash == *header0_hash);  // doesn't change
        REQUIRE(final_headers_head_td == header0->difficulty);

        // inserting bodies
        execution_engine.insert_body(block1);

        auto [final_bodies_head_height, final_head_bodies_hash] = execution_engine.get_bodies_head();
        REQUIRE(final_bodies_head_height == 0);
        REQUIRE(final_head_bodies_hash == *header0_hash);

        // verifying the chain
        auto verification = execution_engine.verify_chain(block1.header.hash());

        REQUIRE(holds_alternative<InvalidChain>(verification));
        auto invalid_chain = std::get<InvalidChain>(verification);

        REQUIRE(invalid_chain.unwind_point == 0);
        REQUIRE(invalid_chain.unwind_head == header0_hash);
        REQUIRE(invalid_chain.bad_block.has_value());
        REQUIRE(invalid_chain.bad_block.value() == block1.header.hash());
        REQUIRE(invalid_chain.bad_headers.size() == 1);
        REQUIRE(*(invalid_chain.bad_headers.begin()) == block1.header.hash());

        // check status
        std::tie(final_headers_head_height, final_headers_head_hash, final_headers_head_td) =
            execution_engine.get_headers_head();
        REQUIRE(final_headers_head_height == block1.header.number);
        REQUIRE(final_headers_head_hash == block1.header.hash());
        REQUIRE(final_headers_head_td > initial_headers_head_td);

        std::tie(final_bodies_head_height, final_head_bodies_hash) = execution_engine.get_bodies_head();
        REQUIRE(final_bodies_head_height == block1.header.number);
        REQUIRE(final_head_bodies_hash == block1.header.hash());

        auto final_canonical_head = execution_engine.get_canonical_head();
        REQUIRE(final_canonical_head == std::tuple(block1.header.number, block1.header.hash()));
        REQUIRE(execution_engine.canonical_chain_.current_head().number == block1.header.number);
        REQUIRE(execution_engine.canonical_chain_.current_head().hash == block1.header.hash());

        auto current_status = execution_engine.current_status();
        REQUIRE(holds_alternative<InvalidChain>(current_status));

        // check db content
        BlockBody saved_body;
        bool present = db::read_body(tx, block1.header.hash(), block1.header.number, saved_body);
        REQUIRE(present);

        auto present_in_canonical = execution_engine.get_canonical_hash(block1.header.number);
        REQUIRE(present_in_canonical);

        // reverting the chain
        execution_engine.notify_fork_choice_updated(*header0_hash);

        // checking the status
        present_in_canonical = execution_engine.get_canonical_hash(block1.header.number);
        REQUIRE(!present_in_canonical);

        final_canonical_head = execution_engine.get_canonical_head();
        REQUIRE(final_canonical_head == initial_canonical_head);
        REQUIRE(execution_engine.canonical_chain_.current_head().number == initial_headers_head_height);
        REQUIRE(execution_engine.canonical_chain_.current_head().hash == initial_headers_head_hash);

        current_status = execution_engine.current_status();
        REQUIRE(holds_alternative<ValidChain>(current_status));
        REQUIRE(std::get<ValidChain>(current_status).current_point == 0);
    }

    SECTION("one valid body after the genesis") {

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

        // getting initial status
        auto [initial_headers_head_height, initial_headers_head_hash, initial_headers_head_td] =
            execution_engine.get_headers_head();
        REQUIRE(initial_headers_head_height == 0);
        REQUIRE(initial_headers_head_hash == *header0_hash);
        REQUIRE(initial_headers_head_td == header0->difficulty);

        auto [initial_bodies_head_height, initial_head_bodies_hash] =
            execution_engine.get_bodies_head();
        REQUIRE(initial_bodies_head_height == 0);
        REQUIRE(initial_head_bodies_hash == *header0_hash);

        auto initial_canonical_head = execution_engine.get_canonical_head();
        REQUIRE(initial_canonical_head == std::tuple(initial_headers_head_height, initial_headers_head_hash));
        REQUIRE(execution_engine.canonical_chain_.current_head().number == initial_headers_head_height);
        REQUIRE(execution_engine.canonical_chain_.current_head().hash == initial_headers_head_hash);

        // inserting & verifying the block
        execution_engine.insert_header(block1.header);
        execution_engine.insert_body(block1);
        auto verification = execution_engine.verify_chain(block1.header.hash());

        REQUIRE(holds_alternative<ValidChain>(verification));
        auto valid_chain = std::get<ValidChain>(verification);
        REQUIRE(valid_chain.current_point == 1);

        // check status
        REQUIRE(execution_engine.pipeline_.head_header_number() == block1.header.number);
        REQUIRE(execution_engine.pipeline_.head_header_hash() == block1.header.hash());

        auto [final_headers_head_height, final_headers_head_hash, final_headers_head_td] =
            execution_engine.get_headers_head();
        REQUIRE(final_headers_head_height == block1.header.number);
        REQUIRE(final_headers_head_hash == block1.header.hash());
        REQUIRE(final_headers_head_td > initial_headers_head_td);

        auto [final_bodies_head_height, final_head_bodies_hash] = execution_engine.get_bodies_head();
        REQUIRE(final_bodies_head_height == block1.header.number);
        REQUIRE(final_head_bodies_hash == block1.header.hash());

        auto final_canonical_head = execution_engine.get_canonical_head();
        REQUIRE(final_canonical_head == std::tuple(block1.header.number, block1.header.hash()));
        REQUIRE(execution_engine.canonical_chain_.current_head().number == block1.header.number);
        REQUIRE(execution_engine.canonical_chain_.current_head().hash == block1.header.hash());

        auto current_status = execution_engine.current_status();
        REQUIRE(holds_alternative<ValidChain>(current_status));
        REQUIRE(std::get<ValidChain>(current_status).current_point == 1);

        // check db content
        BlockBody saved_body;
        bool present = db::read_body(tx, block1.header.hash(), block1.header.number, saved_body);
        REQUIRE(present);

        auto present_in_canonical = execution_engine.get_canonical_hash(block1.header.number);
        REQUIRE(present_in_canonical);

        // confirming the chain
        execution_engine.notify_fork_choice_updated(block1.header.hash());

        // checking the status
        present_in_canonical = execution_engine.get_canonical_hash(block1.header.number);
        REQUIRE(present_in_canonical);

        final_canonical_head = execution_engine.get_canonical_head();
        REQUIRE(final_canonical_head == std::tuple(block1.header.number, block1.header.hash()));
        REQUIRE(execution_engine.canonical_chain_.current_head().number == block1.header.number);
        REQUIRE(execution_engine.canonical_chain_.current_head().hash == block1.header.hash());
    }
}

}  // namespace silkworm
