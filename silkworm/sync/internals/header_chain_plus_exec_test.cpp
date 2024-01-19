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

#include <algorithm>

#include <boost/asio/io_context.hpp>
#include <catch2/catch.hpp>

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/protocol/rule_set.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/infra/common/environment.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/node/db/genesis.hpp>
#include <silkworm/node/db/test_util/temp_chain_data.hpp>
#include <silkworm/node/stagedsync/execution_engine.hpp>
#include <silkworm/node/test_util/temp_chain_data_node_settings.hpp>

#include "chain_fork_view.hpp"
#include "header_chain.hpp"

namespace silkworm {

using namespace stagedsync;
namespace asio = boost::asio;

class HeaderChainForTest : public HeaderChain {
  public:  // publication of internal members to test methods functioning
    using HeaderChain::generate_request_id;
    using HeaderChain::HeaderChain;
};

class ExecutionEngine_ForTest : public stagedsync::ExecutionEngine {
  public:
    using stagedsync::ExecutionEngine::ExecutionEngine;
    using stagedsync::ExecutionEngine::insert_block;
    using stagedsync::ExecutionEngine::main_chain_;
};

class DummyRuleSet : public protocol::IRuleSet {
  public:
    ValidationResult pre_validate_block_body(const Block&, const BlockState&) override { return ValidationResult::kOk; }

    ValidationResult validate_ommers(const Block&, const BlockState&) override { return ValidationResult::kOk; }

    ValidationResult validate_block_header(const BlockHeader&, const BlockState&, bool) override { return ValidationResult::kOk; }

    void initialize(EVM&) override {}

    void finalize(IntraBlockState&, const Block&) override {}

    protocol::BlockReward compute_reward(const Block&) override { return {0, {}}; }

    evmc::address get_beneficiary(const BlockHeader&) override { return {}; }

    void add_fee_transfer_log(IntraBlockState&, const intx::uint256&, const evmc::address&, const intx::uint256&,
                              const evmc::address&, const intx::uint256&) override {}
};

TEST_CASE("Headers receiving and saving") {
    test_util::SetLogVerbosityGuard log_guard(log::Level::kNone);

    asio::io_context io;
    asio::executor_work_guard<decltype(io.get_executor())> work{io.get_executor()};

    db::test_util::TempChainData context;
    context.add_genesis_data();
    context.commit_txn();

    PreverifiedHashes::current.clear();  // we need to skip header/block verification because we use fake blocks

    NodeSettings node_settings = node::test_util::make_node_settings_from_temp_chain_data(context);
    db::RWAccess db_access{context.env()};

    // creating the ExecutionEngine
    ExecutionEngine_ForTest exec_engine{io, node_settings, db_access};
    exec_engine.open();

    auto& tx = exec_engine.main_chain_.tx();  // mdbx refuses to open a ROTxn when there is a RWTxn in the same thread

    auto head = exec_engine.last_fork_choice();
    REQUIRE(height(head) == 0);

    std::vector<BlockHeader> last_headers = exec_engine.get_last_headers(1);
    REQUIRE(last_headers.size() == 1);
    REQUIRE(last_headers[0].number == head.number);
    REQUIRE(last_headers[0].hash() == head.hash);

    // creating the working chain to simulate a bit of the sync
    BlockNum highest_in_db = 0;
    HeaderChainForTest header_chain(std::make_unique<DummyRuleSet>());
    header_chain.initial_state(last_headers);
    header_chain.current_state(highest_in_db);
    auto request_id = header_chain.generate_request_id();

    // reading genesis
    auto header0 = db::read_canonical_header(tx, 0);
    REQUIRE(header0.has_value());
    auto header0_hash = header0->hash();

    auto td = db::read_total_difficulty(tx, 0, header0_hash);
    REQUIRE(td.has_value());

    // creating the chain-fork-view to simulate a bit of the HeaderStage
    chainsync::ChainForkView chain_fork_view{{header0->number, header0_hash, *td}};
    CHECK(chain_fork_view.head() == head);

    chain_fork_view.add(*header0, *td);
    CHECK(chain_fork_view.head() == head);

    chain_fork_view.reset_head({header0->number, header0_hash, *td});
    CHECK(chain_fork_view.head() == head);

    // stop execution pipeline at early stages because we use dummy headers without bodies
    Environment::set_stop_before_stage(db::stages::kBlockHashesKey);

    /* status:
     *         h0 (persisted)
     * input:
     *        (h0) <----- h1 <----- h2
     *                |-- h1'
     */
    SECTION("accepting 1 batch of headers") {
        // testing initial status
        auto initial_height = chain_fork_view.head_height();
        auto initial_hash = chain_fork_view.head_hash();
        REQUIRE(initial_height == 0);
        REQUIRE(initial_hash == header0_hash);

        // receiving 3 headers from a peer
        BlockHeader header1;
        header1.number = 1;
        header1.difficulty = 1'000'000;
        // header1.gas_limit = 5000;
        // header1.timestamp = ++timestamp;
        // header1.difficulty = EthashEngine::difficulty(header1.number, header1.timestamp, header0->difficulty,
        // header0->timestamp, false, kMainnetIdentity.config);
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
        header1b.gas_limit = 5000;
        header1b.parent_hash = header0_hash;
        header1b.extra_data = string_view_to_byte_view("I'm different");
        auto header1b_hash = header1b.hash();

        // processing the headers
        std::vector<BlockHeader> headers = {header1, header2, header1b};
        PeerId peer_id{byte_ptr_cast("1")};
        header_chain.accept_headers(headers, request_id, peer_id);

        // saving headers ready to persist as the header sync does in the forward() method
        Headers headers_to_persist = header_chain.withdraw_stable_headers();

        std::ranges::for_each(headers_to_persist, [&](const auto& header) {
            chain_fork_view.add(*header);
            auto fake_block = std::make_shared<Block>(Block{{}, *header});
            exec_engine.insert_block(fake_block);
        });

        // check internal status
        BigInt expected_td = header0->difficulty + header1.difficulty + header2.difficulty;

        REQUIRE(headers_to_persist.size() == 3);
        REQUIRE(chain_fork_view.head_total_difficulty() == expected_td);
        REQUIRE(chain_fork_view.head_changed() == true);
        REQUIRE(chain_fork_view.head_height() == 2);
        REQUIRE(chain_fork_view.head_hash() == header2_hash);

        // check db content
        auto header1_in_db = db::read_header(tx, header1_hash);
        REQUIRE(header1_in_db.has_value());
        REQUIRE(header1_in_db == header1);
        auto header2_in_db = db::read_header(tx, header2_hash);
        REQUIRE(header2_in_db.has_value());
        REQUIRE(header2_in_db == header2);
        auto header1b_in_db = db::read_header(tx, header1b_hash);
        REQUIRE(header1b_in_db.has_value());
        REQUIRE(header1b_in_db == header1b);

        // verify the inserted chain
        auto verification = exec_engine.verify_chain(chain_fork_view.head_hash()).get();
        REQUIRE(std::holds_alternative<ValidChain>(verification));
        auto valid_chain = std::get<ValidChain>(verification);
        REQUIRE(valid_chain.current_head == BlockId{2, header2_hash});

        // check db content
        REQUIRE(db::read_head_header_hash(tx) == header2_hash);
        REQUIRE(db::read_canonical_head(tx) == std::make_tuple(2, header2_hash));

        REQUIRE(db::read_total_difficulty(tx, 2, header2.hash()) == expected_td);

        REQUIRE(db::read_canonical_hash(tx, 1) == header1_hash);
        REQUIRE(db::read_canonical_hash(tx, 2) == header2_hash);

        // update the fork choice
        exec_engine.notify_fork_choice_update(header2_hash);

        // check db content
        REQUIRE(db::read_head_header_hash(tx) == header2_hash);
        REQUIRE(db::read_canonical_head(tx) == std::make_tuple(2, header2_hash));
    }

    /* status:
     *         h0 (persisted)
     * input 1:
     *        (h0) <----- h1 <------ h2
     * input 2:
     *        (h0) <----- h1'
     * final status:
     *         h0 <------ h1 <----- h2
     *               |--- h1'
     */
    SECTION("accepting 2 batch of headers, the second not changing the canonical") {
        // receiving 2 headers from a peer
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

        // processing the headers
        std::vector<BlockHeader> headers = {header1, header2};
        PeerId peer_id{byte_ptr_cast("1")};
        header_chain.accept_headers(headers, request_id, peer_id);

        // saving headers ready to persist as the header sync does in the forward() method
        Headers headers_to_persist = header_chain.withdraw_stable_headers();

        std::ranges::for_each(headers_to_persist, [&](const auto& header) {
            chain_fork_view.add(*header);
            auto fake_block = std::make_shared<Block>(Block{{}, *header});
            exec_engine.insert_block(fake_block);
        });

        // check internal status
        BigInt expected_td = header0->difficulty + header1.difficulty + header2.difficulty;

        REQUIRE(chain_fork_view.head_total_difficulty() == expected_td);
        REQUIRE(chain_fork_view.head_changed() == true);
        REQUIRE(chain_fork_view.head_height() == 2);
        REQUIRE(chain_fork_view.head_hash() == header2_hash);

        // check db content
        auto header1_in_db = db::read_header(tx, header1_hash);
        REQUIRE(header1_in_db.has_value());
        REQUIRE(header1_in_db == header1);
        auto header2_in_db = db::read_header(tx, header2_hash);
        REQUIRE(header2_in_db.has_value());
        REQUIRE(header2_in_db == header2);

        // verify the inserted chain
        auto verification = exec_engine.verify_chain(chain_fork_view.head_hash()).get();
        REQUIRE(std::holds_alternative<ValidChain>(verification));
        auto valid_chain = std::get<ValidChain>(verification);
        REQUIRE(valid_chain.current_head == BlockId{2, header2_hash});

        // check db content
        REQUIRE(db::read_head_header_hash(tx) == header2_hash);
        REQUIRE(db::read_total_difficulty(tx, 2, header2.hash()) == expected_td);

        // receiving a new header that is a fork
        BlockHeader header1b;
        header1b.number = 1;
        header1b.difficulty = 2'000'000;
        header1b.parent_hash = header0_hash;
        header1b.extra_data = string_view_to_byte_view("I'm different");
        auto header1b_hash = header1b.hash();

        std::vector<BlockHeader> headers_bis = {header1b};
        peer_id = byte_ptr_cast("2");
        header_chain.accept_headers(headers_bis, request_id, peer_id);

        // saving headers ready to persist as the header sync does in the forward() method
        Headers headers_to_persist_bis = header_chain.withdraw_stable_headers();

        std::ranges::for_each(headers_to_persist_bis, [&](const auto& header) {
            auto fake_block = std::make_shared<Block>(Block{{}, *header});
            exec_engine.insert_block(fake_block);
        });

        // status and db content must be as before because the new header is not in the canonical chain
        REQUIRE(chain_fork_view.head_total_difficulty() == expected_td);
        REQUIRE(chain_fork_view.head_changed() == true);
        REQUIRE(chain_fork_view.head_height() == 2);
        REQUIRE(chain_fork_view.head_hash() == header2_hash);

        // check db content
        auto header1b_in_db = db::read_header(tx, header1b_hash);
        REQUIRE(header1b_in_db.has_value());
        REQUIRE(header1b_in_db == header1b);

        // verify the inserted chain
        verification = exec_engine.verify_chain(chain_fork_view.head_hash()).get();
        REQUIRE(std::holds_alternative<ValidChain>(verification));
        valid_chain = std::get<ValidChain>(verification);
        REQUIRE(valid_chain.current_head == BlockId{2, header2_hash});

        // check db content
        REQUIRE(db::read_head_header_hash(tx) == header2_hash);
        REQUIRE(db::read_canonical_head(tx) == std::make_tuple(2, header2_hash));

        REQUIRE(db::read_total_difficulty(tx, 2, header2.hash()) == expected_td);

        REQUIRE(db::read_canonical_hash(tx, 1) == header1_hash);
        REQUIRE(db::read_canonical_hash(tx, 2) == header2_hash);

        // update the fork choice
        exec_engine.notify_fork_choice_update(header2_hash);

        // check db content
        REQUIRE(db::read_head_header_hash(tx) == header2_hash);
        REQUIRE(db::read_canonical_head(tx) == std::make_tuple(2, header2_hash));
    }

    /* status:
     *         h0 (persisted)
     * input 1:
     *        (h0) <----- h1 <------ h2
     * input 2:
     *        (h0) <----- h1'             (td > h2)
     * final status:
     *         h0 <------ h1 <----- h2
     *               |--- h1'             (canonical chain)
     */
    SECTION("accepting 2 batch of headers, the second changing the canonical") {
        // receiving 2 headers from a peer
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

        // processing the headers
        std::vector<BlockHeader> headers = {header1, header2};
        PeerId peer_id{byte_ptr_cast("1")};
        header_chain.accept_headers(headers, request_id, peer_id);

        // saving headers ready to persist as the header sync does in the forward() method
        Headers headers_to_persist = header_chain.withdraw_stable_headers();

        std::ranges::for_each(headers_to_persist, [&](const auto& header) {
            chain_fork_view.add(*header);
            auto fake_block = std::make_shared<Block>(Block{{}, *header});
            exec_engine.insert_block(fake_block);
        });

        // check internal status
        BigInt expected_td = header0->difficulty + header1.difficulty + header2.difficulty;

        REQUIRE(chain_fork_view.head_total_difficulty() == expected_td);
        REQUIRE(chain_fork_view.head_changed() == true);
        REQUIRE(chain_fork_view.head_height() == 2);
        REQUIRE(chain_fork_view.head_hash() == header2_hash);

        // check db content
        auto header1_in_db = db::read_header(tx, header1_hash);
        REQUIRE(header1_in_db.has_value());
        REQUIRE(header1_in_db == header1);
        auto header2_in_db = db::read_header(tx, header2_hash);
        REQUIRE(header2_in_db.has_value());
        REQUIRE(header2_in_db == header2);

        // verify the inserted chain
        auto verification = exec_engine.verify_chain(chain_fork_view.head_hash()).get();
        REQUIRE(std::holds_alternative<ValidChain>(verification));
        auto valid_chain = std::get<ValidChain>(verification);
        REQUIRE(valid_chain.current_head == BlockId{2, header2_hash});

        // check db content
        REQUIRE(db::read_head_header_hash(tx) == header2_hash);
        REQUIRE(db::read_total_difficulty(tx, 2, header2.hash()) == expected_td);

        // receiving a new header that is a fork
        BlockHeader header1b;
        header1b.number = 1;
        header1b.difficulty = 3'000'000;
        header1b.parent_hash = header0_hash;
        header1b.extra_data = string_view_to_byte_view("I'm different");
        auto header1b_hash = header1b.hash();

        std::vector<BlockHeader> headers_bis = {header1b};
        peer_id = byte_ptr_cast("2");
        header_chain.accept_headers(headers_bis, request_id, peer_id);

        // saving headers ready to persist as the header sync does in the forward() method
        Headers headers_to_persist_bis = header_chain.withdraw_stable_headers();

        std::ranges::for_each(headers_to_persist_bis, [&](const auto& header) {
            chain_fork_view.add(*header);
            auto fake_block = std::make_shared<Block>(Block{{}, *header});
            exec_engine.insert_block(fake_block);
        });

        // the canonical is changed, check the new status
        auto new_expected_td = header0->difficulty + header1b.difficulty;

        REQUIRE(chain_fork_view.head_total_difficulty() == new_expected_td);
        REQUIRE(chain_fork_view.head_changed() == true);
        REQUIRE(chain_fork_view.head_height() == 1);  // <-- NOTE! 1 not 2
        REQUIRE(chain_fork_view.head_hash() == header1b_hash);

        // check db content
        auto header1b_in_db = db::read_header(tx, header1b_hash);
        REQUIRE(header1b_in_db.has_value());
        REQUIRE(header1b_in_db == header1b);

        // verify the inserted chain
        verification = exec_engine.verify_chain(chain_fork_view.head_hash()).get();  // this will trigger unwind
        REQUIRE(std::holds_alternative<ValidChain>(verification));
        valid_chain = std::get<ValidChain>(verification);
        REQUIRE(valid_chain.current_head == BlockId{1, header1b_hash});

        // check db content
        REQUIRE(db::read_head_header_hash(tx) == header1b_hash);
        REQUIRE(db::read_canonical_head(tx) == std::make_tuple(1, header1b_hash));  // there was an unwind op

        REQUIRE(db::read_total_difficulty(tx, 1, header1b.hash()) == new_expected_td);
        REQUIRE(db::read_total_difficulty(tx, 2, header2.hash()) == expected_td);

        REQUIRE(db::read_canonical_hash(tx, 1) == header1b_hash);
        REQUIRE(db::read_canonical_hash(tx, 2).has_value() == false);

        REQUIRE(db::read_canonical_head(tx) == std::make_tuple(1, header1b_hash));

        // update the fork choice
        exec_engine.notify_fork_choice_update(header1b_hash);

        // check db content
        REQUIRE(db::read_head_header_hash(tx) == header1b_hash);
        REQUIRE(db::read_canonical_head(tx) == std::make_tuple(1, header1b_hash));
    }

    /* status:
     *         h0 (persisted)
     * input 1:
     *        (h0) <----- h1'            temp canonical chain
     * input 2:
     *        (h0) <----- h1 <----- h2   final canonical chain
     * final status:
     *         h0 <------ h1'
     *               |--- h1 <----- h2
     */
    SECTION("accepting 2 batch of headers, the second changing the canonical") {
        // receiving 1 header from a peer
        BlockHeader header1b;
        header1b.number = 1;
        header1b.difficulty = 2'000'000;
        header1b.parent_hash = header0_hash;
        header1b.extra_data = string_view_to_byte_view("I'm different");
        auto header1b_hash = header1b.hash();

        std::vector<BlockHeader> headers = {header1b};
        PeerId peer_id{byte_ptr_cast("1")};
        header_chain.accept_headers(headers, request_id, peer_id);

        // saving headers ready to persist as the header sync does in the forward() method
        Headers headers_to_persist = header_chain.withdraw_stable_headers();

        std::ranges::for_each(headers_to_persist, [&](const auto& header) {
            chain_fork_view.add(*header);
            auto fake_block = std::make_shared<Block>(Block{{}, *header});
            exec_engine.insert_block(fake_block);
        });

        // check internal status
        BigInt expected_td = header0->difficulty + header1b.difficulty;

        REQUIRE(chain_fork_view.head_total_difficulty() == expected_td);
        REQUIRE(chain_fork_view.head_changed() == true);
        REQUIRE(chain_fork_view.head_height() == 1);
        REQUIRE(chain_fork_view.head_hash() == header1b_hash);

        // check db content
        auto header1b_in_db = db::read_header(tx, header1b_hash);
        REQUIRE(header1b_in_db.has_value());
        REQUIRE(header1b_in_db == header1b);

        // verify the inserted chain
        auto verification = exec_engine.verify_chain(chain_fork_view.head_hash()).get();
        REQUIRE(std::holds_alternative<ValidChain>(verification));
        auto valid_chain = std::get<ValidChain>(verification);
        REQUIRE(valid_chain.current_head == BlockId{1, header1b_hash});

        // check db content
        REQUIRE(db::read_head_header_hash(tx) == header1b_hash);
        REQUIRE(db::read_total_difficulty(tx, 1, header1b.hash()) == expected_td);

        // receiving 2 header that changes the canonical chain
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

        // processing the headers
        std::vector<BlockHeader> headers_bis = {header1, header2};
        peer_id = byte_ptr_cast("2");
        header_chain.accept_headers(headers_bis, request_id, peer_id);

        // saving headers ready to persist as the header sync does in the forward() method
        Headers headers_to_persist_bis = header_chain.withdraw_stable_headers();

        std::ranges::for_each(headers_to_persist_bis, [&](const auto& header) {
            chain_fork_view.add(*header);
            auto fake_block = std::make_shared<Block>(Block{{}, *header});
            exec_engine.insert_block(fake_block);
        });

        // check internal status
        BigInt expected_td_bis = header0->difficulty + header1.difficulty + header2.difficulty;

        REQUIRE(chain_fork_view.head_total_difficulty() == expected_td_bis);
        REQUIRE(chain_fork_view.head_changed() == true);
        REQUIRE(chain_fork_view.head_height() == 2);
        REQUIRE(chain_fork_view.head_hash() == header2_hash);

        // check db
        auto header1_in_db = db::read_header(tx, header1_hash);
        REQUIRE(header1_in_db.has_value());
        REQUIRE(header1_in_db == header1);
        auto header2_in_db = db::read_header(tx, header2_hash);
        REQUIRE(header2_in_db.has_value());
        REQUIRE(header2_in_db == header2);
        header1b_in_db = db::read_header(tx, header1b_hash);
        REQUIRE(header1b_in_db.has_value());
        REQUIRE(header1b_in_db == header1b);

        // verify the inserted chain
        verification = exec_engine.verify_chain(chain_fork_view.head_hash()).get();  // this will trigger unwind
        REQUIRE(std::holds_alternative<ValidChain>(verification));
        valid_chain = std::get<ValidChain>(verification);
        REQUIRE(valid_chain.current_head == BlockId{2, header2_hash});

        REQUIRE(db::read_head_header_hash(tx) == header2_hash);
        REQUIRE(db::read_total_difficulty(tx, 2, header2.hash()) == expected_td_bis);

        REQUIRE(db::read_canonical_hash(tx, 1) == header1_hash);
        REQUIRE(db::read_canonical_hash(tx, 2) == header2_hash);

        REQUIRE(db::read_canonical_head(tx) == std::make_tuple(2, header2_hash));

        // update the fork choice
        exec_engine.notify_fork_choice_update(header2_hash);

        // check db content
        REQUIRE(db::read_head_header_hash(tx) == header2_hash);
        REQUIRE(db::read_canonical_head(tx) == std::make_tuple(2, header2_hash));
    }

    /* status:
     *        h0
     * input:
     *         h0 <----- h1  <----- h2
     *               |-- h1' <----- h2' <----- h3' (new canonical) -> unwind?
     */
    //  SECTION("a header in a secondary chain") {
    //      // ...
    //  }

    /* status:
     *         h0 <----- h1 <----- h2
     *               |-- h1'
     * input:
     *         h0 <----- h1  <----- h2
     *               |-- h1' <----- h2' <----- h3' (new canonical) -> unwind?
     */
    //  SECTION("a forking point in the past") {
    //       // ...
    //  }
}

}  // namespace silkworm
