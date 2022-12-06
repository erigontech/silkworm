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

#include <catch2/catch.hpp>

#include <silkworm/common/cast.hpp>
#include <silkworm/common/test_context.hpp>
#include <silkworm/consensus/engine.hpp>
#include <silkworm/db/genesis.hpp>
#include <silkworm/stagedsync/execution_engine.hpp>
#include <silkworm/test/log.hpp>
#include <silkworm/common/environment.hpp>
#include <silkworm/types/block.hpp>
#include <silkworm/downloader/chain_fork_view.hpp>

#include "header_chain.hpp"

namespace silkworm {

class HeaderChain_ForTest : public HeaderChain {
  public:  // publication of internal members to test methods functioning
    using HeaderChain::generate_request_id;
    using HeaderChain::HeaderChain;
};

class ExecutionEngine_ForTest : public stagedsync::ExecutionEngine {
  public:
    using stagedsync::ExecutionEngine::canonical_chain_;
    using stagedsync::ExecutionEngine::pipeline_;
    using stagedsync::ExecutionEngine::CanonicalChain;
    using stagedsync::ExecutionEngine::ExecutionEngine;
    using stagedsync::ExecutionEngine::tx_;
};

class DummyConsensusEngine : public consensus::IEngine {
  public:
    ValidationResult pre_validate_block_body(const Block&, const BlockState&) override { return ValidationResult::kOk; }

    ValidationResult pre_validate_transactions(const Block&) override { return ValidationResult::kOk; }

    ValidationResult validate_ommers(const Block&, const BlockState&) override { return ValidationResult::kOk; }

    ValidationResult validate_block_header(const BlockHeader&, const BlockState&, bool) override { return ValidationResult::kOk; }

    ValidationResult validate_seal(const BlockHeader&) override { return ValidationResult::kOk; }

    evmc::address get_beneficiary(const BlockHeader&) override { return {}; }
};

TEST_CASE("Headers receiving and saving") {
    test::SetLogVerbosityGuard log_guard(log::Level::kNone);

    test::Context context;
    context.add_genesis_data();
    context.commit_txn();

    Environment::set_pre_verified_hashes_disabled();

    db::RWAccess db_access{context.env()};

    // creating the ExecutionEngine
    ExecutionEngine_ForTest exec_engine{context.node_settings(), db_access};

    auto& tx = exec_engine.tx_;  // mdbx refuses to open a ROTxn when there is a RWTxn in the same thread

    // creating the chain-fork-view to simulate a bit of the HeaderStage
    chainsync::ChainForkView chain_fork_view{exec_engine};

    // creating the working chain to simulate a bit of the downloader
    BlockNum highest_in_db = 0;
    HeaderChain_ForTest header_chain(std::make_unique<DummyConsensusEngine>());
    header_chain.recover_initial_state(tx);
    header_chain.sync_current_state(highest_in_db);
    auto request_id = header_chain.generate_request_id();

    // reading genesis
    auto header0 = db::read_canonical_header(tx, 0);
    auto header0_hash = header0->hash();

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
        // header1.difficulty = canonical_difficulty(header1.number, header1.timestamp, header0->difficulty,
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

        // saving headers ready to persist as the header downloader does in the forward() method
        Headers headers_to_persist = header_chain.withdraw_stable_headers();

        for(auto& header: headers_to_persist) {
            chain_fork_view.add(*header);
            exec_engine.insert_header(*header);  // inserting in batch doesn't work because chain_fork_view
                                                  // needs data of ancestors from execution engine
        }

        // check internal status
        BigInt expected_td = header0->difficulty + header1.difficulty + header2.difficulty;

        REQUIRE(headers_to_persist.size() == 3);
        REQUIRE(chain_fork_view.head_total_difficulty() == expected_td);
        REQUIRE(chain_fork_view.head_changed() == true);
        REQUIRE(chain_fork_view.head_height() == 2);
        REQUIRE(chain_fork_view.head_hash() == header2_hash);

        // check db content
        REQUIRE(db::read_head_header_hash(tx) == header2_hash);
        REQUIRE(db::read_total_difficulty(tx, 2, header2.hash()) == expected_td);

        auto header1_in_db = db::read_header(tx, header1_hash);
        REQUIRE(header1_in_db.has_value());
        REQUIRE(header1_in_db == header1);
        auto header2_in_db = db::read_header(tx, header2_hash);
        REQUIRE(header2_in_db.has_value());
        REQUIRE(header2_in_db == header2);
        auto header1b_in_db = db::read_header(tx, header1b_hash);
        REQUIRE(header1b_in_db.has_value());
        REQUIRE(header1b_in_db == header1b);

        REQUIRE(db::read_canonical_hash(tx, 1) == header1_hash);
        REQUIRE(db::read_canonical_hash(tx, 2) == header2_hash);
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
    SECTION("accepting 2 batch of headers, the second not changing the temporary canonical") {
        INFO("to re-implement");
        /*
        db::RWTxn tx(context.env());

        // starting from an initial status
        auto header0 = db::read_canonical_header(tx, 0);
        auto header0_hash = header0->hash();
        BlockNum highest_in_db = 0;

        // creating the working chain as the downloader does at its construction
        HeaderChain_ForTest wc(std::make_unique<DummyConsensusEngine>());
        wc.recover_initial_state(tx);
        wc.sync_current_state(highest_in_db);
        auto request_id = wc.generate_request_id();

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
        wc.accept_headers(headers, request_id, peer_id);

        // creating the persisted chain as the header downloader does at the beginning of the forward() method
        HeaderPersistence pc(tx);

        // saving headers ready to persist as the header downloader does in the forward() method
        Headers headers_to_persist = wc.withdraw_stable_headers();
        pc.persist(headers_to_persist);

        // check internal status
        BigInt expected_td = header0->difficulty + header1.difficulty + header2.difficulty;

        REQUIRE(pc.total_difficulty() == expected_td);
        REQUIRE(pc.best_header_changed() == true);
        REQUIRE(pc.highest_height() == 2);
        REQUIRE(pc.highest_hash() == header2_hash);
        REQUIRE(pc.unwind_needed() == false);

        // check db content
        REQUIRE(db::read_head_header_hash(tx) == header2_hash);
        REQUIRE(db::read_total_difficulty(tx, 2, header2.hash()) == expected_td);

        auto header1_in_db = db::read_header(tx, header1_hash);
        REQUIRE(header1_in_db.has_value());
        REQUIRE(header1_in_db == header1);
        auto header2_in_db = db::read_header(tx, header2_hash);
        REQUIRE(header2_in_db.has_value());
        REQUIRE(header2_in_db == header2);

        // receiving a new header that is a fork
        BlockHeader header1b;
        header1b.number = 1;
        header1b.difficulty = 2'000'000;
        header1b.parent_hash = header0_hash;
        header1b.extra_data = string_view_to_byte_view("I'm different");
        auto header1b_hash = header1b.hash();

        std::vector<BlockHeader> headers_bis = {header1b};
        peer_id = byte_ptr_cast("2");
        wc.accept_headers(headers_bis, request_id, peer_id);

        // saving headers ready to persist as the header downloader does in the forward() method
        Headers headers_to_persist_bis = wc.withdraw_stable_headers();
        pc.persist(headers_to_persist_bis);

        auto header1b_in_db = db::read_header(tx, header1b_hash);
        REQUIRE(header1b_in_db.has_value());
        REQUIRE(header1b_in_db == header1b);

        // status and db content must be as before because the new header is not in the canonical chain
        REQUIRE(pc.total_difficulty() == expected_td);
        REQUIRE(pc.best_header_changed() == true);
        REQUIRE(pc.highest_height() == 2);
        REQUIRE(pc.highest_hash() == header2_hash);
        REQUIRE(pc.unwind_needed() == false);

        REQUIRE(db::read_head_header_hash(tx) == header2_hash);
        REQUIRE(db::read_total_difficulty(tx, 2, header2.hash()) == expected_td);

        header1_in_db = db::read_header(tx, header1_hash);
        REQUIRE(header1_in_db.has_value());
        REQUIRE(header1_in_db == header1);
        header2_in_db = db::read_header(tx, header2_hash);
        REQUIRE(header2_in_db.has_value());
        REQUIRE(header2_in_db == header2);

        // updating the canonical chain on the db
        pc.finish();

        REQUIRE(db::read_canonical_hash(tx, 1) == header1_hash);
        REQUIRE(db::read_canonical_hash(tx, 2) == header2_hash);
        */
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
    SECTION("accepting 2 batch of headers, the second changing the temporary canonical having height lower") {
        INFO("to implement");
        /*
        db::RWTxn tx(context.env());

        // starting from an initial status
        auto header0 = db::read_canonical_header(tx, 0);
        auto header0_hash = header0->hash();
        BlockNum highest_in_db = 0;

        // creating the working chain as the downloader does at its construction
        HeaderChain_ForTest wc(std::make_unique<DummyConsensusEngine>());
        wc.recover_initial_state(tx);
        wc.sync_current_state(highest_in_db);
        auto request_id = wc.generate_request_id();

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
        wc.accept_headers(headers, request_id, peer_id);

        // creating the persisted chain as the header downloader does at the beginning of the forward() method
        HeaderPersistence pc(tx);

        // saving headers ready to persist as the header downloader does in the forward() method
        Headers headers_to_persist = wc.withdraw_stable_headers();
        pc.persist(headers_to_persist);

        // check internal status
        BigInt expected_td = header0->difficulty + header1.difficulty + header2.difficulty;

        REQUIRE(pc.total_difficulty() == expected_td);
        REQUIRE(pc.best_header_changed() == true);
        REQUIRE(pc.highest_height() == 2);
        REQUIRE(pc.highest_hash() == header2_hash);
        REQUIRE(pc.unwind_needed() == false);

        // check db content
        REQUIRE(db::read_head_header_hash(tx) == header2_hash);
        REQUIRE(db::read_total_difficulty(tx, 2, header2.hash()) == expected_td);

        auto header1_in_db = db::read_header(tx, header1_hash);
        REQUIRE(header1_in_db.has_value());
        REQUIRE(header1_in_db == header1);
        auto header2_in_db = db::read_header(tx, header2_hash);
        REQUIRE(header2_in_db.has_value());
        REQUIRE(header2_in_db == header2);

        // receiving a new header that is a fork
        BlockHeader header1b;
        header1b.number = 1;
        header1b.difficulty = 3'000'000;
        header1b.parent_hash = header0_hash;
        header1b.extra_data = string_view_to_byte_view("I'm different");
        auto header1b_hash = header1b.hash();

        std::vector<BlockHeader> headers_bis = {header1b};
        peer_id = byte_ptr_cast("2");
        wc.accept_headers(headers_bis, request_id, peer_id);

        // saving headers ready to persist as the header downloader does in the forward() method
        Headers headers_to_persist_bis = wc.withdraw_stable_headers();
        pc.persist(headers_to_persist_bis);

        auto header1b_in_db = db::read_header(tx, header1b_hash);
        REQUIRE(header1b_in_db.has_value());
        REQUIRE(header1b_in_db == header1b);

        // the canonical is changed, check the new status
        BigInt expected_td_bis = header0->difficulty + header1b.difficulty;

        REQUIRE(pc.total_difficulty() == expected_td_bis);
        REQUIRE(pc.best_header_changed() == true);
        REQUIRE(pc.highest_height() == 1);  // <-- NOTE! 1 not 2
        REQUIRE(pc.highest_hash() == header1b_hash);
        REQUIRE(pc.unwind_needed() == false);  // because the prev canonical was not persisted

        REQUIRE(db::read_head_header_hash(tx) == header1b_hash);
        REQUIRE(db::read_total_difficulty(tx, 1, header1b.hash()) == expected_td_bis);
        REQUIRE(db::read_total_difficulty(tx, 2, header2.hash()) == expected_td);

        header1_in_db = db::read_header(tx, header1_hash);
        REQUIRE(header1_in_db.has_value());
        REQUIRE(header1_in_db == header1);
        header2_in_db = db::read_header(tx, header2_hash);
        REQUIRE(header2_in_db.has_value());
        REQUIRE(header2_in_db == header2);

        // updating the canonical chain on the db
        pc.finish();

        REQUIRE(db::read_canonical_hash(tx, 1) == header1b_hash);
        REQUIRE(db::read_canonical_hash(tx, 2).has_value() == false);
         */
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
    SECTION("accepting 2 batch of headers, the second changing the temporary canonical") {
        INFO("to implement");
        /*
        db::RWTxn tx(context.env());

        // starting from an initial status
        auto header0 = db::read_canonical_header(tx, 0);
        auto header0_hash = header0->hash();
        BlockNum highest_in_db = 0;

        // creating the working chain as the downloader does at its construction
        HeaderChain_ForTest wc(std::make_unique<DummyConsensusEngine>());
        wc.recover_initial_state(tx);
        wc.sync_current_state(highest_in_db);
        auto request_id = wc.generate_request_id();

        // receiving 1 header from a peer
        BlockHeader header1b;
        header1b.number = 1;
        header1b.difficulty = 2'000'000;
        header1b.parent_hash = header0_hash;
        header1b.extra_data = string_view_to_byte_view("I'm different");
        auto header1b_hash = header1b.hash();

        std::vector<BlockHeader> headers = {header1b};
        PeerId peer_id{byte_ptr_cast("1")};
        wc.accept_headers(headers, request_id, peer_id);

        // creating the persisted chain as the header downloader does at the beginning of the forward() method
        HeaderPersistence pc(tx);

        // saving headers ready to persist as the header downloader does in the forward() method
        Headers headers_to_persist = wc.withdraw_stable_headers();
        pc.persist(headers_to_persist);

        // check internal status
        BigInt expected_td = header0->difficulty + header1b.difficulty;

        REQUIRE(pc.total_difficulty() == expected_td);
        REQUIRE(pc.best_header_changed() == true);
        REQUIRE(pc.highest_height() == 1);
        REQUIRE(pc.highest_hash() == header1b_hash);
        REQUIRE(pc.unwind_needed() == false);

        // check db content
        REQUIRE(db::read_head_header_hash(tx) == header1b_hash);
        REQUIRE(db::read_total_difficulty(tx, 1, header1b.hash()) == expected_td);

        auto header1b_in_db = db::read_header(tx, header1b_hash);
        REQUIRE(header1b_in_db.has_value());
        REQUIRE(header1b_in_db == header1b);

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
        wc.accept_headers(headers_bis, request_id, peer_id);

        // saving headers ready to persist as the header downloader does in the forward() method
        Headers headers_to_persist_bis = wc.withdraw_stable_headers();
        pc.persist(headers_to_persist_bis);

        // check internal status
        BigInt expected_td_bis = header0->difficulty + header1.difficulty + header2.difficulty;

        REQUIRE(pc.total_difficulty() == expected_td_bis);
        REQUIRE(pc.best_header_changed() == true);
        REQUIRE(pc.highest_height() == 2);
        REQUIRE(pc.highest_hash() == header2_hash);
        REQUIRE(pc.unwind_needed() == false);

        // check db
        REQUIRE(db::read_head_header_hash(tx) == header2_hash);
        REQUIRE(db::read_total_difficulty(tx, 2, header2.hash()) == expected_td_bis);

        auto header1_in_db = db::read_header(tx, header1_hash);
        REQUIRE(header1_in_db.has_value());
        REQUIRE(header1_in_db == header1);
        auto header2_in_db = db::read_header(tx, header2_hash);
        REQUIRE(header2_in_db.has_value());
        REQUIRE(header2_in_db == header2);
        header1b_in_db = db::read_header(tx, header1b_hash);
        REQUIRE(header1b_in_db.has_value());
        REQUIRE(header1b_in_db == header1b);

        // updating the canonical chain on the db
        pc.finish();

        REQUIRE(db::read_canonical_hash(tx, 1) == header1_hash);
        REQUIRE(db::read_canonical_hash(tx, 2) == header2_hash);
         */
    }

    /* status:
     *        h0
     * input:
     *         h0 <----- h1  <----- h2
     *               |-- h1' <----- h2' <----- h3' (new cononical) -> unwind?
     */
    //  SECTION("a header in a secondary chain") {
    //      // ...
    //  }

    /* status:
     *         h0 <----- h1 <----- h2
     *               |-- h1'
     * input:
     *         h0 <----- h1  <----- h2
     *               |-- h1' <----- h2' <----- h3' (new cononical) -> unwind?
     */
    //  SECTION("a forking point in the past") {
    //       // ...
    //  }
}

}  // namespace silkworm
