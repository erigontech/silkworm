/*
    Copyright 2020-2022 The Silkworm Authors

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

#include <silkworm/chain/difficulty.hpp>
#include <silkworm/chain/genesis.hpp>
#include <silkworm/common/cast.hpp>
#include <silkworm/common/test_context.hpp>
#include <silkworm/consensus/engine.hpp>
#include <silkworm/db/genesis.hpp>

#include "persisted_chain.hpp"
#include "working_chain.hpp"

namespace silkworm {

class WorkingChain_ForTest : public WorkingChain {
  public:  // publication of internal members to test methods functioning
    using WorkingChain::generate_request_id;
    using WorkingChain::WorkingChain;
};

class DummyConsensusEngine : public consensus::IEngine {
  public:
    ValidationResult pre_validate_block(const Block&, const BlockState&) override { return ValidationResult::kOk; }

    ValidationResult validate_block_header(const BlockHeader&, const BlockState&, bool) override {
        return ValidationResult::kOk;
    }

    ValidationResult validate_seal(const BlockHeader&) override { return ValidationResult::kOk; }

    evmc::address get_beneficiary(const BlockHeader&) override { return {}; }
};

TEST_CASE("working/persistent-chain integration test") {
    test::Context context;
    auto& txn{context.txn()};

    bool allow_exceptions = false;

    auto source_data = silkworm::read_genesis_data(silkworm::kMainnetConfig.chain_id);
    auto genesis_json = nlohmann::json::parse(source_data, nullptr, allow_exceptions);
    db::initialize_genesis(txn, genesis_json, allow_exceptions);
    context.commit_and_renew_txn();

    /* status:
     *         h0 (persisted)
     * input:
     *        (h0) <----- h1 <----- h2
     *                |-- h1'
     */
    SECTION("accepting 1 batch of headers") {
        Db::ReadWriteAccess::Tx tx(txn);  // sub transaction

        // starting from an initial status
        auto header0 = tx.read_canonical_header(0);
        auto header0_hash = header0->hash();
        BlockNum highest_in_db = 0;

        // creating the working chain as the downloader does at its construction
        WorkingChain_ForTest wc(std::make_unique<DummyConsensusEngine>());
        wc.recover_initial_state(tx);
        wc.sync_current_state(highest_in_db);
        auto request_id = wc.generate_request_id();

        // auto timestamp = header0->timestamp;

        // receiving 3 headers from a peer
        BlockHeader header1;
        header1.number = 1;
        header1.difficulty = 1'000'000;
        // header1.gas_limit = 5000;
        // header1.timestamp = ++timestamp;
        // header1.difficulty = canonical_difficulty(header1.number, header1.timestamp, header0->difficulty,
        // header0->timestamp, false, ChainIdentity::mainnet.chain);
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
        PeerId peer_id = "1";
        wc.accept_headers(headers, request_id, peer_id);

        // saving headers ready to persist as the header downloader does in the forward() method
        Headers headers_to_persist = wc.withdraw_stable_headers();
        PersistedChain pc(tx);
        pc.persist(headers_to_persist);

        // check internal status
        BigInt expected_td = header0->difficulty + header1.difficulty + header2.difficulty;

        REQUIRE(headers_to_persist.size() == 3);
        REQUIRE(pc.total_difficulty() == expected_td);
        REQUIRE(pc.best_header_changed() == true);
        REQUIRE(pc.highest_height() == 2);
        REQUIRE(pc.highest_hash() == header2_hash);
        REQUIRE(pc.unwind() == false);

        // check db content
        REQUIRE(tx.read_head_header_hash() == header2_hash);
        REQUIRE(tx.read_total_difficulty(2, header2.hash()) == expected_td);

        auto header1_in_db = tx.read_header(header1_hash);
        REQUIRE(header1_in_db.has_value());
        REQUIRE(header1_in_db == header1);
        auto header2_in_db = tx.read_header(header2_hash);
        REQUIRE(header2_in_db.has_value());
        REQUIRE(header2_in_db == header2);
        auto header1b_in_db = tx.read_header(header1b_hash);
        REQUIRE(header1b_in_db.has_value());
        REQUIRE(header1b_in_db == header1b);

        pc.close();  // here pc update the canonical chain on the db

        REQUIRE(tx.read_canonical_hash(1) == header1_hash);
        REQUIRE(tx.read_canonical_hash(2) == header2_hash);
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
        Db::ReadWriteAccess::Tx tx(txn);  // sub transaction

        // starting from an initial status
        auto header0 = tx.read_canonical_header(0);
        auto header0_hash = header0->hash();
        BlockNum highest_in_db = 0;

        // creating the working chain as the downloader does at its construction
        WorkingChain_ForTest wc(std::make_unique<DummyConsensusEngine>());
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
        PeerId peer_id = "1";
        wc.accept_headers(headers, request_id, peer_id);

        // creating the persisted chain as the header downloader does at the beginning of the forward() method
        PersistedChain pc(tx);

        // saving headers ready to persist as the header downloader does in the forward() method
        Headers headers_to_persist = wc.withdraw_stable_headers();
        pc.persist(headers_to_persist);

        // check internal status
        BigInt expected_td = header0->difficulty + header1.difficulty + header2.difficulty;

        REQUIRE(pc.total_difficulty() == expected_td);
        REQUIRE(pc.best_header_changed() == true);
        REQUIRE(pc.highest_height() == 2);
        REQUIRE(pc.highest_hash() == header2_hash);
        REQUIRE(pc.unwind() == false);

        // check db content
        REQUIRE(tx.read_head_header_hash() == header2_hash);
        REQUIRE(tx.read_total_difficulty(2, header2.hash()) == expected_td);

        auto header1_in_db = tx.read_header(header1_hash);
        REQUIRE(header1_in_db.has_value());
        REQUIRE(header1_in_db == header1);
        auto header2_in_db = tx.read_header(header2_hash);
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
        peer_id = "2";
        wc.accept_headers(headers_bis, request_id, peer_id);

        // saving headers ready to persist as the header downloader does in the forward() method
        Headers headers_to_persist_bis = wc.withdraw_stable_headers();
        pc.persist(headers_to_persist_bis);

        auto header1b_in_db = tx.read_header(header1b_hash);
        REQUIRE(header1b_in_db.has_value());
        REQUIRE(header1b_in_db == header1b);

        // status and db content must be as before because the new header is not in the canonical chain
        REQUIRE(pc.total_difficulty() == expected_td);
        REQUIRE(pc.best_header_changed() == true);
        REQUIRE(pc.highest_height() == 2);
        REQUIRE(pc.highest_hash() == header2_hash);
        REQUIRE(pc.unwind() == false);

        REQUIRE(tx.read_head_header_hash() == header2_hash);
        REQUIRE(tx.read_total_difficulty(2, header2.hash()) == expected_td);

        header1_in_db = tx.read_header(header1_hash);
        REQUIRE(header1_in_db.has_value());
        REQUIRE(header1_in_db == header1);
        header2_in_db = tx.read_header(header2_hash);
        REQUIRE(header2_in_db.has_value());
        REQUIRE(header2_in_db == header2);

        // updating the canonical chain on the db
        pc.close();

        REQUIRE(tx.read_canonical_hash(1) == header1_hash);
        REQUIRE(tx.read_canonical_hash(2) == header2_hash);
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
        Db::ReadWriteAccess::Tx tx(txn);  // sub transaction

        // starting from an initial status
        auto header0 = tx.read_canonical_header(0);
        auto header0_hash = header0->hash();
        BlockNum highest_in_db = 0;

        // creating the working chain as the downloader does at its construction
        WorkingChain_ForTest wc(std::make_unique<DummyConsensusEngine>());
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
        PeerId peer_id = "1";
        wc.accept_headers(headers, request_id, peer_id);

        // creating the persisted chain as the header downloader does at the beginning of the forward() method
        PersistedChain pc(tx);

        // saving headers ready to persist as the header downloader does in the forward() method
        Headers headers_to_persist = wc.withdraw_stable_headers();
        pc.persist(headers_to_persist);

        // check internal status
        BigInt expected_td = header0->difficulty + header1.difficulty + header2.difficulty;

        REQUIRE(pc.total_difficulty() == expected_td);
        REQUIRE(pc.best_header_changed() == true);
        REQUIRE(pc.highest_height() == 2);
        REQUIRE(pc.highest_hash() == header2_hash);
        REQUIRE(pc.unwind() == false);

        // check db content
        REQUIRE(tx.read_head_header_hash() == header2_hash);
        REQUIRE(tx.read_total_difficulty(2, header2.hash()) == expected_td);

        auto header1_in_db = tx.read_header(header1_hash);
        REQUIRE(header1_in_db.has_value());
        REQUIRE(header1_in_db == header1);
        auto header2_in_db = tx.read_header(header2_hash);
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
        peer_id = "2";
        wc.accept_headers(headers_bis, request_id, peer_id);

        // saving headers ready to persist as the header downloader does in the forward() method
        Headers headers_to_persist_bis = wc.withdraw_stable_headers();
        pc.persist(headers_to_persist_bis);

        auto header1b_in_db = tx.read_header(header1b_hash);
        REQUIRE(header1b_in_db.has_value());
        REQUIRE(header1b_in_db == header1b);

        // the canonical is changed, check the new status
        BigInt expected_td_bis = header0->difficulty + header1b.difficulty;

        REQUIRE(pc.total_difficulty() == expected_td_bis);
        REQUIRE(pc.best_header_changed() == true);
        REQUIRE(pc.highest_height() == 1);  // <-- NOTE! 1 not 2
        REQUIRE(pc.highest_hash() == header1b_hash);
        REQUIRE(pc.unwind() == false);  // because the prev canonical was not persisted

        REQUIRE(tx.read_head_header_hash() == header1b_hash);
        REQUIRE(tx.read_total_difficulty(1, header1b.hash()) == expected_td_bis);
        REQUIRE(tx.read_total_difficulty(2, header2.hash()) == expected_td);

        header1_in_db = tx.read_header(header1_hash);
        REQUIRE(header1_in_db.has_value());
        REQUIRE(header1_in_db == header1);
        header2_in_db = tx.read_header(header2_hash);
        REQUIRE(header2_in_db.has_value());
        REQUIRE(header2_in_db == header2);

        // updating the canonical chain on the db
        pc.close();

        REQUIRE(tx.read_canonical_hash(1) == header1b_hash);
        REQUIRE(tx.read_canonical_hash(2).has_value() == false);
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
        Db::ReadWriteAccess::Tx tx(txn);  // sub transaction

        // starting from an initial status
        auto header0 = tx.read_canonical_header(0);
        auto header0_hash = header0->hash();
        BlockNum highest_in_db = 0;

        // creating the working chain as the downloader does at its construction
        WorkingChain_ForTest wc(std::make_unique<DummyConsensusEngine>());
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
        PeerId peer_id = "1";
        wc.accept_headers(headers, request_id, peer_id);

        // creating the persisted chain as the header downloader does at the beginning of the forward() method
        PersistedChain pc(tx);

        // saving headers ready to persist as the header downloader does in the forward() method
        Headers headers_to_persist = wc.withdraw_stable_headers();
        pc.persist(headers_to_persist);

        // check internal status
        BigInt expected_td = header0->difficulty + header1b.difficulty;

        REQUIRE(pc.total_difficulty() == expected_td);
        REQUIRE(pc.best_header_changed() == true);
        REQUIRE(pc.highest_height() == 1);
        REQUIRE(pc.highest_hash() == header1b_hash);
        REQUIRE(pc.unwind() == false);

        // check db content
        REQUIRE(tx.read_head_header_hash() == header1b_hash);
        REQUIRE(tx.read_total_difficulty(1, header1b.hash()) == expected_td);

        auto header1b_in_db = tx.read_header(header1b_hash);
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
        peer_id = "2";
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
        REQUIRE(pc.unwind() == false);

        // check db
        REQUIRE(tx.read_head_header_hash() == header2_hash);
        REQUIRE(tx.read_total_difficulty(2, header2.hash()) == expected_td_bis);

        auto header1_in_db = tx.read_header(header1_hash);
        REQUIRE(header1_in_db.has_value());
        REQUIRE(header1_in_db == header1);
        auto header2_in_db = tx.read_header(header2_hash);
        REQUIRE(header2_in_db.has_value());
        REQUIRE(header2_in_db == header2);
        header1b_in_db = tx.read_header(header1b_hash);
        REQUIRE(header1b_in_db.has_value());
        REQUIRE(header1b_in_db == header1b);

        // updating the canonical chain on the db
        pc.close();

        REQUIRE(tx.read_canonical_hash(1) == header1_hash);
        REQUIRE(tx.read_canonical_hash(2) == header2_hash);
    }

    /* status:
     *        h0
     * input:
     *         h0 <----- h1  <----- h2
     *               |-- h1' <----- h2' <----- h3' (new cononical) -> unwind?
     */
    //  SECTION("a header in a secondary chain") {
    //      // todo
    //  }

    /* status:
     *         h0 <----- h1 <----- h2
     *               |-- h1'
     * input:
     *         h0 <----- h1  <----- h2
     *               |-- h1' <----- h2' <----- h3' (new cononical) -> unwind?
     */
    //  SECTION("a forking point in the past") {
    //       // todo
    //  }
}

}  // namespace silkworm
