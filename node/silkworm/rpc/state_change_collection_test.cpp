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

#include "state_change_collection.hpp"

#include <memory>

#include <catch2/catch.hpp>
#include <evmc/evmc.hpp>

#include <silkworm/common/base.hpp>
#include <silkworm/common/test_util.hpp>
#include <silkworm/rpc/util.hpp>
#include <silkworm/types/transaction.hpp>

namespace silkworm::rpc {

using namespace evmc::literals;

constexpr uint64_t kTestPendingBaseFee{10'000};
constexpr uint64_t kTestGasLimit{10'000'000};
constexpr uint64_t kTestDatabaseViewId{55};

constexpr auto kTestBlockNumber{1'000'000};
constexpr auto kTestBlockHash{0x8e38b4dbf6b11fcc3b9dee84fb7986e29ca0a02cecd8977c161ff7333329681e_bytes32};

constexpr auto kTestAddress{0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7030_address};
constexpr uint64_t kTestIncarnation{3};
const Bytes kTestData1{*from_hex("600035600055")};
const Bytes kTestData2{*from_hex("6000356000550055")};

inline std::vector<Bytes> sample_rlp_buffers() {
    auto transactions = test::sample_transactions();
    std::vector<Bytes> tx_rlps;
    for (auto& tx : transactions) {
        Bytes rlp;
        rlp::encode(rlp, tx);
        tx_rlps.push_back(rlp);
    }
    return tx_rlps;
}

TEST_CASE("StateChangeCollection::StateChangeCollection", "[silkworm][rpc][state_change_collection]") {
    StateChangeCollection scc;
    CHECK(scc.tx_id() == 0);
    CHECK_NOTHROW(scc.notify_batch(kTestPendingBaseFee, kTestGasLimit));
}

TEST_CASE("StateChangeCollection::register_consumer", "[silkworm][rpc][state_change_collection]") {
    StateChangeCollection scc;
    CHECK_NOTHROW(scc.register_consumer([&](auto& /*batch*/) {}));
}

TEST_CASE("StateChangeCollection::notify_batch", "[silkworm][rpc][state_change_collection]") {
    StateChangeCollection scc;

    SECTION("OK: notifies batch w/o changes to single consumer") {
        uint32_t notification_count{0};
        scc.register_consumer([&](const remote::StateChangeBatch& batch) {
            CHECK(batch.pendingblockbasefee() == kTestPendingBaseFee);
            CHECK(batch.blockgaslimit() == kTestGasLimit);
            CHECK(batch.databaseviewid() == 0);
            CHECK(batch.changebatch_size() == 0);
            ++notification_count;
        });
        scc.notify_batch(kTestPendingBaseFee, kTestGasLimit);
        CHECK(notification_count == 1);
    }

    SECTION("OK: notifies batch w/o changes to multiple consumers") {
        uint32_t notification_count1{0}, notification_count2{0};
        scc.register_consumer([&](const remote::StateChangeBatch& batch) {
            CHECK(batch.pendingblockbasefee() == kTestPendingBaseFee);
            CHECK(batch.blockgaslimit() == kTestGasLimit);
            CHECK(batch.databaseviewid() == 0);
            CHECK(batch.changebatch_size() == 0);
            ++notification_count1;
        });
        scc.register_consumer([&](const remote::StateChangeBatch& batch) {
            CHECK(batch.pendingblockbasefee() == kTestPendingBaseFee);
            CHECK(batch.blockgaslimit() == kTestGasLimit);
            CHECK(batch.databaseviewid() == 0);
            CHECK(batch.changebatch_size() == 0);
            ++notification_count2;
        });
        scc.notify_batch(kTestPendingBaseFee, kTestGasLimit);
        CHECK((notification_count1 == 1 && notification_count2 == 1));
    }
}

TEST_CASE("StateChangeCollection::reset", "[silkworm][rpc][state_change_collection]") {
    StateChangeCollection scc;

    SECTION("OK: notifies batch w/o changes with expected transaction ID") {
        REQUIRE(scc.tx_id() == 0);
        scc.register_consumer([&](const remote::StateChangeBatch& batch) {
            CHECK(batch.databaseviewid() == scc.tx_id());
        });
        scc.notify_batch(kTestPendingBaseFee, kTestGasLimit);
        scc.reset(kTestDatabaseViewId);
        CHECK(scc.tx_id() == kTestDatabaseViewId);
        scc.register_consumer([&](const remote::StateChangeBatch& batch) {
            CHECK(batch.databaseviewid() == scc.tx_id());
        });
        scc.notify_batch(kTestPendingBaseFee, kTestGasLimit);
    }
}

TEST_CASE("StateChangeCollection::start_new_block", "[silkworm][rpc][state_change_collection]") {
    StateChangeCollection scc;

    SECTION("OK: one new block in FORWARD direction") {
        scc.start_new_block(kTestBlockNumber, kTestBlockHash, std::vector<silkworm::Bytes>{}, /*unwind=*/false);
        scc.register_consumer([&](const remote::StateChangeBatch& batch) {
            CHECK(batch.pendingblockbasefee() == kTestPendingBaseFee);
            CHECK(batch.blockgaslimit() == kTestGasLimit);
            CHECK(batch.databaseviewid() == 0);
            CHECK(batch.changebatch_size() == 1);
            const remote::StateChange& state_change = batch.changebatch(0);
            CHECK(state_change.direction() == remote::Direction::FORWARD);
            CHECK(state_change.blockheight() == kTestBlockNumber);
            CHECK(bytes32_from_H256(state_change.blockhash()) == kTestBlockHash);
        });
        scc.notify_batch(kTestPendingBaseFee, kTestGasLimit);
    }

    SECTION("OK: two new blocks in FORWARD and UNWIND directions") {
        scc.start_new_block(kTestBlockNumber, kTestBlockHash, sample_rlp_buffers(), /*unwind=*/false);
        scc.register_consumer([&](const remote::StateChangeBatch& batch) {
            CHECK(batch.pendingblockbasefee() == kTestPendingBaseFee);
            CHECK(batch.blockgaslimit() == kTestGasLimit);
            CHECK(batch.changebatch_size() == 1);
            const remote::StateChange& state_change = batch.changebatch(0);
            CHECK(state_change.blockheight() == kTestBlockNumber);
            CHECK(bytes32_from_H256(state_change.blockhash()) == kTestBlockHash);
            CHECK(state_change.txs_size() == 2);
            static int notifications{0};
            if (notifications == 0) {
                CHECK(batch.databaseviewid() == 0);
                CHECK(state_change.direction() == remote::Direction::FORWARD);
            } else if (notifications == 1) {
                CHECK(batch.databaseviewid() == kTestDatabaseViewId);
                CHECK(state_change.direction() == remote::Direction::UNWIND);
            } else {
                CHECK(false); // too many notifications
            }
            notifications++;
        });
        scc.notify_batch(kTestPendingBaseFee, kTestGasLimit);
        scc.reset(kTestDatabaseViewId);
        scc.start_new_block(kTestBlockNumber, kTestBlockHash, sample_rlp_buffers(), /*unwind=*/true);
        scc.notify_batch(kTestPendingBaseFee, kTestGasLimit);
    }
}

TEST_CASE("StateChangeCollection::change_account", "[silkworm][rpc][state_change_collection]") {
    StateChangeCollection scc;

    SECTION("OK: change one account once") {
        scc.register_consumer([&](const remote::StateChangeBatch& batch) {
            CHECK(batch.pendingblockbasefee() == kTestPendingBaseFee);
            CHECK(batch.blockgaslimit() == kTestGasLimit);
            CHECK(batch.changebatch_size() == 1);
            const remote::StateChange& state_change = batch.changebatch(0);
            CHECK(state_change.blockheight() == kTestBlockNumber);
            CHECK(bytes32_from_H256(state_change.blockhash()) == kTestBlockHash);
            CHECK(state_change.txs_size() == 2);
            CHECK(batch.databaseviewid() == 0);
            CHECK(state_change.direction() == remote::Direction::FORWARD);
            CHECK(state_change.changes_size() == 1);
            const remote::AccountChange& account_change = state_change.changes(0);
            CHECK(account_change.storagechanges_size() == 0);
            CHECK(account_change.data() == to_hex(kTestData1));
            CHECK(account_change.code().empty());
            CHECK(address_from_H160(account_change.address()) == kTestAddress);
            CHECK(account_change.incarnation() == kTestIncarnation);
            CHECK(account_change.action() == remote::Action::UPSERT);
        });
        scc.start_new_block(kTestBlockNumber, kTestBlockHash, sample_rlp_buffers(), /*unwind=*/false);
        scc.change_account(kTestAddress, kTestIncarnation, kTestData1);
        scc.notify_batch(kTestPendingBaseFee, kTestGasLimit);
    }

    SECTION("OK: change one account twice") {
        scc.register_consumer([&](const remote::StateChangeBatch& batch) {
            CHECK(batch.pendingblockbasefee() == kTestPendingBaseFee);
            CHECK(batch.blockgaslimit() == kTestGasLimit);
            CHECK(batch.changebatch_size() == 1);
            const remote::StateChange& state_change = batch.changebatch(0);
            CHECK(state_change.blockheight() == kTestBlockNumber);
            CHECK(bytes32_from_H256(state_change.blockhash()) == kTestBlockHash);
            CHECK(state_change.txs_size() == 2);
            CHECK(batch.databaseviewid() == 0);
            CHECK(state_change.direction() == remote::Direction::FORWARD);
            CHECK(state_change.changes_size() == 2);
            const remote::AccountChange& account_change0 = state_change.changes(0);
            CHECK(account_change0.storagechanges_size() == 0);
            CHECK(account_change0.data() == to_hex(kTestData1));
            CHECK(account_change0.code().empty());
            CHECK(address_from_H160(account_change0.address()) == kTestAddress);
            CHECK(account_change0.incarnation() == kTestIncarnation);
            CHECK(account_change0.action() == remote::Action::UPSERT);
            const remote::AccountChange& account_change1 = state_change.changes(1);
            CHECK(account_change1.storagechanges_size() == 0);
            CHECK(account_change1.data() == to_hex(kTestData2));
            CHECK(account_change1.code().empty());
            CHECK(address_from_H160(account_change1.address()) == kTestAddress);
            CHECK(account_change1.incarnation() == kTestIncarnation + 1);
            CHECK(account_change1.action() == remote::Action::UPSERT);
        });
        scc.start_new_block(kTestBlockNumber, kTestBlockHash, sample_rlp_buffers(), /*unwind=*/false);
        scc.change_account(kTestAddress, kTestIncarnation, kTestData1);
        scc.change_account(kTestAddress, kTestIncarnation + 1, kTestData2);
        scc.notify_batch(kTestPendingBaseFee, kTestGasLimit);
    }
}

} // namespace silkworm::rpc
