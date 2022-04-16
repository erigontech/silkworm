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

namespace silkworm::rpc {

using namespace evmc::literals;

constexpr uint64_t kTestPendingBaseFee{10'000};
constexpr uint64_t kTestGasLimit{10'000'000};
constexpr uint64_t kTestDatabaseViewId{55};

constexpr auto kTestBlockNumber{1'000'000};
constexpr auto kTestBlockHash{0x8e38b4dbf6b11fcc3b9dee84fb7986e29ca0a02cecd8977c161ff7333329681e_bytes32};

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

    SECTION("OK: new block in FORWARD direction") {
        scc.start_new_block(kTestBlockNumber, kTestBlockHash, std::vector<silkworm::Bytes>{}, /*unwind=*/false);
        scc.register_consumer([&](const remote::StateChangeBatch& batch) {
            CHECK(batch.pendingblockbasefee() == kTestPendingBaseFee);
            CHECK(batch.blockgaslimit() == kTestGasLimit);
            CHECK(batch.databaseviewid() == 0);
            CHECK(batch.changebatch_size() == 1);
            for (int i{0}; i < batch.changebatch_size(); i++) {
                const remote::StateChange& state_change = batch.changebatch(i);
                CHECK(state_change.blockheight() == kTestBlockNumber);
                CHECK(state_change.has_blockhash());
            }
        });
        scc.notify_batch(kTestPendingBaseFee, kTestGasLimit);
    }
}

} // namespace silkworm::rpc
