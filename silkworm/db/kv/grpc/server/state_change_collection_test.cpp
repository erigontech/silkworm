// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "state_change_collection.hpp"

#include <memory>

#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/common/test_util.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/transaction.hpp>
#include <silkworm/infra/grpc/common/conversion.hpp>
#include <silkworm/infra/grpc/common/util.hpp>

namespace silkworm::rpc {

using namespace evmc::literals;

static constexpr uint64_t kTestPendingBaseFee{10'000};
static constexpr uint64_t kTestGasLimit{10'000'000};
static constexpr uint64_t kTestDatabaseViewId{55};

static constexpr BlockNum kTestBlockNum{1'000'000};
static constexpr evmc::bytes32 kTestBlockHash{0x8e38b4dbf6b11fcc3b9dee84fb7986e29ca0a02cecd8977c161ff7333329681e_bytes32};

static constexpr evmc::address kTestAddress{0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7030_address};
static constexpr uint64_t kTestIncarnation{3};

static const Bytes kTestData1{*from_hex("600035600055")};
static const Bytes kTestData2{*from_hex("6000356000550055")};

static const Bytes kTestCode1{*from_hex("602a6000556101c960015560068060166000396000f3600035600055")};
static const Bytes kTestCode2{*from_hex("602a5f556101c960015560048060135f395ff35f355f55")};

static const evmc::bytes32 kTestHashedLocation1{0x6677907ab33937e392b9be983b30818f29d594039c9e1e7490bf7b3698888fb1_bytes32};
static const evmc::bytes32 kTestHashedLocation2{0xe046602dcccb1a2f1d176718c8e709a42bba57af2da2379ba7130e2f916c95cd_bytes32};

static const Bytes kTestValue1{*from_hex("0xABCD")};
static const Bytes kTestValue2{*from_hex("0x4321")};
static const Bytes kTestValue3{*from_hex("0x4444")};

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
    CHECK(scc.last_token() + 1 == 0);
    CHECK_NOTHROW(scc.notify_batch(kTestPendingBaseFee, kTestGasLimit));
}

TEST_CASE("StateChangeCollection::subscribe", "[silkworm][rpc][state_change_collection]") {
    SECTION("OK: register do-nothing consumer") {
        StateChangeCollection scc;
        CHECK_NOTHROW(scc.subscribe([&](const auto /*batch*/) {}, StateChangeFilter{}));
    }

    SECTION("KO: token already in use") {
        class TestableStateChangeCollection : public StateChangeCollection {
          public:
            void set_token(StateChangeToken next_token) {
                next_token_ = next_token;
            }
        };
        TestableStateChangeCollection collection;

        const auto token1 = collection.subscribe([&](const auto /*batch*/) {}, StateChangeFilter{});
        CHECK(token1);
        collection.set_token(0);
        const auto token2 = collection.subscribe([&](const auto /*batch*/) {}, StateChangeFilter{});
        CHECK(!token2);
    }
}

TEST_CASE("StateChangeCollection::notify_batch", "[silkworm][rpc][state_change_collection]") {
    StateChangeCollection scc;

    SECTION("OK: notifies batch w/o changes to single consumer") {
        uint32_t notification_count{0};
        scc.subscribe([&](std::optional<remote::StateChangeBatch> batch) {
            CHECK(batch->pending_block_base_fee() == kTestPendingBaseFee);
            CHECK(batch->block_gas_limit() == kTestGasLimit);
            CHECK(batch->state_version_id() == 0);
            CHECK(batch->change_batch_size() == 0);
            ++notification_count;
        },
                      StateChangeFilter{});
        scc.notify_batch(kTestPendingBaseFee, kTestGasLimit);
        CHECK(notification_count == 1);
    }

    SECTION("OK: notifies batch w/o changes to multiple consumers") {
        uint32_t notification_count1{0}, notification_count2{0};
        scc.subscribe([&](std::optional<remote::StateChangeBatch> batch) {
            CHECK(batch->pending_block_base_fee() == kTestPendingBaseFee);
            CHECK(batch->block_gas_limit() == kTestGasLimit);
            CHECK(batch->state_version_id() == 0);
            CHECK(batch->change_batch_size() == 0);
            ++notification_count1;
        },
                      StateChangeFilter{});
        scc.subscribe([&](std::optional<remote::StateChangeBatch> batch) {
            CHECK(batch->pending_block_base_fee() == kTestPendingBaseFee);
            CHECK(batch->block_gas_limit() == kTestGasLimit);
            CHECK(batch->state_version_id() == 0);
            CHECK(batch->change_batch_size() == 0);
            ++notification_count2;
        },
                      StateChangeFilter{});
        scc.notify_batch(kTestPendingBaseFee, kTestGasLimit);
        CHECK((notification_count1 == 1 && notification_count2 == 1));
    }
}

TEST_CASE("StateChangeCollection::reset", "[silkworm][rpc][state_change_collection]") {
    StateChangeCollection scc;

    SECTION("OK: notifies batch w/o changes with expected transaction ID") {
        REQUIRE(scc.tx_id() == 0);
        scc.subscribe([&](std::optional<remote::StateChangeBatch> batch) {
            CHECK(batch->state_version_id() == scc.tx_id());
        },
                      StateChangeFilter{});
        scc.notify_batch(kTestPendingBaseFee, kTestGasLimit);
        scc.reset(kTestDatabaseViewId);
        CHECK(scc.tx_id() == kTestDatabaseViewId);
        scc.subscribe([&](std::optional<remote::StateChangeBatch> batch) {
            CHECK(batch->state_version_id() == scc.tx_id());
        },
                      StateChangeFilter{});
        scc.notify_batch(kTestPendingBaseFee, kTestGasLimit);
    }
}

TEST_CASE("StateChangeCollection::start_new_batch", "[silkworm][rpc][state_change_collection]") {
    StateChangeCollection scc;

    SECTION("OK: one new batch in FORWARD direction") {
        scc.start_new_batch(kTestBlockNum, kTestBlockHash, std::vector<silkworm::Bytes>{}, /*unwind=*/false);
        scc.subscribe([&](std::optional<remote::StateChangeBatch> batch) {
            CHECK(batch->pending_block_base_fee() == kTestPendingBaseFee);
            CHECK(batch->block_gas_limit() == kTestGasLimit);
            CHECK(batch->state_version_id() == 0);
            CHECK(batch->change_batch_size() == 1);
            const remote::StateChange& state_change = batch->change_batch(0);
            CHECK(state_change.direction() == remote::Direction::FORWARD);
            CHECK(state_change.block_height() == kTestBlockNum);
            CHECK(bytes32_from_h256(state_change.block_hash()) == kTestBlockHash);
        },
                      StateChangeFilter{});
        scc.notify_batch(kTestPendingBaseFee, kTestGasLimit);
    }

    SECTION("OK: two new batches in FORWARD and UNWIND directions") {
        scc.start_new_batch(kTestBlockNum, kTestBlockHash, sample_rlp_buffers(), /*unwind=*/false);
        scc.subscribe([&](std::optional<remote::StateChangeBatch> batch) {
            CHECK(batch->pending_block_base_fee() == kTestPendingBaseFee);
            CHECK(batch->block_gas_limit() == kTestGasLimit);
            CHECK(batch->change_batch_size() == 1);
            const remote::StateChange& state_change = batch->change_batch(0);
            CHECK(state_change.block_height() == kTestBlockNum);
            CHECK(bytes32_from_h256(state_change.block_hash()) == kTestBlockHash);
            CHECK(state_change.txs_size() == 2);
            static int notifications{0};
            if (notifications == 0) {
                CHECK(batch->state_version_id() == 0);
                CHECK(state_change.direction() == remote::Direction::FORWARD);
            } else if (notifications == 1) {
                CHECK(batch->state_version_id() == kTestDatabaseViewId);
                CHECK(state_change.direction() == remote::Direction::UNWIND);
            } else {
                CHECK(false);  // too many notifications
            }
            ++notifications;
        },
                      StateChangeFilter{});
        scc.notify_batch(kTestPendingBaseFee, kTestGasLimit);
        scc.reset(kTestDatabaseViewId);
        scc.start_new_batch(kTestBlockNum, kTestBlockHash, sample_rlp_buffers(), /*unwind=*/true);
        scc.notify_batch(kTestPendingBaseFee, kTestGasLimit);
    }
}

TEST_CASE("StateChangeCollection::change_account", "[silkworm][rpc][state_change_collection]") {
    StateChangeCollection scc;

    SECTION("OK: change one account once") {
        scc.subscribe([&](std::optional<remote::StateChangeBatch> batch) {
            CHECK(batch->pending_block_base_fee() == kTestPendingBaseFee);
            CHECK(batch->block_gas_limit() == kTestGasLimit);
            CHECK(batch->change_batch_size() == 1);
            const remote::StateChange& state_change = batch->change_batch(0);
            CHECK(state_change.block_height() == kTestBlockNum);
            CHECK(bytes32_from_h256(state_change.block_hash()) == kTestBlockHash);
            CHECK(state_change.txs_size() == 2);
            CHECK(batch->state_version_id() == 0);
            CHECK(state_change.direction() == remote::Direction::FORWARD);
            CHECK(state_change.changes_size() == 1);
            const remote::AccountChange& account_change = state_change.changes(0);
            CHECK(account_change.storage_changes_size() == 0);
            CHECK(account_change.data() == to_hex(kTestData1));
            CHECK(account_change.code().empty());
            CHECK(address_from_h160(account_change.address()) == kTestAddress);
            CHECK(account_change.incarnation() == kTestIncarnation);
            CHECK(account_change.action() == remote::Action::UPSERT);
        },
                      StateChangeFilter{});
        scc.start_new_batch(kTestBlockNum, kTestBlockHash, sample_rlp_buffers(), /*unwind=*/false);
        scc.change_account(kTestAddress, kTestIncarnation, kTestData1);
        scc.notify_batch(kTestPendingBaseFee, kTestGasLimit);
    }

    SECTION("OK: change one account twice") {
        scc.subscribe([&](std::optional<remote::StateChangeBatch> batch) {
            CHECK(batch->pending_block_base_fee() == kTestPendingBaseFee);
            CHECK(batch->block_gas_limit() == kTestGasLimit);
            CHECK(batch->change_batch_size() == 1);
            const remote::StateChange& state_change = batch->change_batch(0);
            CHECK(state_change.block_height() == kTestBlockNum);
            CHECK(bytes32_from_h256(state_change.block_hash()) == kTestBlockHash);
            CHECK(state_change.txs_size() == 2);
            CHECK(batch->state_version_id() == 0);
            CHECK(state_change.direction() == remote::Direction::FORWARD);
            CHECK(state_change.changes_size() == 2);
            const remote::AccountChange& account_change0 = state_change.changes(0);
            CHECK(account_change0.storage_changes_size() == 0);
            CHECK(account_change0.data() == to_hex(kTestData1));
            CHECK(account_change0.code().empty());
            CHECK(address_from_h160(account_change0.address()) == kTestAddress);
            CHECK(account_change0.incarnation() == kTestIncarnation);
            CHECK(account_change0.action() == remote::Action::UPSERT);
            const remote::AccountChange& account_change1 = state_change.changes(1);
            CHECK(account_change1.storage_changes_size() == 0);
            CHECK(account_change1.data() == to_hex(kTestData2));
            CHECK(account_change1.code().empty());
            CHECK(address_from_h160(account_change1.address()) == kTestAddress);
            CHECK(account_change1.incarnation() == kTestIncarnation + 1);
            CHECK(account_change1.action() == remote::Action::UPSERT);
        },
                      StateChangeFilter{});
        scc.start_new_batch(kTestBlockNum, kTestBlockHash, sample_rlp_buffers(), /*unwind=*/false);
        scc.change_account(kTestAddress, kTestIncarnation, kTestData1);
        scc.change_account(kTestAddress, kTestIncarnation + 1, kTestData2);
        scc.notify_batch(kTestPendingBaseFee, kTestGasLimit);
    }

    SECTION("OK: change account after changing code") {
        scc.subscribe([&](std::optional<remote::StateChangeBatch> batch) {
            CHECK(batch->pending_block_base_fee() == kTestPendingBaseFee);
            CHECK(batch->block_gas_limit() == kTestGasLimit);
            CHECK(batch->change_batch_size() == 1);
            const remote::StateChange& state_change = batch->change_batch(0);
            CHECK(state_change.block_height() == kTestBlockNum);
            CHECK(bytes32_from_h256(state_change.block_hash()) == kTestBlockHash);
            CHECK(state_change.txs_size() == 2);
            CHECK(batch->state_version_id() == 0);
            CHECK(state_change.direction() == remote::Direction::FORWARD);
            CHECK(state_change.changes_size() == 1);
            const remote::AccountChange& account_change = state_change.changes(0);
            CHECK(account_change.storage_changes_size() == 0);
            CHECK(account_change.data() == to_hex(kTestData1));
            CHECK(account_change.code() == to_hex(kTestCode1));
            CHECK(address_from_h160(account_change.address()) == kTestAddress);
            CHECK(account_change.incarnation() == kTestIncarnation);
            CHECK(account_change.action() == remote::Action::UPSERT_CODE);
        },
                      StateChangeFilter{});
        scc.start_new_batch(kTestBlockNum, kTestBlockHash, sample_rlp_buffers(), /*unwind=*/false);
        scc.change_code(kTestAddress, kTestIncarnation, kTestCode1);
        scc.change_account(kTestAddress, kTestIncarnation, kTestData1);
        scc.notify_batch(kTestPendingBaseFee, kTestGasLimit);
    }
}

TEST_CASE("StateChangeCollection::change_code", "[silkworm][rpc][state_change_collection]") {
    StateChangeCollection scc;

    SECTION("OK: change code of one account once") {
        scc.subscribe([&](std::optional<remote::StateChangeBatch> batch) {
            CHECK(batch->pending_block_base_fee() == kTestPendingBaseFee);
            CHECK(batch->block_gas_limit() == kTestGasLimit);
            CHECK(batch->change_batch_size() == 1);
            const remote::StateChange& state_change = batch->change_batch(0);
            CHECK(state_change.block_height() == kTestBlockNum);
            CHECK(bytes32_from_h256(state_change.block_hash()) == kTestBlockHash);
            CHECK(state_change.txs_size() == 2);
            CHECK(batch->state_version_id() == 0);
            CHECK(state_change.direction() == remote::Direction::FORWARD);
            CHECK(state_change.changes_size() == 1);
            const remote::AccountChange& account_change = state_change.changes(0);
            CHECK(account_change.storage_changes_size() == 0);
            CHECK(account_change.data().empty());
            CHECK(account_change.code() == to_hex(kTestCode1));
            CHECK(address_from_h160(account_change.address()) == kTestAddress);
            CHECK(account_change.incarnation() == kTestIncarnation);
            CHECK(account_change.action() == remote::Action::CODE);
        },
                      StateChangeFilter{});
        scc.start_new_batch(kTestBlockNum, kTestBlockHash, sample_rlp_buffers(), /*unwind=*/false);
        scc.change_code(kTestAddress, kTestIncarnation, kTestCode1);
        scc.notify_batch(kTestPendingBaseFee, kTestGasLimit);
    }

    SECTION("OK: change code of one account twice") {
        scc.subscribe([&](std::optional<remote::StateChangeBatch> batch) {
            CHECK(batch->pending_block_base_fee() == kTestPendingBaseFee);
            CHECK(batch->block_gas_limit() == kTestGasLimit);
            CHECK(batch->change_batch_size() == 1);
            const remote::StateChange& state_change = batch->change_batch(0);
            CHECK(state_change.block_height() == kTestBlockNum);
            CHECK(bytes32_from_h256(state_change.block_hash()) == kTestBlockHash);
            CHECK(state_change.txs_size() == 2);
            CHECK(batch->state_version_id() == 0);
            CHECK(state_change.direction() == remote::Direction::FORWARD);
            CHECK(state_change.changes_size() == 2);
            const remote::AccountChange& account_change0 = state_change.changes(0);
            CHECK(account_change0.storage_changes_size() == 0);
            CHECK(account_change0.data().empty());
            CHECK(account_change0.code() == to_hex(kTestCode1));
            CHECK(address_from_h160(account_change0.address()) == kTestAddress);
            CHECK(account_change0.incarnation() == kTestIncarnation);
            CHECK(account_change0.action() == remote::Action::CODE);
            const remote::AccountChange& account_change1 = state_change.changes(1);
            CHECK(account_change1.storage_changes_size() == 0);
            CHECK(account_change1.data().empty());
            CHECK(account_change1.code() == to_hex(kTestCode2));
            CHECK(address_from_h160(account_change1.address()) == kTestAddress);
            CHECK(account_change1.incarnation() == kTestIncarnation + 1);
            CHECK(account_change1.action() == remote::Action::CODE);
        },
                      StateChangeFilter{});
        scc.start_new_batch(kTestBlockNum, kTestBlockHash, sample_rlp_buffers(), /*unwind=*/false);
        scc.change_code(kTestAddress, kTestIncarnation, kTestCode1);
        scc.change_code(kTestAddress, kTestIncarnation + 1, kTestCode2);
        scc.notify_batch(kTestPendingBaseFee, kTestGasLimit);
    }

    SECTION("OK: change code after changing storage in new incarnation") {
        scc.subscribe([&](std::optional<remote::StateChangeBatch> batch) {
            CHECK(batch->pending_block_base_fee() == kTestPendingBaseFee);
            CHECK(batch->block_gas_limit() == kTestGasLimit);
            CHECK(batch->change_batch_size() == 1);
            const remote::StateChange& state_change = batch->change_batch(0);
            CHECK(state_change.block_height() == kTestBlockNum);
            CHECK(bytes32_from_h256(state_change.block_hash()) == kTestBlockHash);
            CHECK(state_change.txs_size() == 2);
            CHECK(batch->state_version_id() == 0);
            CHECK(state_change.direction() == remote::Direction::FORWARD);
            CHECK(state_change.changes_size() == 2);
            const remote::AccountChange& account_change0 = state_change.changes(0);
            CHECK(account_change0.data().empty());
            CHECK(account_change0.code().empty());
            CHECK(address_from_h160(account_change0.address()) == kTestAddress);
            CHECK(account_change0.incarnation() == kTestIncarnation);
            CHECK(account_change0.action() == remote::Action::STORAGE);
            CHECK(account_change0.storage_changes_size() == 1);
            const remote::StorageChange& storage_change00 = account_change0.storage_changes(0);
            CHECK(bytes32_from_h256(storage_change00.location()) == kTestHashedLocation1);
            CHECK(*from_hex(storage_change00.data()) == kTestData1);
            const remote::AccountChange& account_change1 = state_change.changes(1);
            CHECK(account_change1.data().empty());
            CHECK(account_change1.code() == to_hex(kTestCode1));
            CHECK(address_from_h160(account_change1.address()) == kTestAddress);
            CHECK(account_change1.incarnation() == kTestIncarnation + 1);
            CHECK(account_change1.action() == remote::Action::CODE);
            CHECK(account_change1.storage_changes_size() == 0);
        },
                      StateChangeFilter{});
        scc.start_new_batch(kTestBlockNum, kTestBlockHash, sample_rlp_buffers(), /*unwind=*/false);
        scc.change_storage(kTestAddress, kTestIncarnation, kTestHashedLocation1, kTestData1);
        scc.change_code(kTestAddress, kTestIncarnation + 1, kTestCode1);
        scc.notify_batch(kTestPendingBaseFee, kTestGasLimit);
    }

    SECTION("OK: change code after changing storage in same incarnation") {
        scc.subscribe([&](std::optional<remote::StateChangeBatch> batch) {
            CHECK(batch->pending_block_base_fee() == kTestPendingBaseFee);
            CHECK(batch->block_gas_limit() == kTestGasLimit);
            CHECK(batch->change_batch_size() == 1);
            const remote::StateChange& state_change = batch->change_batch(0);
            CHECK(state_change.block_height() == kTestBlockNum);
            CHECK(bytes32_from_h256(state_change.block_hash()) == kTestBlockHash);
            CHECK(state_change.txs_size() == 2);
            CHECK(batch->state_version_id() == 0);
            CHECK(state_change.direction() == remote::Direction::FORWARD);
            CHECK(state_change.changes_size() == 1);
            const remote::AccountChange& account_change0 = state_change.changes(0);
            CHECK(account_change0.data().empty());
            CHECK(account_change0.code() == to_hex(kTestCode1));
            CHECK(address_from_h160(account_change0.address()) == kTestAddress);
            CHECK(account_change0.incarnation() == kTestIncarnation);
            CHECK(account_change0.action() == remote::Action::CODE);
            CHECK(account_change0.storage_changes_size() == 1);
            const remote::StorageChange& storage_change00 = account_change0.storage_changes(0);
            CHECK(bytes32_from_h256(storage_change00.location()) == kTestHashedLocation1);
            CHECK(*from_hex(storage_change00.data()) == kTestData1);
        },
                      StateChangeFilter{});
        scc.start_new_batch(kTestBlockNum, kTestBlockHash, sample_rlp_buffers(), /*unwind=*/false);
        scc.change_storage(kTestAddress, kTestIncarnation, kTestHashedLocation1, kTestData1);
        scc.change_code(kTestAddress, kTestIncarnation, kTestCode1);
        scc.notify_batch(kTestPendingBaseFee, kTestGasLimit);
    }

    SECTION("OK: change code after changing account in new incarnation") {
        scc.subscribe([&](std::optional<remote::StateChangeBatch> batch) {
            CHECK(batch->pending_block_base_fee() == kTestPendingBaseFee);
            CHECK(batch->block_gas_limit() == kTestGasLimit);
            CHECK(batch->change_batch_size() == 1);
            const remote::StateChange& state_change = batch->change_batch(0);
            CHECK(state_change.block_height() == kTestBlockNum);
            CHECK(bytes32_from_h256(state_change.block_hash()) == kTestBlockHash);
            CHECK(state_change.txs_size() == 2);
            CHECK(batch->state_version_id() == 0);
            CHECK(state_change.direction() == remote::Direction::FORWARD);
            CHECK(state_change.changes_size() == 2);
            const remote::AccountChange& account_change0 = state_change.changes(0);
            CHECK(account_change0.storage_changes_size() == 0);
            CHECK(account_change0.data() == to_hex(kTestData1));
            CHECK(account_change0.code().empty());
            CHECK(address_from_h160(account_change0.address()) == kTestAddress);
            CHECK(account_change0.incarnation() == kTestIncarnation);
            CHECK(account_change0.action() == remote::Action::UPSERT);
            CHECK(account_change0.storage_changes_size() == 0);
            const remote::AccountChange& account_change1 = state_change.changes(1);
            CHECK(account_change1.data().empty());
            CHECK(account_change1.code() == to_hex(kTestCode1));
            CHECK(address_from_h160(account_change1.address()) == kTestAddress);
            CHECK(account_change1.incarnation() == kTestIncarnation + 1);
            CHECK(account_change1.action() == remote::Action::CODE);
            CHECK(account_change1.storage_changes_size() == 0);
        },
                      StateChangeFilter{});
        scc.start_new_batch(kTestBlockNum, kTestBlockHash, sample_rlp_buffers(), /*unwind=*/false);
        scc.change_account(kTestAddress, kTestIncarnation, kTestData1);
        scc.change_code(kTestAddress, kTestIncarnation + 1, kTestCode1);
        scc.notify_batch(kTestPendingBaseFee, kTestGasLimit);
    }

    SECTION("OK: change code after changing account in same incarnation") {
        scc.subscribe([&](std::optional<remote::StateChangeBatch> batch) {
            CHECK(batch->pending_block_base_fee() == kTestPendingBaseFee);
            CHECK(batch->block_gas_limit() == kTestGasLimit);
            CHECK(batch->change_batch_size() == 1);
            const remote::StateChange& state_change = batch->change_batch(0);
            CHECK(state_change.block_height() == kTestBlockNum);
            CHECK(bytes32_from_h256(state_change.block_hash()) == kTestBlockHash);
            CHECK(state_change.txs_size() == 2);
            CHECK(batch->state_version_id() == 0);
            CHECK(state_change.direction() == remote::Direction::FORWARD);
            CHECK(state_change.changes_size() == 1);
            const remote::AccountChange& account_change0 = state_change.changes(0);
            CHECK(account_change0.storage_changes_size() == 0);
            CHECK(account_change0.data() == to_hex(kTestData1));
            CHECK(account_change0.code() == to_hex(kTestCode1));
            CHECK(address_from_h160(account_change0.address()) == kTestAddress);
            CHECK(account_change0.incarnation() == kTestIncarnation);
            CHECK(account_change0.action() == remote::Action::UPSERT_CODE);
            CHECK(account_change0.storage_changes_size() == 0);
        },
                      StateChangeFilter{});
        scc.start_new_batch(kTestBlockNum, kTestBlockHash, sample_rlp_buffers(), /*unwind=*/false);
        scc.change_account(kTestAddress, kTestIncarnation, kTestData1);
        scc.change_code(kTestAddress, kTestIncarnation, kTestCode1);
        scc.notify_batch(kTestPendingBaseFee, kTestGasLimit);
    }
}

TEST_CASE("StateChangeCollection::change_storage", "[silkworm][rpc][state_change_collection]") {
    StateChangeCollection scc;

    SECTION("OK: change storage of one account once") {
        scc.subscribe([&](std::optional<remote::StateChangeBatch> batch) {
            CHECK(batch->pending_block_base_fee() == kTestPendingBaseFee);
            CHECK(batch->block_gas_limit() == kTestGasLimit);
            CHECK(batch->change_batch_size() == 1);
            const remote::StateChange& state_change = batch->change_batch(0);
            CHECK(state_change.block_height() == kTestBlockNum);
            CHECK(bytes32_from_h256(state_change.block_hash()) == kTestBlockHash);
            CHECK(state_change.txs_size() == 2);
            CHECK(batch->state_version_id() == 0);
            CHECK(state_change.direction() == remote::Direction::FORWARD);
            CHECK(state_change.changes_size() == 1);
            const remote::AccountChange& account_change = state_change.changes(0);
            CHECK(account_change.data().empty());
            CHECK(account_change.code().empty());
            CHECK(address_from_h160(account_change.address()) == kTestAddress);
            CHECK(account_change.incarnation() == kTestIncarnation);
            CHECK(account_change.action() == remote::Action::STORAGE);
            CHECK(account_change.storage_changes_size() == 1);
            const remote::StorageChange& storage_change = account_change.storage_changes(0);
            CHECK(bytes32_from_h256(storage_change.location()) == kTestHashedLocation1);
            CHECK(*from_hex(storage_change.data()) == kTestData1);
        },
                      StateChangeFilter{});
        scc.start_new_batch(kTestBlockNum, kTestBlockHash, sample_rlp_buffers(), /*unwind=*/false);
        scc.change_storage(kTestAddress, kTestIncarnation, kTestHashedLocation1, kTestData1);
        scc.notify_batch(kTestPendingBaseFee, kTestGasLimit);
    }

    SECTION("OK: change storage of one account twice") {
        scc.subscribe([&](std::optional<remote::StateChangeBatch> batch) {
            CHECK(batch->pending_block_base_fee() == kTestPendingBaseFee);
            CHECK(batch->block_gas_limit() == kTestGasLimit);
            CHECK(batch->change_batch_size() == 1);
            const remote::StateChange& state_change = batch->change_batch(0);
            CHECK(state_change.block_height() == kTestBlockNum);
            CHECK(bytes32_from_h256(state_change.block_hash()) == kTestBlockHash);
            CHECK(state_change.txs_size() == 2);
            CHECK(batch->state_version_id() == 0);
            CHECK(state_change.direction() == remote::Direction::FORWARD);
            CHECK(state_change.changes_size() == 2);
            const remote::AccountChange& account_change0 = state_change.changes(0);
            CHECK(account_change0.data().empty());
            CHECK(account_change0.code().empty());
            CHECK(address_from_h160(account_change0.address()) == kTestAddress);
            CHECK(account_change0.incarnation() == kTestIncarnation);
            CHECK(account_change0.action() == remote::Action::STORAGE);
            CHECK(account_change0.storage_changes_size() == 1);
            const remote::StorageChange& storage_change00 = account_change0.storage_changes(0);
            CHECK(bytes32_from_h256(storage_change00.location()) == kTestHashedLocation1);
            CHECK(*from_hex(storage_change00.data()) == kTestData1);
            const remote::AccountChange& account_change1 = state_change.changes(1);
            CHECK(account_change1.data().empty());
            CHECK(account_change1.code().empty());
            CHECK(address_from_h160(account_change1.address()) == kTestAddress);
            CHECK(account_change1.incarnation() == kTestIncarnation + 1);
            CHECK(account_change1.action() == remote::Action::STORAGE);
            CHECK(account_change1.storage_changes_size() == 1);
            const remote::StorageChange& storage_change10 = account_change1.storage_changes(0);
            CHECK(bytes32_from_h256(storage_change10.location()) == kTestHashedLocation2);
            CHECK(*from_hex(storage_change10.data()) == kTestData2);
        },
                      StateChangeFilter{});
        scc.start_new_batch(kTestBlockNum, kTestBlockHash, sample_rlp_buffers(), /*unwind=*/false);
        scc.change_storage(kTestAddress, kTestIncarnation, kTestHashedLocation1, kTestData1);
        scc.change_storage(kTestAddress, kTestIncarnation + 1, kTestHashedLocation2, kTestData2);
        scc.notify_batch(kTestPendingBaseFee, kTestGasLimit);
    }
}

TEST_CASE("StateChangeCollection::delete_account", "[silkworm][rpc][state_change_collection]") {
    StateChangeCollection scc;

    SECTION("OK: delete one account once in forward direction") {
        scc.subscribe([&](std::optional<remote::StateChangeBatch> batch) {
            CHECK(batch->pending_block_base_fee() == kTestPendingBaseFee);
            CHECK(batch->block_gas_limit() == kTestGasLimit);
            CHECK(batch->state_version_id() == 0);
            CHECK(batch->change_batch_size() == 1);
            const remote::StateChange& state_change = batch->change_batch(0);
            CHECK(state_change.direction() == remote::Direction::FORWARD);
            CHECK(state_change.block_height() == kTestBlockNum);
            CHECK(bytes32_from_h256(state_change.block_hash()) == kTestBlockHash);
            CHECK(state_change.changes_size() == 1);
            const remote::AccountChange& account_change = state_change.changes(0);
            CHECK(account_change.data().empty());
            CHECK(account_change.code().empty());
            CHECK(address_from_h160(account_change.address()) == kTestAddress);
            CHECK(account_change.incarnation() == 0);
            CHECK(account_change.action() == remote::Action::REMOVE);
            CHECK(account_change.storage_changes_size() == 0);
        },
                      StateChangeFilter{});
        scc.start_new_batch(kTestBlockNum, kTestBlockHash, sample_rlp_buffers(), /*unwind=*/false);
        scc.delete_account(kTestAddress);
        scc.notify_batch(kTestPendingBaseFee, kTestGasLimit);
    }
}

}  // namespace silkworm::rpc
