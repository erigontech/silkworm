// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <string>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/db/buffer.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/test_util/temp_chain_data.hpp>
#include <silkworm/infra/test_util/log.hpp>

#include "state/account_codec.hpp"

namespace silkworm::db {

TEST_CASE("Buffer storage", "[silkworm][db][buffer]") {
    db::test_util::TempChainData context;
    auto& txn{context.rw_txn()};

    const evmc::address address{0xbe00000000000000000000000000000000000000_address};
    const Bytes key{storage_prefix(address, kDefaultIncarnation)};

    const evmc::bytes32 location_a{0x0000000000000000000000000000000000000000000000000000000000000013_bytes32};
    const evmc::bytes32 value_a1{0x000000000000000000000000000000000000000000000000000000000000006b_bytes32};
    const evmc::bytes32 value_a2{0x0000000000000000000000000000000000000000000000000000000000000085_bytes32};
    const evmc::bytes32 value_a3{0x0000000000000000000000000000000000000000000000000000000000000095_bytes32};
    const evmc::bytes32 value_nil{0x0000000000000000000000000000000000000000000000000000000000000000_bytes32};

    const evmc::bytes32 location_b{0x0000000000000000000000000000000000000000000000000000000000000002_bytes32};
    const evmc::bytes32 value_b{0x0000000000000000000000000000000000000000000000000000000000000132_bytes32};

    const evmc::bytes32 location_c{0x0000000000000000000000000000000000000000000000000000000000000003_bytes32};

    auto state = txn.rw_cursor_dup_sort(table::kPlainState);

    upsert_storage_value(*state, key, location_a.bytes, value_a1.bytes);
    upsert_storage_value(*state, key, location_b.bytes, value_b.bytes);

    Buffer buffer{txn, std::make_unique<BufferROTxDataModel>(txn)};

    SECTION("Reads storage by address and location") {
        CHECK(buffer.read_storage(address, kDefaultIncarnation, location_a) == value_a1);
        CHECK(buffer.read_storage(address, kDefaultIncarnation, location_b) == value_b);
    }

    SECTION("Updates storage by address and location") {
        // Update only location A
        buffer.update_storage(address, kDefaultIncarnation, location_a,
                              /*initial=*/value_a1, /*current=*/value_a2);

        REQUIRE(buffer.storage_changes().empty() == false);

        buffer.write_to_db();

        // Location A should have the new value
        const std::optional<ByteView> db_value_a{find_value_suffix(*state, key, location_a.bytes)};
        REQUIRE(db_value_a.has_value());
        CHECK(db_value_a == zeroless_view(value_a2.bytes));

        // Location B should not change
        const std::optional<ByteView> db_value_b{find_value_suffix(*state, key, location_b.bytes)};
        REQUIRE(db_value_b.has_value());
        CHECK(db_value_b == zeroless_view(value_b.bytes));
    }

    SECTION("Keeps track of storage changes") {
        // Update location A
        buffer.update_storage(address, kDefaultIncarnation, location_a,
                              /*initial=*/value_a1, /*current=*/value_a2);
        buffer.write_to_db();

        // Update again location A
        buffer.update_storage(address, kDefaultIncarnation, location_a,
                              /*initial=*/value_a2, /*current=*/value_a3);

        REQUIRE(buffer.storage_changes().empty() == false);

        // Ask state buffer to not write change sets
        buffer.write_to_db(/*write_change_sets=*/false);

        // Location A should have the previous value of old value in state changes, i.e. value_a1
        const auto storage_changes{read_storage_changes(txn, 0)};
        REQUIRE(storage_changes.size() == 1);
        const auto& [changed_address, changed_map] = *storage_changes.begin();
        CHECK(changed_address == address);
        REQUIRE(changed_map.size() == 1);
        const auto& [changed_incarnation, changed_storage] = *changed_map.begin();
        CHECK(changed_incarnation == kDefaultIncarnation);
        REQUIRE(changed_storage.size() == 1);
        const auto& [changed_location, changed_value] = *changed_storage.begin();
        CHECK(changed_location == location_a);
        CHECK(changed_value == zeroless_view(value_a1.bytes));
    }

    SECTION("Multiple storage changes in a single block saves one storage change entry") {
        buffer.update_storage(address, kDefaultIncarnation, location_a,
                              /*initial=*/value_a1, /*current=*/value_a2);
        buffer.update_storage(address, kDefaultIncarnation, location_a,
                              /*initial=*/value_a2, /*current=*/value_a3);

        REQUIRE(buffer.storage_changes().empty() == false);

        buffer.write_to_db();

        const auto storage_changes{read_storage_changes(txn, 0)};
        REQUIRE(storage_changes.size() == 1);
        const auto& [changed_address, changed_map] = *storage_changes.begin();
        CHECK(changed_address == address);
        REQUIRE(changed_map.size() == 1);
        const auto& [changed_incarnation, changed_storage] = *changed_map.begin();
        CHECK(changed_incarnation == kDefaultIncarnation);
        REQUIRE(changed_storage.size() == 1);
        const auto& [changed_location_a, changed_value_a] = *changed_storage.find(location_a);
        CHECK(changed_location_a == location_a);
        CHECK(changed_value_a == zeroless_view(value_a2.bytes));
    }

    SECTION("Multiple storage changes in different blocks cause multiple storage changes") {
        buffer.begin_block(1, 1);
        buffer.update_storage(address, kDefaultIncarnation, location_a,
                              /*initial=*/value_a1, /*current=*/value_nil);
        buffer.write_to_db();

        buffer.begin_block(2, 1);
        buffer.update_storage(address, kDefaultIncarnation, location_a,
                              /*initial=*/value_nil, /*current=*/value_a3);
        buffer.write_to_db();

        buffer.begin_block(3, 1);
        buffer.update_storage(address, kDefaultIncarnation, location_a,
                              /*initial=*/value_a3, /*current=*/value_a2);
        buffer.write_to_db();

        const auto storage_changes1{read_storage_changes(txn, 1)};
        REQUIRE(storage_changes1.size() == 1);
        const auto storage_changes2{read_storage_changes(txn, 2)};
        REQUIRE(storage_changes2.size() == 1);
        const auto storage_changes3{read_storage_changes(txn, 3)};
        REQUIRE(storage_changes3.size() == 1);

        const std::optional<ByteView> db_value_a2{find_value_suffix(*state, key, location_a.bytes)};
        REQUIRE(db_value_a2.has_value());
        CHECK(db_value_a2 == zeroless_view(value_a2.bytes));
    }

    SECTION("Deletes storage by address and location") {
        // Delete location A
        buffer.update_storage(address, kDefaultIncarnation, location_a,
                              /*initial=*/value_a1, /*current=*/value_nil);

        // Buffer value set to nil
        auto current_value_a1{buffer.read_storage(address, kDefaultIncarnation, location_a)};
        CHECK(current_value_a1 == value_nil);

        // Not deleted from the db yet
        const std::optional<ByteView> db_value_a1{find_value_suffix(*state, key, location_a.bytes)};
        CHECK(db_value_a1.has_value());
        CHECK(db_value_a1 == zeroless_view(value_a1.bytes));

        buffer.write_to_db();

        // Buffer reads the value from the db
        auto current_value_a2{buffer.read_storage(address, kDefaultIncarnation, location_a)};
        CHECK(current_value_a2 == value_nil);

        // Location A should be deleted
        const std::optional<ByteView> db_value_a2{find_value_suffix(*state, key, location_a.bytes)};
        CHECK(!db_value_a2.has_value());

        // Location B should not change
        const std::optional<ByteView> db_value_b{find_value_suffix(*state, key, location_b.bytes)};
        REQUIRE(db_value_b.has_value());
        CHECK(db_value_b == zeroless_view(value_b.bytes));
    }

    SECTION("Can re-set value after deletion") {
        // Buffer only
        buffer.update_storage(address, kDefaultIncarnation, location_a,
                              /*initial=*/value_a1, /*current=*/value_nil);

        // Buffer value set to nil
        auto current_value_a1{buffer.read_storage(address, kDefaultIncarnation, location_a)};
        CHECK(current_value_a1 == value_nil);

        buffer.update_storage(address, kDefaultIncarnation, location_a,
                              /*initial=*/value_nil, /*current=*/value_a2);

        auto current_value_a2{buffer.read_storage(address, kDefaultIncarnation, location_a)};
        CHECK(current_value_a2 == value_a2);
    }

    SECTION("Sets new value") {
        buffer.update_storage(address, kDefaultIncarnation, location_c,
                              /*initial=*/{}, /*current=*/value_a1);

        auto current_value_a1{buffer.read_storage(address, kDefaultIncarnation, location_c)};
        CHECK(current_value_a1 == value_a1);

        buffer.write_to_db();

        const std::optional<ByteView> db_value_c1{find_value_suffix(*state, key, location_c.bytes)};
        REQUIRE(db_value_c1.has_value());
        CHECK(db_value_c1 == zeroless_view(value_a1.bytes));

        auto current_value_a2{buffer.read_storage(address, kDefaultIncarnation, location_c)};
        CHECK(current_value_a2 == value_a1);
    }

    SECTION("Setting to nil deletes the value") {
        buffer.update_storage(address, kDefaultIncarnation, location_a,
                              /*initial=*/value_a1, /*current=*/{});

        auto current_value_a1{buffer.read_storage(address, kDefaultIncarnation, location_a)};
        CHECK(current_value_a1 == value_nil);

        buffer.write_to_db();

        const std::optional<ByteView> db_value_a1{find_value_suffix(*state, key, location_a.bytes)};
        CHECK(!db_value_a1.has_value());

        auto current_value_a2{buffer.read_storage(address, kDefaultIncarnation, location_a)};
        CHECK(current_value_a2 == value_nil);
    }
}

TEST_CASE("Buffer account", "[silkworm][db][buffer]") {
    using datastore::kvdb::from_slice;
    db::test_util::TempChainData context;
    auto& txn{context.rw_txn()};

    SECTION("New EOA account") {
        const evmc::address address{0xbe00000000000000000000000000000000000000_address};
        state::AccountEncodable current_account;
        current_account.balance = kEther;

        Buffer buffer{txn, std::make_unique<BufferROTxDataModel>(txn)};
        buffer.begin_block(1, 1);
        buffer.update_account(address, /*initial=*/std::nullopt, current_account);
        REQUIRE(!buffer.account_changes().empty());
        // Current state batch: current account address + current account encoding
        CHECK(buffer.current_batch_state_size() == kAddressLength + current_account.encoding_length_for_storage());
        REQUIRE_NOTHROW(buffer.write_to_db());

        auto account_changeset{open_cursor(txn, table::kAccountChangeSet)};
        REQUIRE(txn->get_map_stat(account_changeset.map()).ms_entries == 1);
        auto data{account_changeset.to_first()};
        auto data_key_view{from_slice(data.key)};
        auto data_value_view{from_slice(data.value)};

        auto changeset_blocknum{endian::load_big_u64(data_key_view.data())};
        REQUIRE(changeset_blocknum == 1);

        auto changeset_address{bytes_to_address(data_value_view)};
        REQUIRE(changeset_address == address);
        data_value_view.remove_prefix(kAddressLength);
        REQUIRE(data_value_view.empty());
    }

    SECTION("Changed EOA account") {
        const evmc::address address{0xbe00000000000000000000000000000000000000_address};
        Account initial_account;
        initial_account.nonce = 1;
        initial_account.balance = 0;

        state::AccountEncodable current_account;
        current_account.nonce = 2;
        current_account.balance = kEther;

        Buffer buffer{txn, std::make_unique<BufferROTxDataModel>(txn)};
        buffer.begin_block(1, 1);
        buffer.update_account(address, /*initial=*/initial_account, current_account);
        REQUIRE(!buffer.account_changes().empty());
        // Current state batch: current account address + current account encoding
        CHECK(buffer.current_batch_state_size() == kAddressLength + current_account.encoding_length_for_storage());
        REQUIRE_NOTHROW(buffer.write_to_db());

        auto account_changeset{open_cursor(txn, table::kAccountChangeSet)};
        REQUIRE(txn->get_map_stat(account_changeset.map()).ms_entries == 1);
        auto data{account_changeset.to_first()};
        auto data_key_view{from_slice(data.key)};
        auto data_value_view{from_slice(data.value)};

        auto changeset_blocknum{endian::load_big_u64(data_key_view.data())};
        REQUIRE(changeset_blocknum == 1);

        auto changeset_address{bytes_to_address(data_value_view)};
        REQUIRE(changeset_address == address);
        data_value_view.remove_prefix(kAddressLength);
        REQUIRE(!data_value_view.empty());

        auto previous_account = state::AccountCodec::from_encoded_storage(data_value_view);
        CHECK(previous_account == initial_account);
    }

    SECTION("Delete contract account") {
        const evmc::address address{0xbe00000000000000000000000000000000000000_address};
        Account account;
        account.incarnation = kDefaultIncarnation;
        account.code_hash = to_bytes32(keccak256(address.bytes).bytes);  // Just a fake hash

        Buffer buffer{txn, std::make_unique<BufferROTxDataModel>(txn)};
        buffer.begin_block(1, 1);
        buffer.update_account(address, /*initial=*/account, /*current=*/std::nullopt);
        REQUIRE(!buffer.account_changes().empty());
        // Current state batch: initial account for delete + (initial account + incarnation) for incarnation
        CHECK(buffer.current_batch_state_size() == kAddressLength + (kAddressLength + kIncarnationLength));
        REQUIRE_NOTHROW(buffer.write_to_db());

        auto incarnations{open_cursor(txn, table::kIncarnationMap)};
        REQUIRE_NOTHROW(incarnations.to_first());
        auto data{incarnations.current()};
        REQUIRE(std::memcmp(data.key.data(), address.bytes, kAddressLength) == 0);
        REQUIRE(endian::load_big_u64(from_slice(data.value).data()) == account.incarnation);
    }

    SECTION("Delete contract account and recreate as EOA") {
        const evmc::address address{0xbe00000000000000000000000000000000000000_address};
        Account account;
        account.incarnation = kDefaultIncarnation;
        account.code_hash = to_bytes32(keccak256(address.bytes).bytes);  // Just a fake hash

        // Block 1: create contract account
        Buffer buffer{txn, std::make_unique<BufferROTxDataModel>(txn)};
        buffer.begin_block(1, 1);
        buffer.update_account(address, /*initial=*/std::nullopt, /*current=*/account);
        REQUIRE(!buffer.account_changes().empty());
        REQUIRE_NOTHROW(buffer.write_to_db());

        // Block 2 : destroy contract and recreate account as EOA
        buffer.begin_block(2, 1);
        Account eoa;
        eoa.balance = kEther;
        buffer.update_account(address, /*initial=*/account, /*current=*/eoa);
        REQUIRE(!buffer.account_changes().empty());
        REQUIRE_NOTHROW(buffer.write_to_db());

        auto incarnations{open_cursor(txn, table::kIncarnationMap)};
        REQUIRE_NOTHROW(incarnations.to_first());
        auto data{incarnations.current()};
        CHECK(std::memcmp(data.key.data(), address.bytes, kAddressLength) == 0);
        CHECK(endian::load_big_u64(from_slice(data.value).data()) == account.incarnation);
    }

    SECTION("Change EOA account w/ new value equal to old one") {
        const evmc::address address{0xbe00000000000000000000000000000000000000_address};
        Account initial_account;
        initial_account.nonce = 2;
        initial_account.balance = kEther;

        Account current_account;
        current_account.nonce = 2;
        current_account.balance = kEther;

        Buffer buffer{txn, std::make_unique<BufferROTxDataModel>(txn)};
        buffer.begin_block(1, 1);
        buffer.update_account(address, /*initial=*/initial_account, current_account);
        REQUIRE(buffer.account_changes().empty());
        // No change in current state batch
        CHECK(buffer.current_batch_state_size() == 0);
        REQUIRE_NOTHROW(buffer.write_to_db());

        auto account_changeset{open_cursor(txn, table::kAccountChangeSet)};
        REQUIRE(txn->get_map_stat(account_changeset.map()).ms_entries == 0);
    }
}

}  // namespace silkworm::db
