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

#include <catch2/catch.hpp>

#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/node/db/buffer.hpp>
#include <silkworm/node/db/tables.hpp>
#include <silkworm/node/test/context.hpp>

namespace silkworm::db {

TEST_CASE("Storage update") {
    test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};
    test::Context context;
    auto& txn{context.rw_txn()};

    const auto address{0xbe00000000000000000000000000000000000000_address};
    const Bytes key{storage_prefix(address, kDefaultIncarnation)};

    const auto location_a{0x0000000000000000000000000000000000000000000000000000000000000013_bytes32};
    const auto value_a1{0x000000000000000000000000000000000000000000000000000000000000006b_bytes32};
    const auto value_a2{0x0000000000000000000000000000000000000000000000000000000000000085_bytes32};
    const auto value_a3{0x0000000000000000000000000000000000000000000000000000000000000095_bytes32};

    const auto location_b{0x0000000000000000000000000000000000000000000000000000000000000002_bytes32};
    const auto value_b{0x0000000000000000000000000000000000000000000000000000000000000132_bytes32};

    auto state = txn.rw_cursor_dup_sort(table::kPlainState);

    upsert_storage_value(*state, key, location_a.bytes, value_a1.bytes);
    upsert_storage_value(*state, key, location_b.bytes, value_b.bytes);

    Buffer buffer{txn, 0};

    CHECK(buffer.read_storage(address, kDefaultIncarnation, location_a) == value_a1);

    // Update only location A
    buffer.update_storage(address, kDefaultIncarnation, location_a,
                          /*initial=*/value_a1, /*current=*/value_a2);

    REQUIRE(buffer.storage_changes().empty() == false);
    REQUIRE(buffer.current_batch_history_size() != 0);

    buffer.write_to_db();

    // Location A should have the new value
    const std::optional<ByteView> db_value_a{find_value_suffix(*state, key, location_a.bytes)};
    REQUIRE(db_value_a.has_value());
    CHECK(db_value_a == zeroless_view(value_a2.bytes));

    // Location B should not change
    const std::optional<ByteView> db_value_b{find_value_suffix(*state, key, location_b.bytes)};
    REQUIRE(db_value_b.has_value());
    CHECK(db_value_b == zeroless_view(value_b.bytes));

    // Update again only location A
    buffer.update_storage(address, kDefaultIncarnation, location_a,
                          /*initial=*/value_a2, /*current=*/value_a3);

    REQUIRE(buffer.storage_changes().empty() == false);
    REQUIRE(buffer.current_batch_history_size() != 0);

    // Ask state buffer to not write change sets
    buffer.write_to_db(/*write_change_sets=*/false);

    // Location A should have the previous value of old value in state changes, i.e. value_a1
    const auto storage_changes{db::read_storage_changes(txn, 0)};
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

TEST_CASE("Account update") {
    test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};
    test::Context context;
    auto& txn{context.rw_txn()};

    SECTION("New EOA account") {
        const auto address{0xbe00000000000000000000000000000000000000_address};
        Account current_account;
        current_account.balance = kEther;

        Buffer buffer{txn, 0};
        buffer.begin_block(1);
        buffer.update_account(address, /*initial=*/std::nullopt, current_account);
        REQUIRE(buffer.account_changes().empty() == false);
        REQUIRE_NOTHROW(buffer.write_to_db());

        auto account_changeset{db::open_cursor(txn, table::kAccountChangeSet)};
        REQUIRE(txn->get_map_stat(account_changeset.map()).ms_entries == 1);
        auto data{account_changeset.to_first()};
        auto data_key_view{db::from_slice(data.key)};
        auto data_value_view{db::from_slice(data.value)};

        auto changeset_blocknum{endian::load_big_u64(data_key_view.data())};
        REQUIRE(changeset_blocknum == 1);

        auto changeset_address{bytes_to_address(data_value_view)};
        REQUIRE(changeset_address == address);
        data_value_view.remove_prefix(kAddressLength);
        REQUIRE(data_value_view.length() == 0);
    }

    SECTION("Changed EOA account") {
        const auto address{0xbe00000000000000000000000000000000000000_address};
        Account initial_account;
        initial_account.nonce = 1;
        initial_account.balance = 0;

        Account current_account;
        current_account.nonce = 2;
        current_account.balance = kEther;

        Buffer buffer{txn, 0};
        buffer.begin_block(1);
        buffer.update_account(address, /*initial=*/initial_account, current_account);
        REQUIRE(buffer.account_changes().empty() == false);
        REQUIRE_NOTHROW(buffer.write_to_db());

        auto account_changeset{db::open_cursor(txn, table::kAccountChangeSet)};
        REQUIRE(txn->get_map_stat(account_changeset.map()).ms_entries == 1);
        auto data{account_changeset.to_first()};
        auto data_key_view{db::from_slice(data.key)};
        auto data_value_view{db::from_slice(data.value)};

        auto changeset_blocknum{endian::load_big_u64(data_key_view.data())};
        REQUIRE(changeset_blocknum == 1);

        auto changeset_address{bytes_to_address(data_value_view)};
        REQUIRE(changeset_address == address);
        data_value_view.remove_prefix(kAddressLength);
        REQUIRE(data_value_view.length() != 0);

        auto previous_account{Account::from_encoded_storage(data_value_view)};
        CHECK(previous_account == initial_account);
    }

    SECTION("Delete Contract account") {
        const auto address{0xbe00000000000000000000000000000000000000_address};
        Account account;
        account.incarnation = kDefaultIncarnation;
        account.code_hash = to_bytes32(keccak256(address.bytes).bytes);  // Just a fake hash

        Buffer buffer{txn, 0};
        buffer.begin_block(1);
        buffer.update_account(address, /*initial=*/account, std::nullopt);
        REQUIRE(buffer.account_changes().empty() == false);
        REQUIRE_NOTHROW(buffer.write_to_db());

        auto incarnations{db::open_cursor(txn, table::kIncarnationMap)};
        REQUIRE_NOTHROW(incarnations.to_first());
        auto data{incarnations.current()};
        REQUIRE(memcmp(data.key.data(), address.bytes, kAddressLength) == 0);
        REQUIRE(endian::load_big_u64(db::from_slice(data.value).data()) == account.incarnation);
    }
}

}  // namespace silkworm::db
