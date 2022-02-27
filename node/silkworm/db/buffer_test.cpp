/*
   Copyright 2021-2022 The Silkworm Authors

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
#include <magic_enum.hpp>

#include <silkworm/common/test_context.hpp>
#include <silkworm/db/buffer.hpp>
#include <silkworm/db/tables.hpp>

namespace silkworm::db {

TEST_CASE("Storage update") {
    test::Context context;
    auto& txn{context.txn()};

    const auto address{0xbe00000000000000000000000000000000000000_address};
    const Bytes key{storage_prefix(address, kDefaultIncarnation)};

    const auto location_a{0x0000000000000000000000000000000000000000000000000000000000000013_bytes32};
    const auto value_a1{0x000000000000000000000000000000000000000000000000000000000000006b_bytes32};
    const auto value_a2{0x0000000000000000000000000000000000000000000000000000000000000085_bytes32};

    const auto location_b{0x0000000000000000000000000000000000000000000000000000000000000002_bytes32};
    const auto value_b{0x0000000000000000000000000000000000000000000000000000000000000132_bytes32};

    auto state{db::open_cursor(txn, table::kPlainState)};

    upsert_storage_value(state, key, location_a, value_a1);
    upsert_storage_value(state, key, location_b, value_b);

    Buffer buffer{txn, 0};

    CHECK(buffer.read_storage(address, kDefaultIncarnation, location_a) == value_a1);

    // Update only location A
    buffer.update_storage(address, kDefaultIncarnation, location_a,
                          /*initial=*/value_a1, /*current=*/value_a2);

    REQUIRE(buffer.storage_changes().empty() == false);
    REQUIRE(buffer.current_batch_history_size() != 0);

    buffer.write_to_db();

    // Location A should have the new value
    const std::optional<ByteView> db_value_a{find_value_suffix(state, key, location_a)};
    REQUIRE(db_value_a.has_value());
    CHECK(db_value_a == zeroless_view(value_a2));

    // Location B should not change
    const std::optional<ByteView> db_value_b{find_value_suffix(state, key, location_b)};
    REQUIRE(db_value_b.has_value());
    CHECK(db_value_b == zeroless_view(value_b));
}

TEST_CASE("Account update") {
    test::Context context;
    auto& txn{context.txn()};

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
        REQUIRE(txn.get_map_stat(account_changeset.map()).ms_entries == 1);
        auto data{account_changeset.to_first()};
        auto data_key_view{db::from_slice(data.key)};
        auto data_value_view{db::from_slice(data.value)};

        auto changeset_blocknum{endian::load_big_u64(data_key_view.data())};
        REQUIRE(changeset_blocknum == 1);

        auto changeset_address{to_evmc_address(data_value_view)};
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
        REQUIRE(txn.get_map_stat(account_changeset.map()).ms_entries == 1);
        auto data{account_changeset.to_first()};
        auto data_key_view{db::from_slice(data.key)};
        auto data_value_view{db::from_slice(data.value)};

        auto changeset_blocknum{endian::load_big_u64(data_key_view.data())};
        REQUIRE(changeset_blocknum == 1);

        auto changeset_address{to_evmc_address(data_value_view)};
        REQUIRE(changeset_address == address);
        data_value_view.remove_prefix(kAddressLength);
        REQUIRE(data_value_view.length() != 0);

        auto exp_decoding_result{magic_enum::enum_name<DecodingResult>(DecodingResult::kOk)};
        auto [previous_account, err]{Account::from_encoded_storage(data_value_view)};
        auto act_decoding_result{magic_enum::enum_name<DecodingResult>(err)};

        REQUIRE(exp_decoding_result == act_decoding_result);
        REQUIRE(previous_account == initial_account);
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
