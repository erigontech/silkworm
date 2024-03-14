/*
   Copyright 2023 The Silkworm Authors

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

#include "state_reader.hpp"

#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/account.hpp>
#include <silkworm/db/mdbx/bitmap.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/core/rawdb/util.hpp>

namespace silkworm::rpc {

Task<std::optional<silkworm::Account>> StateReader::read_account(const evmc::address& address, BlockNum block_number) const {
    std::optional<silkworm::Bytes> encoded{co_await read_historical_account(address, block_number)};
    if (!encoded) {
        encoded = co_await db_reader_.get_one(db::table::kPlainStateName, full_view(address));
    }
    SILK_DEBUG << "StateReader::read_account encoded: " << (encoded ? *encoded : silkworm::Bytes{});
    if (!encoded || encoded->empty()) {
        co_return std::nullopt;
    }

    auto account{silkworm::Account::from_encoded_storage(*encoded)};
    silkworm::success_or_throw(account);  // TODO(canepat) suggest rename as throw_if_error or better throw_if(err != kOk)

    if (account->incarnation > 0 && account->code_hash == silkworm::kEmptyHash) {
        // Restore code hash
        const auto storage_key{silkworm::db::storage_prefix(full_view(address), account->incarnation)};
        auto code_hash{co_await db_reader_.get_one(db::table::kPlainCodeHashName, storage_key)};
        if (code_hash.length() == silkworm::kHashLength) {
            std::memcpy(account->code_hash.bytes, code_hash.data(), silkworm::kHashLength);
        }
    }

    co_return *account;
}

Task<evmc::bytes32> StateReader::read_storage(
    const evmc::address& address,
    uint64_t incarnation,
    const evmc::bytes32& location_hash,
    BlockNum block_number) const {
    std::optional<silkworm::Bytes> value{co_await read_historical_storage(address, incarnation, location_hash, block_number)};
    if (!value) {
        auto composite_key{silkworm::composite_storage_key_without_hash_lookup(address, incarnation)};
        SILK_DEBUG << "StateReader::read_storage composite_key: " << composite_key;
        value = co_await db_reader_.get_both_range(db::table::kPlainStateName, composite_key, location_hash.bytes);
        SILK_DEBUG << "StateReader::read_storage value: " << (value ? *value : silkworm::Bytes{});
    }
    if (!value) {
        co_return evmc::bytes32{};
    }

    evmc::bytes32 storage_value{};
    std::memcpy(storage_value.bytes + silkworm::kHashLength - value->length(), value->data(), value->length());
    co_return storage_value;
}

Task<std::optional<silkworm::Bytes>> StateReader::read_code(const evmc::bytes32& code_hash) const {
    if (code_hash == silkworm::kEmptyHash) {
        co_return std::nullopt;
    }
    co_return co_await db_reader_.get_one(db::table::kCodeName, full_view(code_hash));
}

Task<std::optional<silkworm::Bytes>> StateReader::read_historical_account(const evmc::address& address, BlockNum block_number) const {
    const auto account_history_key{silkworm::db::account_history_key(address, block_number)};
    SILK_DEBUG << "StateReader::read_historical_account account_history_key: " << account_history_key;
    const auto kv_pair{co_await db_reader_.get(db::table::kAccountHistoryName, account_history_key)};

    SILK_DEBUG << "StateReader::read_historical_account kv_pair.key: " << silkworm::to_hex(kv_pair.key);
    const auto address_view{full_view(address)};
    if (kv_pair.key.substr(0, silkworm::kAddressLength) != address_view) {
        co_return std::nullopt;
    }

    SILK_DEBUG << "StateReader::read_historical_account kv_pair.value: " << silkworm::to_hex(kv_pair.value);
    if (kv_pair.value.empty()) {
        co_return std::nullopt;
    }
    const auto bitmap{silkworm::db::bitmap::parse(kv_pair.value)};
    SILK_DEBUG << "StateReader::read_historical_account bitmap: " << bitmap.toString();

    const auto change_block{silkworm::db::bitmap::seek(bitmap, block_number)};
    if (!change_block) {
        co_return std::nullopt;
    }

    const auto block_key{silkworm::db::block_key(*change_block)};
    SILK_DEBUG << "StateReader::read_historical_account block_key: " << block_key;
    const auto address_subkey{address_view};
    SILK_DEBUG << "StateReader::read_historical_account address_subkey: " << address_subkey;
    const auto value{co_await db_reader_.get_both_range(db::table::kAccountChangeSetName, block_key, address_subkey)};
    SILK_DEBUG << "StateReader::read_historical_account value: " << (value ? *value : silkworm::Bytes{});

    co_return value;
}

Task<std::optional<silkworm::Bytes>> StateReader::read_historical_storage(const evmc::address& address, uint64_t incarnation,
                                                                          const evmc::bytes32& location_hash, BlockNum block_number) const {
    const auto storage_history_key{silkworm::db::storage_history_key(address, location_hash, block_number)};
    SILK_DEBUG << "StateReader::read_historical_storage storage_history_key: " << storage_history_key;
    const auto kv_pair{co_await db_reader_.get(db::table::kStorageHistoryName, storage_history_key)};

    const auto location_hash_view{full_view(location_hash)};
    if (kv_pair.key.substr(0, silkworm::kAddressLength) != full_view(address) ||
        kv_pair.key.substr(silkworm::kAddressLength, silkworm::kHashLength) != location_hash_view) {
        co_return std::nullopt;
    }

    const auto bitmap{silkworm::db::bitmap::parse(kv_pair.value)};
    SILK_DEBUG << "StateReader::read_historical_storage bitmap: " << bitmap.toString();

    const auto change_block{silkworm::db::bitmap::seek(bitmap, block_number)};
    if (!change_block) {
        co_return std::nullopt;
    }

    const auto storage_change_key{silkworm::db::storage_change_key(*change_block, address, incarnation)};
    SILK_DEBUG << "StateReader::read_historical_storage storage_change_key: " << storage_change_key;
    const auto location_subkey{location_hash_view};
    SILK_DEBUG << "StateReader::read_historical_storage location_subkey: " << location_subkey;
    const auto value{co_await db_reader_.get_both_range(db::table::kStorageChangeSetName, storage_change_key, location_subkey)};
    SILK_DEBUG << "StateReader::read_historical_storage value: " << (value ? *value : silkworm::Bytes{});

    co_return value;
}
}  // namespace silkworm::rpc
