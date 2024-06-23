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
#include <silkworm/db/kv/api/util.hpp>
#include <silkworm/db/mdbx/bitmap.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/log.hpp>

namespace silkworm::db::state {

Task<std::optional<Account>> StateReader::read_account(const evmc::address& address, BlockNum block_number) const {
    std::optional<Bytes> encoded{co_await read_historical_account(address, block_number)};
    if (!encoded) {
        encoded = co_await tx_.get_one(table::kPlainStateName, full_view(address));
    }
    SILK_DEBUG << "StateReader::read_account encoded: " << (encoded ? *encoded : Bytes{});
    if (!encoded || encoded->empty()) {
        co_return std::nullopt;
    }

    auto account{Account::from_encoded_storage(*encoded)};
    success_or_throw(account);  // TODO(canepat) suggest rename as throw_if_error or better throw_if(err != kOk)

    if (account->incarnation > 0 && account->code_hash == kEmptyHash) {
        // Restore code hash
        const auto storage_key{storage_prefix(full_view(address), account->incarnation)};
        auto code_hash{co_await tx_.get_one(table::kPlainCodeHashName, storage_key)};
        if (code_hash.length() == kHashLength) {
            std::memcpy(account->code_hash.bytes, code_hash.data(), kHashLength);
        }
    }

    co_return *account;
}

Task<evmc::bytes32> StateReader::read_storage(
    const evmc::address& address,
    uint64_t incarnation,
    const evmc::bytes32& location_hash,
    BlockNum block_number) const {
    std::optional<Bytes> value{co_await read_historical_storage(address, incarnation, location_hash, block_number)};
    if (!value) {
        const auto composite_key{storage_prefix(address, incarnation)};
        SILK_DEBUG << "StateReader::read_storage composite_key: " << composite_key;
        value = co_await tx_.get_both_range(table::kPlainStateName, composite_key, location_hash.bytes);
        SILK_DEBUG << "StateReader::read_storage value: " << (value ? *value : Bytes{});
    }
    if (!value) {
        co_return evmc::bytes32{};
    }

    evmc::bytes32 storage_value{};
    std::memcpy(storage_value.bytes + kHashLength - value->length(), value->data(), value->length());
    co_return storage_value;
}

Task<std::optional<Bytes>> StateReader::read_code(const evmc::bytes32& code_hash) const {
    if (code_hash == kEmptyHash) {
        co_return std::nullopt;
    }
    co_return co_await tx_.get_one(table::kCodeName, full_view(code_hash));
}

Task<std::optional<Bytes>> StateReader::read_historical_account(const evmc::address& address, BlockNum block_number) const {
    const auto account_history_key{db::account_history_key(address, block_number)};
    SILK_DEBUG << "StateReader::read_historical_account account_history_key: " << account_history_key;
    const auto kv_pair{co_await tx_.get(table::kAccountHistoryName, account_history_key)};

    SILK_DEBUG << "StateReader::read_historical_account kv_pair.key: " << to_hex(kv_pair.key);
    const auto address_view{full_view(address)};
    if (kv_pair.key.substr(0, kAddressLength) != address_view) {
        co_return std::nullopt;
    }

    SILK_DEBUG << "StateReader::read_historical_account kv_pair.value: " << to_hex(kv_pair.value);
    if (kv_pair.value.empty()) {
        co_return std::nullopt;
    }
    const auto bitmap{bitmap::parse(kv_pair.value)};
    SILK_DEBUG << "StateReader::read_historical_account bitmap: " << bitmap.toString();

    const auto change_block{bitmap::seek(bitmap, block_number)};
    if (!change_block) {
        co_return std::nullopt;
    }

    const auto block_key{db::block_key(*change_block)};
    SILK_DEBUG << "StateReader::read_historical_account block_key: " << block_key;
    const auto address_subkey{address_view};
    SILK_DEBUG << "StateReader::read_historical_account address_subkey: " << address_subkey;
    const auto value{co_await tx_.get_both_range(table::kAccountChangeSetName, block_key, address_subkey)};
    SILK_DEBUG << "StateReader::read_historical_account value: " << (value ? *value : Bytes{});

    co_return value;
}

Task<std::optional<Bytes>> StateReader::read_historical_storage(const evmc::address& address, uint64_t incarnation,
                                                                const evmc::bytes32& location_hash, BlockNum block_number) const {
    const auto storage_history_key{db::storage_history_key(address, location_hash, block_number)};
    SILK_DEBUG << "StateReader::read_historical_storage storage_history_key: " << storage_history_key;
    const auto kv_pair{co_await tx_.get(table::kStorageHistoryName, storage_history_key)};

    const auto location_hash_view{full_view(location_hash)};
    if (kv_pair.key.substr(0, kAddressLength) != full_view(address) ||
        kv_pair.key.substr(kAddressLength, kHashLength) != location_hash_view) {
        co_return std::nullopt;
    }

    const auto bitmap{bitmap::parse(kv_pair.value)};
    SILK_DEBUG << "StateReader::read_historical_storage bitmap: " << bitmap.toString();

    const auto change_block{bitmap::seek(bitmap, block_number)};
    if (!change_block) {
        co_return std::nullopt;
    }

    const auto storage_change_key{db::storage_change_key(*change_block, address, incarnation)};
    SILK_DEBUG << "StateReader::read_historical_storage storage_change_key: " << storage_change_key;
    const auto location_subkey{location_hash_view};
    SILK_DEBUG << "StateReader::read_historical_storage location_subkey: " << location_subkey;
    const auto value{co_await tx_.get_both_range(table::kStorageChangeSetName, storage_change_key, location_subkey)};
    SILK_DEBUG << "StateReader::read_historical_storage value: " << (value ? *value : Bytes{});

    co_return value;
}
}  // namespace silkworm::db::state
