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
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/db/datastore/mdbx/bitmap.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/log.hpp>

namespace silkworm::db::state {

StateReader::StateReader(kv::api::Transaction& tx, BlockNum block_number) : tx_(tx), block_number_(block_number) {
    const bool is_v3 = is_data_format_v3();
    read_account_impl_ = is_v3 ? read_account_impl_v3_ : read_account_impl_v2_;
    read_storage_impl_ = is_v3 ? read_storage_impl_v3_ : read_storage_impl_v2_;
    read_code_impl_ = is_v3 ? read_code_impl_v3_ : read_code_impl_v2_;
}

Task<std::optional<Account>> StateReader::read_account(const evmc::address& address) const {
    co_return co_await std::invoke(read_account_impl_, *this, address);
}

Task<evmc::bytes32> StateReader::read_storage(const evmc::address& address,
                                              uint64_t incarnation,
                                              const evmc::bytes32& location_hash) const {
    co_return co_await std::invoke(read_storage_impl_, *this, address, incarnation, location_hash);
}

Task<std::optional<Bytes>> StateReader::read_code(const evmc::address& address, const evmc::bytes32& code_hash) const {
    co_return co_await std::invoke(read_code_impl_, *this, address, code_hash);
}

Task<std::optional<Account>> StateReader::read_account_v2(const evmc::address& address) const {
    std::optional<Bytes> encoded{co_await read_historical_account_v2(address)};
    if (!encoded) {
        encoded = co_await tx_.get_one(table::kPlainStateName, address.bytes);
    }
    SILK_DEBUG << "StateReader::read_account_v2 encoded: " << (encoded ? *encoded : Bytes{});
    if (!encoded || encoded->empty()) {
        co_return std::nullopt;
    }

    auto account{Account::from_encoded_storage(*encoded)};
    success_or_throw(account);

    if (account->incarnation > 0 && account->code_hash == kEmptyHash) {
        // Restore code hash
        const auto storage_key{storage_prefix(address.bytes, account->incarnation)};
        auto code_hash{co_await tx_.get_one(table::kPlainCodeHashName, storage_key)};
        if (code_hash.length() == kHashLength) {
            std::memcpy(account->code_hash.bytes, code_hash.data(), kHashLength);
        }
    }

    co_return *account;
}

Task<std::optional<Account>> StateReader::read_account_v3(const evmc::address& address) const {
    if (!txn_number_) {
        txn_number_ = co_await first_txn_num_in_block();
    }

    db::kv::api::DomainPointQuery query{
        .table = table::kAccountDomain,
        .key = db::account_domain_key(address),
        .timestamp = txn_number_,
    };
    const auto result = co_await tx_.domain_get(std::move(query));
    if (!result.success) {
        co_return std::nullopt;
    }
    auto account{Account::from_encoded_storage_v3(result.value)};
    success_or_throw(account);
    co_return *account;
}

Task<evmc::bytes32> StateReader::read_storage_v2(const evmc::address& address,
                                                 uint64_t incarnation,
                                                 const evmc::bytes32& location_hash) const {
    std::optional<Bytes> value{co_await read_historical_storage_v2(address, incarnation, location_hash)};
    if (!value) {
        const auto composite_key{storage_prefix(address, incarnation)};
        SILK_DEBUG << "StateReader::read_storage_v2 composite_key: " << composite_key;
        value = co_await tx_.get_both_range(table::kPlainStateName, composite_key, location_hash.bytes);
        SILK_DEBUG << "StateReader::read_storage_v2 value: " << (value ? *value : Bytes{});
    }
    if (!value) {
        co_return evmc::bytes32{};
    }

    evmc::bytes32 storage_value{};
    std::memcpy(storage_value.bytes + kHashLength - value->length(), value->data(), value->length());
    co_return storage_value;
}

Task<evmc::bytes32> StateReader::read_storage_v3(const evmc::address& address,
                                                 uint64_t /*incarnation*/,
                                                 const evmc::bytes32& location_hash) const {
    if (!txn_number_) {
        txn_number_ = co_await first_txn_num_in_block();
    }

    db::kv::api::DomainPointQuery query{
        .table = table::kStorageDomain,
        .key = db::storage_domain_key(address, location_hash),
        .timestamp = txn_number_,
    };
    const auto result = co_await tx_.domain_get(std::move(query));
    if (!result.success) {
        co_return evmc::bytes32{};
    }
    co_return to_bytes32(result.value);
}

Task<std::optional<Bytes>> StateReader::read_code_v2(const evmc::address& /*address*/, const evmc::bytes32& code_hash) const {
    if (code_hash == kEmptyHash) {
        co_return std::nullopt;
    }
    co_return co_await tx_.get_one(table::kCodeName, code_hash.bytes);
}

Task<std::optional<Bytes>> StateReader::read_code_v3(const evmc::address& address, const evmc::bytes32& code_hash) const {
    if (code_hash == kEmptyHash) {
        co_return std::nullopt;
    }
    if (!txn_number_) {
        txn_number_ = co_await first_txn_num_in_block();
    }

    db::kv::api::DomainPointQuery query{
        .table = table::kCodeDomain,
        .key = db::code_domain_key(address),
        .timestamp = txn_number_,
    };
    const auto result = co_await tx_.domain_get(std::move(query));
    if (!result.success) {
        co_return std::nullopt;
    }
    co_return result.value;
}

Task<std::optional<Bytes>> StateReader::read_historical_account_v2(const evmc::address& address) const {
    const auto account_history_key{db::account_history_key(address, block_number_)};
    SILK_DEBUG << "StateReader::read_historical_account_v2 account_history_key: " << account_history_key;
    const auto kv_pair{co_await tx_.get(table::kAccountHistoryName, account_history_key)};

    SILK_DEBUG << "StateReader::read_historical_account_v2 kv_pair.key: " << to_hex(kv_pair.key);
    const ByteView address_view{address.bytes};
    if (kv_pair.key.substr(0, kAddressLength) != address_view) {
        co_return std::nullopt;
    }

    SILK_DEBUG << "StateReader::read_historical_account_v2 kv_pair.value: " << to_hex(kv_pair.value);
    if (kv_pair.value.empty()) {
        co_return std::nullopt;
    }
    const auto bitmap{bitmap::parse(kv_pair.value)};
    SILK_DEBUG << "StateReader::read_historical_account_v2 bitmap: " << bitmap.toString();

    const auto change_block{bitmap::seek(bitmap, block_number_)};
    if (!change_block) {
        co_return std::nullopt;
    }

    const auto block_key{db::block_key(*change_block)};
    SILK_DEBUG << "StateReader::read_historical_account_v2 block_key: " << block_key;
    const auto address_subkey{address_view};
    SILK_DEBUG << "StateReader::read_historical_account_v2 address_subkey: " << address_subkey;
    const auto value{co_await tx_.get_both_range(table::kAccountChangeSetName, block_key, address_subkey)};
    SILK_DEBUG << "StateReader::read_historical_account_v2 value: " << (value ? *value : Bytes{});

    co_return value;
}

Task<std::optional<Bytes>> StateReader::read_historical_storage_v2(const evmc::address& address, uint64_t incarnation,
                                                                   const evmc::bytes32& location_hash) const {
    const auto storage_history_key{db::storage_history_key(address, location_hash, block_number_)};
    SILK_DEBUG << "StateReader::read_historical_storage_v2 storage_history_key: " << storage_history_key;
    const auto kv_pair{co_await tx_.get(table::kStorageHistoryName, storage_history_key)};

    const ByteView address_view{address.bytes};
    const ByteView location_hash_view{location_hash.bytes};
    if (kv_pair.key.substr(0, kAddressLength) != address_view ||
        kv_pair.key.substr(kAddressLength, kHashLength) != location_hash_view) {
        co_return std::nullopt;
    }

    const auto bitmap{bitmap::parse(kv_pair.value)};
    SILK_DEBUG << "StateReader::read_historical_storage_v2 bitmap: " << bitmap.toString();

    const auto change_block{bitmap::seek(bitmap, block_number_)};
    if (!change_block) {
        co_return std::nullopt;
    }

    const auto storage_change_key{db::storage_change_key(*change_block, address, incarnation)};
    SILK_DEBUG << "StateReader::read_historical_storage_v2 storage_change_key: " << storage_change_key;
    const auto location_subkey{location_hash_view};
    SILK_DEBUG << "StateReader::read_historical_storage_v2 location_subkey: " << location_subkey;
    const auto value{co_await tx_.get_both_range(table::kStorageChangeSetName, storage_change_key, location_subkey)};
    SILK_DEBUG << "StateReader::read_historical_storage_v2 value: " << (value ? *value : Bytes{});

    co_return value;
}

Task<txn::TxNum> StateReader::first_txn_num_in_block() const {
    const auto min_txn_num = co_await txn::min_tx_num(tx_, block_number_);
    co_return min_txn_num + /*txn_index*/ 0;
}

}  // namespace silkworm::db::state
