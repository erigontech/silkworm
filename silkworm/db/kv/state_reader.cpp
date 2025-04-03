// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "state_reader.hpp"

#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/account.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/db/state/account_codec.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>

namespace silkworm::db::kv {

StateReader::StateReader(api::Transaction& tx, std::optional<TxnId> txn_id)
    : tx_(tx), txn_number_(txn_id) {}

Task<std::optional<Account>> StateReader::read_account(const evmc::address& address) const {
    api::PointResult result;

    if (!txn_number_) {
        result = co_await latest_from_cache(table::kAccountDomain, db::account_domain_key(address));
    } else {
        db::kv::api::GetAsOfRequest request{
            .table = table::kAccountDomain,
            .key = db::account_domain_key(address),
            .timestamp = static_cast<kv::api::Timestamp>(*txn_number_),
        };
        result = co_await tx_.get_as_of(std::move(request));
    }

    if (!result.success) {
        co_return std::nullopt;
    }

    // Non-existent account has empty encoded value
    if (result.value.empty()) {
        co_return std::nullopt;
    }

    const auto account = db::state::AccountCodec::from_encoded_storage_v3(result.value);
    success_or_throw(account);
    co_return *account;
}

Task<evmc::bytes32> StateReader::read_storage(const evmc::address& address,
                                              uint64_t /* incarnation */,
                                              const evmc::bytes32& location_hash) const {
    api::PointResult result;

    if (!txn_number_) {
        result = co_await latest_from_cache(table::kStorageDomain, db::storage_domain_key(address, location_hash));
    } else {
        db::kv::api::GetAsOfRequest request{
            .table = table::kStorageDomain,
            .key = db::storage_domain_key(address, location_hash),
            .timestamp = static_cast<kv::api::Timestamp>(*txn_number_),
        };
        result = co_await tx_.get_as_of(std::move(request));
    }

    if (!result.success) {
        co_return evmc::bytes32{};
    }
    co_return to_bytes32(result.value);
}

Task<std::optional<Bytes>> StateReader::read_code(const evmc::address& address, const evmc::bytes32& code_hash) const {
    if (code_hash == kEmptyHash) {
        co_return std::nullopt;
    }

    api::PointResult result;

    if (!txn_number_) {
        result = co_await latest_code_from_cache(db::code_domain_key(address));
    } else {
        db::kv::api::GetAsOfRequest request{
            .table = table::kCodeDomain,
            .key = db::code_domain_key(address),
            .timestamp = static_cast<kv::api::Timestamp>(*txn_number_),
        };
        result = co_await tx_.get_as_of(std::move(request));
    }

    if (!result.success) {
        co_return std::nullopt;
    }
    co_return result.value;
}

Task<api::PointResult> StateReader::latest_from_cache(std::string_view table, Bytes key) const {
    const auto state_view = co_await tx_.state_cache()->get_view(tx_);
    auto value = co_await state_view->get(table, std::move(key));
    api::PointResult result{.success = value.has_value()};
    if (value) {
        result.value = std::move(*value);
    }
    co_return result;
}

Task<api::PointResult> StateReader::latest_code_from_cache(Bytes key) const {
    const auto state_view = co_await tx_.state_cache()->get_view(tx_);
    auto value = co_await state_view->get_code(std::move(key));
    api::PointResult result{.success = value.has_value()};
    if (value) {
        result.value = std::move(*value);
    }
    co_return result;
}

}  // namespace silkworm::db::kv
