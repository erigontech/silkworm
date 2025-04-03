// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "storage_walker.hpp"

#include <silkworm/core/types/address.hpp>
#include <silkworm/db/datastore/kvdb/bitmap.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/ethdb/split_cursor.hpp>

namespace silkworm::rpc {

Bytes make_key(const evmc::address& address, const evmc::bytes32& location) {
    Bytes res(silkworm::kAddressLength + kHashLength, '\0');
    std::memcpy(&res[0], address.bytes, kAddressLength);
    std::memcpy(&res[kAddressLength], location.bytes, kHashLength);
    return res;
}

Task<void> StorageWalker::storage_range_at(
    TxnId txn_number,
    const evmc::address& address,
    const evmc::bytes32& start_location,
    StorageCollector& collector) {
    auto from{make_key(address, start_location)};
    auto to = db::code_domain_key(address);
    increment(to);

    db::kv::api::DomainRangeRequest query{
        .table = db::table::kStorageDomain,
        .from_key = from,
        .to_key = to,
        .timestamp = txn_number,
        .ascending_order = true};
    auto paginated_result = co_await transaction_.range_as_of(std::move(query));
    auto it = co_await paginated_result.begin();

    while (const auto value = co_await it->next()) {
        if (value->second.empty())
            continue;

        SILKWORM_ASSERT(value->first.size() >= kAddressLength);
        const auto key = value->first.substr(kAddressLength);
        auto hash = hash_of(key);
        const auto sec_key = ByteView{hash.bytes};
        if (!collector(key, sec_key, value->second))
            co_return;
    }
    co_return;
}

}  // namespace silkworm::rpc
