// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "intrinsic_gas.hpp"

#include <algorithm>

#include "param.hpp"

namespace silkworm::protocol {

intx::uint128 intrinsic_gas(const UnsignedTransaction& txn, const evmc_revision rev) noexcept {
    intx::uint128 gas{fee::kGTransaction};

    const bool contract_creation{!txn.to};
    if (contract_creation && rev >= EVMC_HOMESTEAD) {
        gas += fee::kGTxCreate;
    }

    // EIP-2930: Optional access lists
    gas += intx::uint128{txn.access_list.size()} * fee::kAccessListAddressCost;
    intx::uint128 total_num_of_storage_keys{0};
    for (const AccessListEntry& e : txn.access_list) {
        total_num_of_storage_keys += e.storage_keys.size();
    }
    gas += total_num_of_storage_keys * fee::kAccessListStorageKeyCost;

    // EIP-7702 Set EOA account code
    gas += txn.authorizations.size() * fee::kPerEmptyAccountCost;

    const uint64_t data_len{txn.data.size()};
    if (data_len == 0) {
        return gas;
    }

    const intx::uint128 non_zero_bytes{std::ranges::count_if(txn.data, [](uint8_t c) { return c != 0; })};
    const intx::uint128 non_zero_gas{rev >= EVMC_ISTANBUL ? fee::kGTxDataNonZeroIstanbul : fee::kGTxDataNonZeroFrontier};
    gas += non_zero_bytes * non_zero_gas;
    const intx::uint128 zero_bytes{data_len - non_zero_bytes};
    gas += zero_bytes * fee::kGTxDataZero;

    // EIP-3860: Limit and meter initcode
    if (contract_creation && rev >= EVMC_SHANGHAI) {
        gas += num_words(data_len) * fee::kInitCodeWordCost;
    }

    return gas;
}

// EIP-7623: Increase calldata cost
uint64_t floor_cost(const UnsignedTransaction& txn) noexcept {
    const uint64_t zero_bytes = static_cast<uint64_t>(std::ranges::count(txn.data, 0));
    const uint64_t non_zero_bytes{txn.data.size() - zero_bytes};
    return fee::kGTransaction + (zero_bytes + non_zero_bytes * 4) * fee::kTotalCostFloorPerToken;
}

}  // namespace silkworm::protocol
