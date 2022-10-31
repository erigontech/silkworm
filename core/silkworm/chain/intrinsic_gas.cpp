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

#include "intrinsic_gas.hpp"

#include <algorithm>

#include <silkworm/common/as_range.hpp>

#include "protocol_param.hpp"

namespace silkworm {

intx::uint128 intrinsic_gas(const Transaction& txn, const evmc_revision rev) noexcept {
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

    const intx::uint128 data_len{txn.data.length()};
    if (data_len == 0) {
        return gas;
    }

    const intx::uint128 non_zero_bytes{as_range::count_if(txn.data, [](uint8_t c) { return c != 0; })};
    const intx::uint128 nonZeroGas{rev >= EVMC_ISTANBUL ? fee::kGTxDataNonZeroIstanbul : fee::kGTxDataNonZeroFrontier};
    gas += non_zero_bytes * nonZeroGas;
    const intx::uint128 zero_bytes{data_len - non_zero_bytes};
    gas += zero_bytes * fee::kGTxDataZero;

    // EIP-3860: Limit and meter initcode
    if (contract_creation && rev >= EVMC_SHANGHAI) {
        const intx::uint128 num_words{(data_len + 31) / 32};
        gas += num_words * fee::kInitCodeWordCost;
    }

    return gas;
}

}  // namespace silkworm
