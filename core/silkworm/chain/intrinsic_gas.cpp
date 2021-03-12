/*
   Copyright 2021 The Silkworm Authors

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

#include "protocol_param.hpp"

namespace silkworm {

intx::uint128 intrinsic_gas(const Transaction& txn, bool homestead, bool istanbul) noexcept {
    intx::uint128 gas{fee::kGTransaction};

    if (!txn.to && homestead) {
        gas += fee::kGTxCreate;
    }

    // https://eips.ethereum.org/EIPS/eip-2930
    gas += intx::uint128{txn.access_list.size()} * fee::kAccessListAddressCost;
    for (const AccessListEntry& e : txn.access_list) {
        gas += intx::uint128{e.storage_keys.size()} * fee::kAccessListStorageKeyCost;
    }

    if (txn.data.empty()) {
        return gas;
    }

    intx::uint128 non_zero_bytes{std::count_if(txn.data.begin(), txn.data.end(), [](char c) { return c != 0; })};

    uint64_t nonZeroGas{istanbul ? fee::kGTxDataNonZeroIstanbul : fee::kGTxDataNonZeroFrontier};
    gas += non_zero_bytes * nonZeroGas;

    intx::uint128 zero_bytes{txn.data.length() - non_zero_bytes};
    gas += zero_bytes * fee::kGTxDataZero;

    return gas;
}

}  // namespace silkworm
