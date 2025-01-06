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

#pragma once

#include <optional>
#include <vector>

#include <evmc/evmc.hpp>
#include <intx/intx.hpp>

#include <silkworm/core/types/bloom.hpp>
#include <silkworm/rpc/types/log.hpp>
#include <silkworm/rpc/types/transaction.hpp>

namespace silkworm::rpc {

struct Receipt {
    /* raw fields */
    TransactionType type{TransactionType::kLegacy};  // EIP-2718
    bool success{false};
    uint64_t cumulative_gas_used{0};
    silkworm::Bloom bloom{};
    Logs logs;

    /* derived fields */
    evmc::bytes32 tx_hash;
    evmc::address contract_address;
    uint64_t gas_used{0};
    evmc::bytes32 block_hash;
    BlockNum block_num{0};
    uint32_t tx_index{0};
    std::optional<evmc::address> from;
    std::optional<evmc::address> to;
    intx::uint256 effective_gas_price{0};
    std::optional<uint64_t> blob_gas_used{std::nullopt};        // EIP-4844
    std::optional<intx::uint256> blob_gas_price{std::nullopt};  // EIP-4844
};

std::ostream& operator<<(std::ostream& out, const Receipt& r);

silkworm::Bloom bloom_from_logs(const Logs& logs);

using Receipts = std::vector<Receipt>;

}  // namespace silkworm::rpc
