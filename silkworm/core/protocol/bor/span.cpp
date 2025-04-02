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

#include "span.hpp"

#include <silkworm/core/protocol/param.hpp>

namespace silkworm::protocol::bor {

std::optional<Span> get_current_span(EVM& evm, const evmc_address& validator_contract) {
    static constexpr uint8_t kFunctionSelector[]{0xaf, 0x26, 0xaa, 0x96};  // getCurrentSpan()

    Transaction system_txn{};
    system_txn.type = TransactionType::kSystem;
    system_txn.to = validator_contract;
    system_txn.data = ByteView{kFunctionSelector};
    system_txn.set_sender(kSystemAddress);

    const CallResult res{evm.execute(system_txn, kSystemCallGasLimit)};
    if (res.status != EVMC_SUCCESS || res.data.size() != 32 * 3) {
        return std::nullopt;
    }

    const auto id{intx::be::unsafe::load<intx::uint256>(&res.data[0])};
    const auto start_block{intx::be::unsafe::load<intx::uint256>(&res.data[32])};
    const auto end_block{intx::be::unsafe::load<intx::uint256>(&res.data[64])};

    if (intx::count_significant_words(id) > 1 ||
        intx::count_significant_words(start_block) > 1 ||
        intx::count_significant_words(end_block) > 1) {
        return std::nullopt;
    }

    return Span{.id = static_cast<uint64_t>(id),
                .start_block = static_cast<uint64_t>(start_block),
                .end_block = static_cast<uint64_t>(end_block)};
}

}  // namespace silkworm::protocol::bor
