/*
   Copyright 2020-2021 The Silkworm Authors

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

#include "execution.hpp"

#include <silkworm/trie/vector_root.hpp>

#include "processor.hpp"

namespace silkworm {

ValidationResult execute_block(const Block& block, StateBuffer& buffer, const ChainConfig& config,
                               std::vector<Receipt>& receipts, AnalysisCache* analysis_cache,
                               ExecutionStatePool* state_pool, evmc_vm* exo_evm) noexcept {
    const BlockHeader& header{block.header};
    const uint64_t block_num{header.number};

    IntraBlockState state{buffer};
    ExecutionProcessor processor{block, state, config};
    processor.evm().advanced_analysis_cache = analysis_cache;
    processor.evm().state_pool = state_pool;
    processor.evm().exo_evm = exo_evm;

    if (const ValidationResult res{processor.execute_block(receipts)}; res != ValidationResult::kOk) {
        return res;
    }

    uint64_t gas_used{0};
    if (!receipts.empty()) {
        gas_used = receipts.back().cumulative_gas_used;
    }

    if (gas_used != header.gas_used) {
        return ValidationResult::kWrongBlockGas;
    }

    const evmc_revision rev{config.revision(block_num)};
    if (rev >= EVMC_BYZANTIUM) {
        static constexpr auto kEncoder = [](Bytes& to, const Receipt& r) { rlp::encode(to, r); };
        evmc::bytes32 receipt_root{trie::root_hash(receipts, kEncoder)};
        if (receipt_root != header.receipts_root) {
            return ValidationResult::kWrongReceiptsRoot;
        }
    }

    Bloom bloom{};  // zero initialization
    for (const Receipt& receipt : receipts) {
        join(bloom, receipt.bloom);
    }
    if (bloom != header.logs_bloom) {
        return ValidationResult::kWrongLogsBloom;
    }

    processor.evm().state().write_to_db(block_num);

    return ValidationResult::kOk;
}

}  // namespace silkworm
