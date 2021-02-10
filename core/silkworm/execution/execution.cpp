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

std::pair<std::vector<Receipt>, ValidationResult> execute_block(const Block& block, StateBuffer& buffer,
                                                                const ChainConfig& config,
                                                                AnalysisCache* analysis_cache,
                                                                ExecutionStatePool* state_pool) noexcept {
    const BlockHeader& header{block.header};
    uint64_t block_num{header.number};

    IntraBlockState state{buffer};
    ExecutionProcessor processor{block, state, config};
    processor.evm().analysis_cache = analysis_cache;
    processor.evm().state_pool = state_pool;

    std::pair<std::vector<Receipt>, ValidationResult> res{processor.execute_block()};

    const auto& receipts{res.first};
    auto& err{res.second};
    if (err != ValidationResult::kOk) {
        return res;
    }

    uint64_t gas_used{0};
    if (!receipts.empty()) {
        gas_used = receipts.back().cumulative_gas_used;
    }

    if (gas_used != header.gas_used) {
        err = ValidationResult::kWrongBlockGas;
        return res;
    }

    if (config.has_byzantium(block_num)) {
        evmc::bytes32 receipt_root{trie::root_hash(receipts)};
        if (receipt_root != header.receipts_root) {
            err = ValidationResult::kWrongReceiptsRoot;
            return res;
        }
    }

    Bloom bloom{};  // zero initialization
    for (const Receipt& receipt : receipts) {
        join(bloom, receipt.bloom);
    }
    if (bloom != header.logs_bloom) {
        err = ValidationResult::kWrongLogsBloom;
        return res;
    }

    processor.evm().state().write_to_db(block_num);

    return res;
}

}  // namespace silkworm
