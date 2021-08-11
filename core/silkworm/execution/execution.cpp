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

#include "processor.hpp"

namespace silkworm {

ValidationResult execute_block(const Block& block, StateBuffer& buffer, const ChainConfig& config,
                               std::vector<Receipt>& receipts, AnalysisCache* analysis_cache,
                               ExecutionStatePool* state_pool, evmc_vm* exo_evm) noexcept {
    IntraBlockState state{buffer};
    ExecutionProcessor processor{block, state, config};
    processor.evm().advanced_analysis_cache = analysis_cache;
    processor.evm().state_pool = state_pool;
    processor.evm().exo_evm = exo_evm;

    return processor.execute_and_write_block(receipts);
}

}  // namespace silkworm
