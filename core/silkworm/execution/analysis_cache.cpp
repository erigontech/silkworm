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

#include "analysis_cache.hpp"

#include <memory>
#include <utility>

#include <evmone/analysis.hpp>

namespace silkworm {

std::shared_ptr<evmone::AdvancedCodeAnalysis> AnalysisCache::get(const evmc::bytes32& key,
                                                                 evmc_revision revision) noexcept {
    if (revision_ == revision) {
        const auto* ptr{cache_.get(key)};
        return ptr ? *ptr : nullptr;
    } else {
        return nullptr;
    }
}

void AnalysisCache::put(const evmc::bytes32& key, const std::shared_ptr<evmone::AdvancedCodeAnalysis>& analysis,
                        evmc_revision revision) noexcept {
    if (revision_ != revision) {
        // multiple revisions are not supported
        cache_.clear();
    }
    revision_ = revision;

    cache_.put(key, analysis);
}

}  // namespace silkworm
