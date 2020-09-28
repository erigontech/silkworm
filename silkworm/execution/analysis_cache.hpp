/*
   Copyright 2020 The Silkworm Authors

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

#ifndef SILKWORM_EXECUTION_ANALYSIS_CACHE_H_
#define SILKWORM_EXECUTION_ANALYSIS_CACHE_H_

#include <cpp-lru-cache/include/lrucache.hpp>
#include <evmc/evmc.hpp>
#include <memory>
#include <silkworm/common/base.hpp>

namespace evmone {
struct code_analysis;
}

namespace silkworm {

class AnalysisCache {
   public:
    static constexpr size_t kMaxSize{50'000};

    static AnalysisCache& instance() noexcept;

    AnalysisCache(const AnalysisCache&) = delete;
    AnalysisCache& operator=(const AnalysisCache&) = delete;

    void update_revision(evmc_revision revision) noexcept;

    bool exists(const evmc::bytes32& key) const noexcept { return cache_.exists(key); }

    std::shared_ptr<evmone::code_analysis> get(const evmc::bytes32& key) noexcept { return cache_.get(key); }

    void put(const evmc::bytes32& key, evmone::code_analysis&& value) noexcept;

   private:
    AnalysisCache() : cache_{kMaxSize} {}

    cache::lru_cache<evmc::bytes32, std::shared_ptr<evmone::code_analysis>> cache_;
    evmc_revision revision_{EVMC_MAX_REVISION};
};
}  // namespace silkworm

#endif  // SILKWORM_EXECUTION_ANALYSIS_CACHE_H_
