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

#ifndef SILKWORM_EXECUTION_ANALYSIS_CACHE_HPP_
#define SILKWORM_EXECUTION_ANALYSIS_CACHE_HPP_

#include <memory>

#include <silkworm/common/base.hpp>
#include <silkworm/common/lru_cache.hpp>

namespace evmone {
struct AdvancedCodeAnalysis;
}

namespace silkworm {

/** @brief Cache of EVM analyses.
 *
 * Analyses performed for different EVM revisions do not coexist in the cache
 * and all other revisions are evicted on revision update.
 */
class AnalysisCache {
  public:
    static constexpr size_t kDefaultMaxSize{5'000};

    explicit AnalysisCache(size_t maxSize = kDefaultMaxSize) : cache_{maxSize} {}

    AnalysisCache(const AnalysisCache&) = delete;
    AnalysisCache& operator=(const AnalysisCache&) = delete;

    /** @brief Gets an EVM analysis from the cache.
     * A nullptr is returned if there's nothing in the cache for this key & revision.
     */
    std::shared_ptr<evmone::AdvancedCodeAnalysis> get(const evmc::bytes32& key, evmc_revision revision) noexcept;

    /** @brief Puts an EVM analysis into the cache.
     * All cache entries for other EVM revisions are evicted.
     */
    void put(const evmc::bytes32& key, const std::shared_ptr<evmone::AdvancedCodeAnalysis>& analysis,
             evmc_revision revision) noexcept;

  private:
    lru_cache<evmc::bytes32, std::shared_ptr<evmone::AdvancedCodeAnalysis>> cache_;
    evmc_revision revision_{EVMC_MAX_REVISION};
};

}  // namespace silkworm

#endif  // SILKWORM_EXECUTION_ANALYSIS_CACHE_HPP_
