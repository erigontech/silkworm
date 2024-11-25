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

#include <cstdint>
#include <functional>
#include <vector>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/block.hpp>

namespace silkworm::rpc {

inline const intx::uint256 kWei = 1;
inline const intx::uint256 kGWei = 1E9;

inline const intx::uint256 kDefaultPrice = 0;
inline const intx::uint256 kDefaultMaxPrice = 500 * kGWei;
inline const intx::uint256 kDefaultMinPrice = 2 * kWei;

inline constexpr uint8_t kCheckBlocks = 20;
inline constexpr uint8_t kSamples = 3;
inline constexpr uint8_t kMaxSamples = kCheckBlocks * kSamples;
inline constexpr uint8_t kPercentile = 60;

using BlockProvider = std::function<Task<std::shared_ptr<silkworm::BlockWithHash>>(BlockNum)>;

class GasPriceOracle {
  public:
    explicit GasPriceOracle(const BlockProvider& block_provider) : block_provider_(block_provider) {}
    virtual ~GasPriceOracle() = default;

    GasPriceOracle(const GasPriceOracle&) = delete;
    GasPriceOracle& operator=(const GasPriceOracle&) = delete;

    Task<intx::uint256> suggested_price(BlockNum block_num);

  private:
    Task<void> load_block_prices(BlockNum block_num, uint64_t limit, std::vector<intx::uint256>& tx_prices);

    const BlockProvider& block_provider_;
};

}  // namespace silkworm::rpc
