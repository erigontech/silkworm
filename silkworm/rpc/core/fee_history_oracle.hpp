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

#include <functional>
#include <limits>
#include <memory>
#include <string>
#include <vector>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/transaction.hpp>
#include <silkworm/rpc/core/blocks.hpp>
#include <silkworm/rpc/core/rawdb/accessors.hpp>

namespace silkworm::rpc::fee_history {

using BlockProvider = std::function<Task<std::shared_ptr<silkworm::BlockWithHash>>(BlockNum)>;
using ReceiptsProvider = std::function<Task<rpc::Receipts>(const BlockWithHash&)>;

using Rewards = std::vector<intx::uint256>;

struct FeeHistory {
    BlockNum oldest_block{0};
    std::vector<intx::uint256> base_fees_per_gas;
    std::vector<double> gas_used_ratio;
    std::vector<Rewards> rewards;
    std::optional<std::string> error{std::nullopt};
};

void to_json(nlohmann::json& json, const FeeHistory& fh);

struct BlockRange {
    uint64_t num_blocks;
    BlockNum last_block;
    BlockWithHash block;
    rpc::Receipts receipts;
};

struct BlockFees {
    BlockNum block_number;
    BlockWithHash block;
    rpc::Receipts receipts;
    Rewards rewards;
    intx::uint256 base_fee;
    intx::uint256 next_base_fee;
    double gas_used_ratio;
};

class FeeHistoryOracle {
  public:
    explicit FeeHistoryOracle(const silkworm::ChainConfig& config, const BlockProvider& block_provider, ReceiptsProvider& receipts_provider)
        : config_{config}, block_provider_(block_provider), receipts_provider_(receipts_provider) {}
    virtual ~FeeHistoryOracle() {}

    FeeHistoryOracle(const FeeHistoryOracle&) = delete;
    FeeHistoryOracle& operator=(const FeeHistoryOracle&) = delete;

    Task<FeeHistory> fee_history(BlockNum newest_block, BlockNum block_count, const std::vector<std::int8_t>& reward_percentile);

  private:
    static inline const std::uint32_t kDefaultMaxFeeHistory = 1024;
    static inline const std::uint32_t kDefaultMaxHeaderHistory = 300;
    static inline const std::uint32_t kDefaultMaxBlockHistory = 5;

    Task<BlockRange> resolve_block_range(BlockNum newest_block, uint64_t block_count, uint64_t max_history);
    Task<void> process_block(BlockFees& block_fees, const std::vector<std::int8_t>& reward_percentile);

    const silkworm::ChainConfig& config_;
    const BlockProvider& block_provider_;
    const ReceiptsProvider& receipts_provider_;
};

}  // namespace silkworm::rpc::fee_history
