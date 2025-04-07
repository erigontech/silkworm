// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/transaction.hpp>
#include <silkworm/rpc/core/block_reader.hpp>

namespace silkworm::rpc::fee_history {

using BlockHeaderProvider = std::function<Task<std::optional<silkworm::BlockHeader>>(BlockNum)>;
using BlockProvider = std::function<Task<std::shared_ptr<silkworm::BlockWithHash>>(BlockNum)>;
using ReceiptsProvider = std::function<Task<rpc::Receipts>(const BlockWithHash&)>;
using LatestBlockProvider = std::function<Task<uint64_t>()>;

using Rewards = std::vector<intx::uint256>;

struct FeeHistory {
    BlockNum oldest_block{0};
    std::vector<intx::uint256> base_fees_per_gas;
    std::vector<double> gas_used_ratio;
    std::vector<Rewards> rewards;
    std::vector<double> blob_gas_used_ratio;
    std::vector<intx::uint256> blob_base_fees_per_gas;
    std::optional<std::string> error{std::nullopt};
};

void to_json(nlohmann::json& json, const FeeHistory& fh);

struct BlockRange {
    uint64_t num_blocks{0};
    BlockNum last_block_num{0};
    std::optional<std::string> error;
};

struct BlockFees {
    BlockNum block_num{0};
    std::optional<BlockHeader> block_header;
    std::shared_ptr<BlockWithHash> block;  // only set if reward percentiles are requested
    rpc::Receipts receipts;
    Rewards rewards;
    intx::uint256 base_fee;
    intx::uint256 next_base_fee;
    intx::uint256 blob_base_fee;
    intx::uint256 next_blob_base_fee;
    double gas_used_ratio{0};
    double blob_gas_used_ratio{0};
};

class FeeHistoryOracle {
  public:
    explicit FeeHistoryOracle(const silkworm::ChainConfig& config, const BlockHeaderProvider& header_provider, const BlockProvider& block_provider, ReceiptsProvider& receipts_provider,
                              LatestBlockProvider& latest_block_provider)
        : config_{config}, block_header_provider_(header_provider), block_provider_(block_provider), receipts_provider_(receipts_provider), latest_block_provider_{latest_block_provider} {}
    virtual ~FeeHistoryOracle() = default;

    FeeHistoryOracle(const FeeHistoryOracle&) = delete;
    FeeHistoryOracle& operator=(const FeeHistoryOracle&) = delete;

    Task<FeeHistory> fee_history(BlockNum newest_block, BlockNum block_count, const std::vector<int8_t>& reward_percentiles);

  private:
    static constexpr std::uint32_t kDefaultMaxFeeHistory{1024};
    static constexpr std::uint32_t kDefaultMaxHeaderHistory{0};
    static constexpr std::uint32_t kDefaultMaxBlockHistory{0};

    Task<BlockRange> resolve_block_range(BlockNum newest_block, uint64_t block_count, uint64_t max_history);
    Task<void> process_block(BlockFees& block_fees, const std::vector<int8_t>& reward_percentiles);

    const silkworm::ChainConfig& config_;
    const BlockHeaderProvider& block_header_provider_;
    const BlockProvider& block_provider_;
    const ReceiptsProvider& receipts_provider_;
    const LatestBlockProvider& latest_block_provider_;
};

}  // namespace silkworm::rpc::fee_history
