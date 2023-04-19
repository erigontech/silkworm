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

#include "fee_history_oracle.hpp"

#include <algorithm>

#include <boost/asio/post.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <silkworm/silkrpc/common/log.hpp>
#include <silkworm/silkrpc/core/blocks.hpp>

namespace silkworm::rpc::fee_history {

boost::asio::awaitable<FeeHistory> FeeHistoryOracle::fee_history(uint64_t newest_block, uint64_t block_count, const std::vector<int32_t>& reward_percentile) {
    FeeHistory fee_history;
    if (block_count < 1) {
        co_return fee_history;
    }
    if (block_count > DEFAULT_MAX_FEE_HISTORY) {
        SILKRPC_WARN << "FeeHistoryOracle::fee_history fee history length to long: requested " << block_count << " truncated to " << DEFAULT_MAX_FEE_HISTORY << "\n";
        block_count = DEFAULT_MAX_FEE_HISTORY;
    }

    for (uint32_t idx = 0; idx < reward_percentile.size(); idx++) {
        if (reward_percentile[idx] < 0 || reward_percentile[idx] > 100) {
            std::ostringstream ss;
            ss << "ErrInvalidPercentile: " << std::dec << reward_percentile[idx];

            fee_history.error = ss.str();
            co_return fee_history;
        }
        if (idx > 0 && reward_percentile[idx] < reward_percentile[idx - 1]) {
            std::ostringstream ss;
            ss << "ErrInvalidPercentile: #" << idx - 1 << ":" << reward_percentile[idx - 1]
               << "> #" << idx << ":" << reward_percentile[idx];
            fee_history.error = ss.str();
            co_return fee_history;
        }
    }

    auto max_history = reward_percentile.size() > 0 ? DEFAULT_MAX_BLOCK_HISTORY : DEFAULT_MAX_HEADER_HISTORY;

    auto block_range = co_await resolve_block_range(newest_block, block_count, max_history);

    fee_history.rewards.reserve(block_range.num_block);
    fee_history.base_fees.reserve(block_range.num_block + 1);
    fee_history.gas_used_ratio.reserve(block_range.num_block);

    auto oldest_block = block_range.last_block + 1 - block_range.num_block;
    for (auto idx = block_range.num_block; idx > 0; idx--) {
        auto block_number = ++oldest_block - 1;

        if (block_number > block_range.last_block) {
            continue;
        }
        BlockFees block_fees{block_number};

        if (block_number >= block_range.block.block.header.number) {
            block_fees.block = block_range.block;
            block_fees.receipts = co_await receipts_provider_(block_fees.block);
            ;
        } else {
            block_fees.block = co_await block_provider_(block_number);
            if (reward_percentile.size() > 0) {
                block_fees.receipts = co_await receipts_provider_(block_fees.block);
                ;
            }
        }

        co_await process_block(block_fees, reward_percentile);
        auto index = block_fees.block_number - oldest_block;
        fee_history.rewards[index] = block_fees.rewards;
        fee_history.base_fees[index] = block_fees.base_fee;
        fee_history.base_fees[index + 1] = block_fees.next_base_fee;
        fee_history.gas_used_ratio[index] = block_fees.gas_used_ratio;
    }
    // TODO firstMissing management as in erigon
    co_return fee_history;
}

boost::asio::awaitable<BlockRange> FeeHistoryOracle::resolve_block_range(uint64_t last_block, uint64_t /*block_count*/, uint64_t /*max_history*/) {
    // BlockWithHash pending_block;
    // uint64_t head_block_number;
    // if (last_block == kPendingBlockNumber) {
    //     pending_block = co_await block_provider_(rpc::core::kPendingBlockId);
    //     head_block_number = pending_block.block.header.number - 1;
    // }
    const auto block_with_hash = co_await block_provider_(last_block);
    const auto receipts = co_await receipts_provider_(block_with_hash);

    BlockRange block_range;

    co_return block_range;
}

boost::asio::awaitable<void> FeeHistoryOracle::process_block(BlockFees& /*block_fees*/, const std::vector<int32_t>& /*reward_percentile*/) {
    co_return;
}

}  // namespace silkworm::rpc::fee_history
