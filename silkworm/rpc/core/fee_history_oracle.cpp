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

#include <silkworm/core/protocol/validation.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/core/blocks.hpp>
#include <silkworm/rpc/json/types.hpp>

namespace silkworm::rpc::fee_history {

void to_json(nlohmann::json& json, const Rewards& rewards) {
    json = nlohmann::json::array();
    for (const auto& reward : rewards) {
        json.push_back(to_quantity(reward));
    }
}

void to_json(nlohmann::json& json, const FeeHistory& fh) {
    json["baseFeePerGas"] = nlohmann::json::array();
    for (const auto& fee : fh.base_fees_per_gas) {
        json["baseFeePerGas"].push_back(to_quantity(fee));
    }

    json["gasUsedRatio"] = fh.gas_used_ratio;
    json["oldestBlock"] = to_quantity(fh.oldest_block);

    json["reward"] = nlohmann::json::array();
    for (const auto& rewards : fh.rewards) {
        nlohmann::json item;
        to_json(item, rewards);
        json["reward"].push_back(item);
    }
}

Task<FeeHistory> FeeHistoryOracle::fee_history(BlockNum newest_block, BlockNum block_count, const std::vector<std::int8_t>& reward_percentile) {
    FeeHistory fee_history;
    if (block_count < 1) {
        co_return fee_history;
    }
    if (block_count > kDefaultMaxFeeHistory) {
        SILK_WARN << "FeeHistoryOracle::fee_history fee history length to long: requested " << block_count << " truncated to " << kDefaultMaxFeeHistory;
        block_count = kDefaultMaxFeeHistory;
    }

    for (size_t idx = 0; idx < reward_percentile.size(); idx++) {
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

    auto max_history = reward_percentile.size() > 0 ? kDefaultMaxBlockHistory : kDefaultMaxHeaderHistory;

    auto block_range = co_await resolve_block_range(newest_block, block_count, max_history);

    fee_history.rewards.reserve(block_range.num_blocks);
    fee_history.base_fees_per_gas.reserve(block_range.num_blocks + 1);
    fee_history.gas_used_ratio.reserve(block_range.num_blocks);

    auto oldest_block = block_range.last_block + 1 - block_range.num_blocks;
    for (auto idx = block_range.num_blocks; idx > 0; idx--) {
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
            block_fees.block = *co_await block_provider_(block_number);
            if (reward_percentile.size() > 0) {
                block_fees.receipts = co_await receipts_provider_(block_fees.block);
            }
        }

        co_await process_block(block_fees, reward_percentile);
        auto index = block_fees.block_number - oldest_block;
        fee_history.rewards[index] = block_fees.rewards;
        fee_history.base_fees_per_gas[index] = block_fees.base_fee;
        fee_history.base_fees_per_gas[index + 1] = block_fees.next_base_fee;
        fee_history.gas_used_ratio[index] = block_fees.gas_used_ratio;
    }
    // TODO(sixtysixter) firstMissing management as in erigon

    co_return fee_history;
}

Task<BlockRange> FeeHistoryOracle::resolve_block_range(BlockNum last_block, uint64_t block_count, uint64_t max_history) {
    const auto block_with_hash = co_await block_provider_(last_block);
    const auto receipts = co_await receipts_provider_(*block_with_hash);

    if (max_history != 0) {
        // limit retrieval to the given number of latest blocks
        const auto too_old_count = last_block - max_history + block_count;
        if (too_old_count > 0) {
            // tooOldCount is the number of requested blocks that are too old to be served
            if (block_count > too_old_count) {
                block_count -= too_old_count;
            } else {
                co_return BlockRange{0};
            }
        }
    }

    BlockRange block_range{block_count, last_block, *block_with_hash, receipts};

    co_return block_range;
}

Task<void> FeeHistoryOracle::process_block(BlockFees& block_fees, const std::vector<std::int8_t>& reward_percentile) {
    auto& header = block_fees.block.block.header;

    block_fees.base_fee = header.base_fee_per_gas.value_or(0);
    block_fees.gas_used_ratio = static_cast<double>(header.gas_used) / static_cast<double>(header.gas_limit);

    const auto parent_block = co_await block_provider_(header.number - 1);

    const auto evmc_revision = config_.revision(parent_block->block.header.number, parent_block->block.header.timestamp);
    block_fees.next_base_fee = 0;
    if (evmc_revision >= EVMC_LONDON) {
        block_fees.next_base_fee = protocol::expected_base_fee_per_gas(parent_block->block.header);
    }

    if (reward_percentile.size() == 0) {
        co_return;
    }
    if (block_fees.receipts.size() != block_fees.block.block.transactions.size()) {
        co_return;
    }

    if (block_fees.block.block.transactions.size() == 0) {
        std::fill(block_fees.rewards.begin(), block_fees.rewards.end(), 0);
        co_return;
    }

    std::map<intx::uint256, std::uint64_t> gas_and_rewards;
    for (size_t idx = 0; idx < block_fees.block.block.transactions.size(); idx++) {
        const auto reward = block_fees.block.block.transactions[idx].effective_gas_price(block_fees.base_fee);
        gas_and_rewards.emplace(reward, block_fees.receipts[idx].gas_used);
    }

    auto index = gas_and_rewards.begin();
    auto last = --gas_and_rewards.end();
    auto sum_gas_used = index->second;
    for (size_t idx = 0; idx < reward_percentile.size(); idx++) {
        std::uint8_t percentile = static_cast<std::uint8_t>(reward_percentile[idx]);
        std::uint64_t threshold_gas_used = header.gas_used * percentile / 100;
        while (index != last) {
            index++;
            if (sum_gas_used < threshold_gas_used) {
                sum_gas_used += index->second;
            }
        }
        block_fees.rewards[idx] = index->first;
    }

    co_return;
}
}  // namespace silkworm::rpc::fee_history
