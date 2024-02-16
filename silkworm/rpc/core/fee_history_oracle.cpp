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

#include <silkworm/core/protocol/validation.hpp>
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/json/types.hpp>

namespace silkworm::rpc::fee_history {

void to_json(nlohmann::json& json, const Rewards& rewards) {
    std::vector<std::string> rewards_list;
    for (const auto& reward : rewards) {
        rewards_list.push_back(to_quantity(reward));
    }
    json = rewards_list;
}

void to_json(nlohmann::json& json, const FeeHistory& fh) {
    if (fh.gas_used_ratio.empty()) {
        json["gasUsedRatio"] = nullptr;
    } else {
        json["gasUsedRatio"] = fh.gas_used_ratio;
    }
    json["oldestBlock"] = to_quantity(fh.oldest_block);

    if (!fh.base_fees_per_gas.empty()) {
        std::vector<std::string> fee_string_list;
        for (const auto& fee : fh.base_fees_per_gas) {
            fee_string_list.push_back(to_quantity(fee));
        }
        json["baseFeePerGas"] = fee_string_list;
    }

    if (!fh.rewards.empty()) {
        std::vector<nlohmann::json> json_list;
        for (const auto& rewards : fh.rewards) {
            nlohmann::json item;
            to_json(item, rewards);
            json_list.push_back(item);
        }
        json["reward"] = json_list;
    }
}

Task<FeeHistory> FeeHistoryOracle::fee_history(BlockNum newest_block,
                                               BlockNum block_count,
                                               const std::vector<int8_t>& reward_percentiles) {
    FeeHistory fee_history;
    if (block_count < 1) {
        co_return fee_history;
    }
    if (block_count > kDefaultMaxFeeHistory) {
        SILK_WARN << "FeeHistoryOracle::fee_history fee history length too long: requested " << block_count
                  << " truncated to " << kDefaultMaxFeeHistory;
        block_count = kDefaultMaxFeeHistory;
    }

    for (size_t idx = 0; idx < reward_percentiles.size(); idx++) {
        if (reward_percentiles[idx] < 0 || reward_percentiles[idx] > 100) {
            std::ostringstream ss;
            ss << "ErrInvalidPercentile: " << std::dec << reward_percentiles[idx];
            fee_history.error = ss.str();
            co_return fee_history;
        }
        if (idx > 0 && reward_percentiles[idx] < reward_percentiles[idx - 1]) {
            std::ostringstream ss;
            ss << "ErrInvalidPercentile: #" << idx - 1 << ":" << reward_percentiles[idx - 1]
               << "> #" << idx << ":" << reward_percentiles[idx];
            fee_history.error = ss.str();
            co_return fee_history;
        }
    }

    // Only process blocks if reward percentiles were requested
    const auto max_history = reward_percentiles.empty() ? kDefaultMaxHeaderHistory : kDefaultMaxBlockHistory;

    const auto block_range = co_await resolve_block_range(newest_block, block_count, max_history);
    if (block_range.num_blocks == 0) {
        co_return fee_history;
    }
    fee_history.rewards.resize(block_range.num_blocks);
    fee_history.base_fees_per_gas.resize(block_range.num_blocks + 1);
    fee_history.gas_used_ratio.resize(block_range.num_blocks);

    const auto oldest_block_number = block_range.last_block_number + 1 - block_range.num_blocks;
    auto first_missing = block_range.num_blocks;
    for (auto idx = block_range.num_blocks, next = oldest_block_number; idx > 0; idx--) {
        const auto block_number = ++next - 1;
        if (block_number > block_range.last_block_number) {
            continue;
        }

        BlockFees block_fees{block_number};
        if (block_number >= block_range.last_block->block.header.number) {
            block_fees.block = block_range.last_block;
            block_fees.receipts = co_await receipts_provider_(*block_fees.block);
        } else {
            const auto block_with_hash = co_await block_provider_(block_number);
            if (!block_with_hash) {
                continue;
            }
            block_fees.block = block_with_hash;
            if (!reward_percentiles.empty()) {
                block_fees.receipts = co_await receipts_provider_(*block_fees.block);
            }
        }
        co_await process_block(block_fees, reward_percentiles);

        ensure(block_fees.block_number >= oldest_block_number, "fee_history: block_number lower than oldest");
        const auto index = block_fees.block_number - oldest_block_number;
        if (block_fees.block) {
            fee_history.rewards[index] = block_fees.rewards;
            fee_history.base_fees_per_gas[index] = block_fees.base_fee;
            fee_history.base_fees_per_gas[index + 1] = block_fees.next_base_fee;
            fee_history.gas_used_ratio[index] = block_fees.gas_used_ratio;
        } else {
            // Getting no block and no error means we are requesting into the future (might happen because of a reorg)
            if (index < first_missing) {
                first_missing = index;
            }
        }
    }
    if (first_missing == 0) {
        co_return FeeHistory{};
    }
    if (!reward_percentiles.empty()) {
        fee_history.rewards.resize(first_missing);
    } else {
        fee_history.rewards.clear();
    }
    fee_history.base_fees_per_gas.resize(first_missing + 1);
    fee_history.gas_used_ratio.resize(first_missing);
    fee_history.oldest_block = oldest_block_number;

    co_return fee_history;
}

Task<BlockRange> FeeHistoryOracle::resolve_block_range(BlockNum newest_block, uint64_t block_count, uint64_t max_history) {
    const auto block_with_hash = co_await block_provider_(newest_block);
    if (!block_with_hash) {
        co_return BlockRange{0};
    }

    if (max_history != 0) {
        const auto latest_block_number = co_await latest_block_provider_();
        // Limit retrieval to the given number of latest blocks
        const auto too_old_count = latest_block_number - max_history - newest_block + block_count;
        if (too_old_count > 0) {
            // too_old_count is the number of requested blocks that are too old to be served
            if (block_count > too_old_count) {
                block_count -= too_old_count;
            } else {
                co_return BlockRange{0};
            }
        }
    }

    // Ensure not trying to retrieve before genesis
    if (block_count > newest_block + 1) {
        block_count = newest_block + 1;
    }

    const auto receipts = co_await receipts_provider_(*block_with_hash);

    co_return BlockRange{block_count, newest_block, block_with_hash, receipts};
}

bool sort_by_reward(std::pair<intx::uint256, uint64_t>& p1, const std::pair<intx::uint256, uint64_t>& p2) {
    return (p1.first < p2.first);
}

Task<void> FeeHistoryOracle::process_block(BlockFees& block_fees, const std::vector<int8_t>& reward_percentiles) {
    auto& header = block_fees.block->block.header;
    block_fees.base_fee = header.base_fee_per_gas.value_or(0);

    block_fees.gas_used_ratio = static_cast<double>(header.gas_used) / static_cast<double>(header.gas_limit);

    const auto parent_block = co_await block_provider_(header.number + 1);
    if (!parent_block) {
        co_return;
    }
    const auto evmc_revision = config_.revision(parent_block->block.header.number, parent_block->block.header.timestamp);
    block_fees.next_base_fee = 0;
    if (evmc_revision >= EVMC_LONDON) {
        block_fees.next_base_fee = protocol::expected_base_fee_per_gas(header);
    }

    if (reward_percentiles.empty()) {
        co_return;
    }
    if (block_fees.receipts.size() != block_fees.block->block.transactions.size()) {
        co_return;
    }

    if (block_fees.block->block.transactions.empty()) {
        std::fill(block_fees.rewards.begin(), block_fees.rewards.end(), 0);
        // return an all zero row if there are no transactions to gather data from
        for (size_t idx = 0; idx < reward_percentiles.size(); idx++) {
            block_fees.rewards.emplace_back(0);
        }
        co_return;
    }
    std::vector<std::pair<intx::uint256, uint64_t> > rewards_and_gas;
    for (size_t idx = 0; idx < block_fees.block->block.transactions.size(); idx++) {
        auto& txn = block_fees.block->block.transactions[idx];
        const auto reward{txn.max_fee_per_gas >= block_fees.base_fee ? txn.effective_gas_price(block_fees.base_fee) - block_fees.base_fee
                                                                     : txn.max_priority_fee_per_gas};
        rewards_and_gas.emplace_back(reward, block_fees.receipts[idx].gas_used);
    }
    sort(rewards_and_gas.begin(), rewards_and_gas.end(), sort_by_reward);

    auto index = rewards_and_gas.begin();
    const auto last = --rewards_and_gas.end();
    auto sum_gas_used = index->second;
    for (const auto percentile : reward_percentiles) {
        const uint64_t threshold_gas_used = header.gas_used * static_cast<uint8_t>(percentile) / 100;
        while (sum_gas_used < threshold_gas_used && index != last) {
            index++;
            sum_gas_used += index->second;
        }
        block_fees.rewards.push_back(index->first);
    }

    co_return;
}

}  // namespace silkworm::rpc::fee_history
