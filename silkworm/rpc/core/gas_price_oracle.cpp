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

#include "gas_price_oracle.hpp"

#include <algorithm>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/core/blocks.hpp>

namespace silkworm::rpc {

struct PriceComparator {
    bool operator()(const intx::uint256& p1, const intx::uint256& p2) const {
        return p1 < p2;
    }
};

Task<intx::uint256> GasPriceOracle::suggested_price(BlockNum block_number) {
    SILK_TRACE << "GasPriceOracle::suggested_price starting block: " << block_number;
    std::vector<intx::uint256> tx_prices;
    tx_prices.reserve(kMaxSamples);
    while (tx_prices.size() < kMaxSamples && block_number > 0) {
        co_await load_block_prices(block_number, kSamples, tx_prices);
        block_number--;
    }
    SILK_TRACE << "GasPriceOracle::suggested_price ending block: " << block_number;

    std::sort(tx_prices.begin(), tx_prices.end(), PriceComparator());

    intx::uint256 price = kDefaultPrice;
    if (!tx_prices.empty()) {
        auto position = (tx_prices.size() - 1) * kPercentile / 100;
        SILK_TRACE << "GasPriceOracle::suggested_price getting price in position: " << position;

        if (tx_prices.size() > position) {
            price = tx_prices[position];
        }
    }

    if (price > kDefaultMaxPrice) {
        SILK_TRACE << "GasPriceOracle::suggested_price price to high: set to 0x" << intx::hex(kDefaultMaxPrice);
        price = kDefaultMaxPrice;
    }

    SILK_TRACE << "GasPriceOracle::suggested_price price: 0x" << intx::hex(price);

    co_return price;
}

Task<void> GasPriceOracle::load_block_prices(BlockNum block_number, uint64_t limit, std::vector<intx::uint256>& tx_prices) {
    SILK_TRACE << "GasPriceOracle::load_block_prices processing block: " << block_number;

    const auto block_with_hash = co_await block_provider_(block_number);
    if (!block_with_hash) {
        throw std::invalid_argument("GasPriceOracle::load_block_prices invalid block number");
    }

    const auto& base_fee = block_with_hash->block.header.base_fee_per_gas.value_or(0);
    const auto& coinbase = block_with_hash->block.header.beneficiary;

    SILK_TRACE << "GasPriceOracle::load_block_prices # transactions in block: " << block_with_hash->block.transactions.size();
    SILK_TRACE << "GasPriceOracle::load_block_prices # block base_fee: 0x" << intx::hex(base_fee);
    SILK_TRACE << "GasPriceOracle::load_block_prices # block beneficiary: " << coinbase;

    std::vector<intx::uint256> block_prices;
    int idx = 0;
    block_prices.reserve(block_with_hash->block.transactions.size());
    for (const auto& transaction : block_with_hash->block.transactions) {
        const auto priority_fee_per_gas = transaction.priority_fee_per_gas(base_fee);
        SILK_TRACE << "idx: " << idx++
                   << " hash: " << silkworm::to_hex(transaction.hash().bytes)
                   << " priority_fee_per_gas: 0x" << intx::hex(transaction.priority_fee_per_gas(base_fee))
                   << " max_fee_per_gas: 0x" << intx::hex(transaction.max_fee_per_gas)
                   << " max_priority_fee_per_gas: 0x" << intx::hex(transaction.max_priority_fee_per_gas);
        if (priority_fee_per_gas < kDefaultMinPrice) {
            continue;
        }

        if (transaction.sender() == coinbase) {
            continue;
        }
        block_prices.push_back(priority_fee_per_gas);
    }

    std::sort(block_prices.begin(), block_prices.end(), PriceComparator());

    for (int count = 0; const auto& priority_fee_per_gas : block_prices) {
        SILK_TRACE << " priority_fee_per_gas : 0x" << intx::hex(priority_fee_per_gas);
        tx_prices.push_back(priority_fee_per_gas);
        if (++count >= int(limit)) {
            break;
        }
    }
}

}  // namespace silkworm::rpc
