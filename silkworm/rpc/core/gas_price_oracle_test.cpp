// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "gas_price_oracle.hpp"

#include <algorithm>
#include <iostream>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/endian/conversion.hpp>
#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>

#include <silkworm/rpc/common/worker_pool.hpp>
#include <silkworm/rpc/types/block.hpp>

namespace silkworm::rpc {

static const evmc::address kBeneficiary = 0xe5ef458d37212a06e3f59d40c454e76150ae7c31_address;
static const evmc::address kFromTnx1 = 0xe5ef458d37212a06e3f59d40c454e76150ae7c32_address;
static const evmc::address kFromTnx2 = 0xe5ef458d37212a06e3f59d40c454e76150ae7c33_address;

struct FixedBlockData {
    intx::uint256 base_fee;
    intx::uint256 max_priority_fee_per_gas_tx1;
    intx::uint256 max_fee_per_gas_tx1;
    intx::uint256 max_priority_fee_per_gas_tx2;
    intx::uint256 max_fee_per_gas_tx2;
};

struct VariableBlockData {
    intx::uint256 base_fee;
    intx::uint256 max_priority_fee_per_gas;
    int delta_max_priority_fee_per_gas;
    intx::uint256 max_fee_per_gas;
    int delta_max_fee_per_gas;
};

static silkworm::BlockWithHash allocate_block(BlockNum block_num,
                                              const evmc::address& beneficiary, const FixedBlockData& block_data) {
    silkworm::BlockWithHash block_with_hash;

    block_with_hash.block.header.number = block_num;
    block_with_hash.block.header.beneficiary = beneficiary;
    block_with_hash.block.header.base_fee_per_gas = block_data.base_fee;

    block_with_hash.block.transactions.resize(2);
    block_with_hash.block.transactions[0].max_priority_fee_per_gas = block_data.max_priority_fee_per_gas_tx1;
    block_with_hash.block.transactions[0].max_fee_per_gas = block_data.max_fee_per_gas_tx1;
    block_with_hash.block.transactions[0].set_sender(kFromTnx1);

    block_with_hash.block.transactions[1].max_priority_fee_per_gas = block_data.max_priority_fee_per_gas_tx2;
    block_with_hash.block.transactions[1].max_fee_per_gas = block_data.max_fee_per_gas_tx2;
    block_with_hash.block.transactions[1].set_sender(kFromTnx2);

    return block_with_hash;
}

static void fill_blocks_vector(std::vector<silkworm::BlockWithHash>& blocks,
                               const evmc::address& beneficiary, const FixedBlockData& block_data) {
    for (auto idx = 0u; idx < blocks.capacity(); ++idx) {
        silkworm::BlockWithHash block_with_hash = allocate_block(static_cast<uint64_t>(idx), beneficiary, block_data);
        blocks.push_back(block_with_hash);
    }
}

static void fill_blocks_vector(std::vector<silkworm::BlockWithHash>& blocks, const evmc::address& beneficiary,
                               const VariableBlockData& variable_block_data) {
    for (auto idx = 0; idx < static_cast<int>(blocks.capacity()); ++idx) {
        int64_t max_priority = int64_t{variable_block_data.max_priority_fee_per_gas} + variable_block_data.delta_max_priority_fee_per_gas * idx;
        max_priority = std::max<int64_t>(max_priority, 0);
        int64_t max_fee = int64_t{variable_block_data.max_fee_per_gas} + variable_block_data.delta_max_fee_per_gas * idx;
        max_fee = std::max<int64_t>(max_fee, 0);

        FixedBlockData block_data = {
            variable_block_data.base_fee,
            intx::uint256{max_priority},
            intx::uint256{max_fee},
            intx::uint256{max_priority},
            intx::uint256{max_fee}};
        silkworm::BlockWithHash block_with_hash = allocate_block(static_cast<uint64_t>(idx), beneficiary, block_data);
        blocks.push_back(block_with_hash);
    }
}

TEST_CASE("suggested price") {
    WorkerPool pool{1};

    std::vector<silkworm::BlockWithHash> blocks;

    BlockProvider block_provider = [&](BlockNum block_num) -> Task<std::shared_ptr<silkworm::BlockWithHash>> {
        auto block_with_hash = std::make_shared<silkworm::BlockWithHash>();
        *block_with_hash = blocks[block_num];
        co_return block_with_hash;
    };
    GasPriceOracle gas_price_oracle{block_provider};

    SECTION("when there is no block in chain") {
        FixedBlockData data = {0, 0x32, 0x32, 0x32, 0x32};
        const intx::uint256 expected_price = kDefaultPrice;

        blocks.reserve(1);
        fill_blocks_vector(blocks, kBeneficiary, data);

        auto result = boost::asio::co_spawn(pool, gas_price_oracle.suggested_price(0), boost::asio::use_future);
        const intx::uint256& price = result.get();

        CHECK(price == expected_price);
    }

    SECTION("when there is just 1 block in chain with 0x0 base fee") {
        FixedBlockData data = {0, 0x32, 0x32, 0x32, 0x32};
        const intx::uint256 expected_price = 0x32;

        blocks.reserve(2);
        fill_blocks_vector(blocks, kBeneficiary, data);

        auto result = boost::asio::co_spawn(pool, gas_price_oracle.suggested_price(1), boost::asio::use_future);
        const intx::uint256& price = result.get();

        CHECK(price == expected_price);
    }

    SECTION("when there is just 1 block in chain with 0x7 base fee") {
        FixedBlockData data = {0x7, 0x32, 0x32, 0x32, 0x32};
        const intx::uint256 expected_price = 0x2b;

        blocks.reserve(2);
        fill_blocks_vector(blocks, kBeneficiary, data);

        auto result = boost::asio::co_spawn(pool, gas_price_oracle.suggested_price(1), boost::asio::use_future);
        const intx::uint256& price = result.get();

        CHECK(price == expected_price);
    }

    SECTION("when there is just 1 block in chain with 0x7 base fee and different max_priority and max_fee in tnxs") {
        FixedBlockData data = {0x7, 0x0, 0x32, 0x32, 0x32};
        const intx::uint256 expected_price = 0x2b;

        blocks.reserve(2);
        fill_blocks_vector(blocks, kBeneficiary, data);

        auto result = boost::asio::co_spawn(pool, gas_price_oracle.suggested_price(1), boost::asio::use_future);
        const intx::uint256& price = result.get();

        CHECK(price == expected_price);
    }

    SECTION("when there are 20 blocks with 0x0 base fee and same max_priority and max_fee in tnxs") {
        FixedBlockData data = {0x0, 0x32, 0x32, 0x32, 0x32};
        const intx::uint256 expected_price = 0x32;

        blocks.reserve(20);
        fill_blocks_vector(blocks, kBeneficiary, data);

        auto result = boost::asio::co_spawn(pool, gas_price_oracle.suggested_price(1), boost::asio::use_future);
        const intx::uint256& price = result.get();

        CHECK(price == expected_price);
    }

    SECTION("when there are 20 blocks with 0x7 base fee and different max_priority and max_fee in tnxs") {
        FixedBlockData data = {0x7, 0x0, 0x32, 0x32, 0x32};
        const intx::uint256 expected_price = 0x2b;

        blocks.reserve(20);
        fill_blocks_vector(blocks, kBeneficiary, data);

        auto result = boost::asio::co_spawn(pool, gas_price_oracle.suggested_price(1), boost::asio::use_future);
        const intx::uint256& price = result.get();

        CHECK(price == expected_price);
    }

    SECTION("when there are 30 blocks with 0x0 base fee and same max_priority and max_fee in tnxs") {
        FixedBlockData data = {0x0, 0x32, 0x32, 0x32, 0x32};
        const intx::uint256 expected_price = 0x32;

        blocks.reserve(30);
        fill_blocks_vector(blocks, kBeneficiary, data);

        auto result = boost::asio::co_spawn(pool, gas_price_oracle.suggested_price(1), boost::asio::use_future);
        const intx::uint256& price = result.get();

        CHECK(price == expected_price);
    }

    SECTION("when there are 30 blocks with 0x7 base fee and different max_priority and max_fee in tnxs") {
        FixedBlockData data = {0x7, 0x0, 0x32, 0x32, 0x32};
        const intx::uint256 expected_price = 0x2b;

        blocks.reserve(30);
        fill_blocks_vector(blocks, kBeneficiary, data);

        auto result = boost::asio::co_spawn(pool, gas_price_oracle.suggested_price(1), boost::asio::use_future);
        const intx::uint256& price = result.get();

        CHECK(price == expected_price);
    }

    SECTION("when there are 60 blocks with 0x0 base fee and same max_priority and max_fee in tnxs") {
        FixedBlockData data = {0x0, 0x32, 0x32, 0x32, 0x32};
        const intx::uint256 expected_price = 0x32;

        blocks.reserve(60);
        fill_blocks_vector(blocks, kBeneficiary, data);

        auto result = boost::asio::co_spawn(pool, gas_price_oracle.suggested_price(1), boost::asio::use_future);
        const intx::uint256& price = result.get();

        CHECK(price == expected_price);
    }

    SECTION("when there are 60 blocks with 0x7 base fee and different max_priority and max_fee in tnxs") {
        FixedBlockData data = {0x7, 0x0, 0x32, 0x32, 0x32};
        const intx::uint256 expected_price = 0x2b;

        blocks.reserve(60);
        fill_blocks_vector(blocks, kBeneficiary, data);

        auto result = boost::asio::co_spawn(pool, gas_price_oracle.suggested_price(1), boost::asio::use_future);
        const intx::uint256& price = result.get();

        CHECK(price == expected_price);
    }

    SECTION("when there are 60 blocks with 0x7 base fee and max_priority > max_fee") {
        FixedBlockData data = {0x7, 0x40, 0x32, 0x40, 0x32};
        const intx::uint256 expected_price = 0x2b;

        blocks.reserve(60);
        fill_blocks_vector(blocks, kBeneficiary, data);

        auto result = boost::asio::co_spawn(pool, gas_price_oracle.suggested_price(1), boost::asio::use_future);
        const intx::uint256& price = result.get();

        CHECK(price == expected_price);
    }

    SECTION("when there are 60 blocks with 0x7 base fee and max_priority < max_fee") {
        FixedBlockData data = {0x7, 0x32, 0x40, 0x32, 0x40};
        const intx::uint256 expected_price = 0x32;

        blocks.reserve(60);
        fill_blocks_vector(blocks, kBeneficiary, data);

        auto result = boost::asio::co_spawn(pool, gas_price_oracle.suggested_price(1), boost::asio::use_future);
        const intx::uint256& price = result.get();

        CHECK(price == expected_price);
    }

    SECTION("when there are 60 blocks with 0x7 base fee and different max_priority and max_fee in tnxs, beneficiary == tx1 from") {
        FixedBlockData data = {0x7, 0x0, 0x32, 0x32, 0x32};
        const intx::uint256 expected_price = 0x2b;

        blocks.reserve(60);
        fill_blocks_vector(blocks, kFromTnx1, data);

        auto result = boost::asio::co_spawn(pool, gas_price_oracle.suggested_price(1), boost::asio::use_future);
        const intx::uint256& price = result.get();

        CHECK(price == expected_price);
    }

    SECTION("when there are 60 blocks with 0x7 base_fee and different max_priority and max_fee in tnxs, beneficiary == tx2 from") {
        FixedBlockData data = {0x7, 0x0, 0x32, 0x32, 0x32};
        const intx::uint256 expected_price = 0x0;

        blocks.reserve(60);
        fill_blocks_vector(blocks, kFromTnx2, data);

        auto result = boost::asio::co_spawn(pool, gas_price_oracle.suggested_price(1), boost::asio::use_future);
        const intx::uint256& price = result.get();

        CHECK(price == expected_price);
    }

    SECTION("when there are 60 blocks with 0x0 base fee and 1 tnx with fee == kDefaultMinPrice") {
        FixedBlockData data = {0x0, 0x32, 0x32, kDefaultMinPrice, kDefaultMinPrice};
        const intx::uint256 expected_price = kDefaultMinPrice;

        blocks.reserve(60);
        fill_blocks_vector(blocks, kBeneficiary, data);

        auto result = boost::asio::co_spawn(pool, gas_price_oracle.suggested_price(1), boost::asio::use_future);
        const intx::uint256& price = result.get();

        CHECK(price == expected_price);
    }

    SECTION("when there are 60 blocks ith 0x0 base fee and 1 tnx with fee < kDefaultMinPrice") {
        FixedBlockData data = {0x0, 0x32, 0x32, kDefaultMinPrice - 1, kDefaultMinPrice - 1};
        const intx::uint256 expected_price = 0x32;

        blocks.reserve(60);
        fill_blocks_vector(blocks, kBeneficiary, data);

        auto result = boost::asio::co_spawn(pool, gas_price_oracle.suggested_price(1), boost::asio::use_future);
        const intx::uint256& price = result.get();

        CHECK(price == expected_price);
    }

    SECTION("when there are 60 blocks with 0x0 base fee with fee == kDefaultMaxPrice") {
        FixedBlockData data = {0x0, kDefaultMaxPrice, kDefaultMaxPrice, kDefaultMaxPrice, kDefaultMaxPrice};
        const intx::uint256 expected_price = kDefaultMaxPrice;

        blocks.reserve(60);
        fill_blocks_vector(blocks, kBeneficiary, data);

        auto result = boost::asio::co_spawn(pool, gas_price_oracle.suggested_price(1), boost::asio::use_future);
        const intx::uint256& price = result.get();

        CHECK(price == expected_price);
    }

    SECTION("when there are 60 blocks with with 0x07 base fee with fee == kDefaultMaxPrice") {
        FixedBlockData data = {0x07, kDefaultMaxPrice + 0x07, kDefaultMaxPrice + 0x07, kDefaultMaxPrice + 0x07, kDefaultMaxPrice + 0x07};
        const intx::uint256 expected_price = kDefaultMaxPrice;

        blocks.reserve(60);
        fill_blocks_vector(blocks, kBeneficiary, data);

        auto result = boost::asio::co_spawn(pool, gas_price_oracle.suggested_price(1), boost::asio::use_future);
        const intx::uint256& price = result.get();

        CHECK(price == expected_price);
    }

    SECTION("when there are 60 blocks with 0x0 base fee with fee > kDefaultMaxPrice") {
        FixedBlockData data = {0x0, kDefaultMaxPrice + 0x10, kDefaultMaxPrice + 0x10, kDefaultMaxPrice + 0x10, kDefaultMaxPrice + 0x10};
        const intx::uint256 expected_price = kDefaultMaxPrice;

        blocks.reserve(60);
        fill_blocks_vector(blocks, kBeneficiary, data);

        auto result = boost::asio::co_spawn(pool, gas_price_oracle.suggested_price(1), boost::asio::use_future);
        const intx::uint256& price = result.get();

        CHECK(price == expected_price);
    }

    SECTION("when there are 60 blocks with 0x07 base fee with fee > kDefaultMaxPrice") {
        FixedBlockData data = {0x07, kDefaultMaxPrice + 0x10, kDefaultMaxPrice + 0x10, kDefaultMaxPrice + 0x10, kDefaultMaxPrice + 0x10};
        const intx::uint256 expected_price = kDefaultMaxPrice;

        blocks.reserve(60);
        fill_blocks_vector(blocks, kBeneficiary, data);

        auto result = boost::asio::co_spawn(pool, gas_price_oracle.suggested_price(1), boost::asio::use_future);
        const intx::uint256& price = result.get();

        CHECK(price == expected_price);
    }

    SECTION("when there are 60 blocks with 0x0 base fee and 1 tnx with fee > kDefaultMaxPrice") {
        FixedBlockData data = {0x0, kDefaultMaxPrice + kDefaultMaxPrice + 0x10, 0x32, 0x32, 0x32};
        const intx::uint256 expected_price = 0x32;

        blocks.reserve(60);
        fill_blocks_vector(blocks, kBeneficiary, data);

        auto result = boost::asio::co_spawn(pool, gas_price_oracle.suggested_price(1), boost::asio::use_future);
        const intx::uint256& price = result.get();

        CHECK(price == expected_price);
    }

    SECTION("when there are 60 blocks with 0x7 base fee and 1 tnx with fee > kDefaultMaxPrice") {
        FixedBlockData data = {0x7, kDefaultMaxPrice + 0x10, kDefaultMaxPrice + 0x10, 0x32, 0x32};
        const intx::uint256 expected_price = 0x2b;

        blocks.reserve(60);
        fill_blocks_vector(blocks, kBeneficiary, data);

        auto result = boost::asio::co_spawn(pool, gas_price_oracle.suggested_price(1), boost::asio::use_future);
        const intx::uint256& price = result.get();

        CHECK(price == expected_price);
    }

    SECTION("when there are 60 blocks with 0x0 base fee and tnxs with increasing max_priority_fee_per_gas and max_fee_per_gas") {
        VariableBlockData data = {0x0, 0x10, 0x9, 0x10, 0x9};
        const intx::uint256 expected_price = 0x019;

        blocks.reserve(60);
        fill_blocks_vector(blocks, kBeneficiary, data);

        auto result = boost::asio::co_spawn(pool, gas_price_oracle.suggested_price(1), boost::asio::use_future);
        const intx::uint256& price = result.get();

        CHECK(price == expected_price);
    }

    SECTION("when there are 60 blocks with 0x7 base fee and tnxs with increasing max_priority_fee_per_gas and max_fee_per_gas") {
        VariableBlockData data = {0x7, 0x10, 0x9, 0x10, 0x9};
        const intx::uint256 expected_price = 0x012;

        blocks.reserve(60);
        fill_blocks_vector(blocks, kBeneficiary, data);

        auto result = boost::asio::co_spawn(pool, gas_price_oracle.suggested_price(1), boost::asio::use_future);
        const intx::uint256& price = result.get();

        CHECK(price == expected_price);
    }

    SECTION("when there are 60 blocks with 0x0 base fee and tnxs with decreasing max_priority_fee_per_gas and max_fee_per_gas") {
        VariableBlockData data = {0x0, 0x300, -0x9, 0x300, -0x9};
        const intx::uint256 expected_price = 0x2f7;

        blocks.reserve(60);
        fill_blocks_vector(blocks, kBeneficiary, data);

        auto result = boost::asio::co_spawn(pool, gas_price_oracle.suggested_price(1), boost::asio::use_future);
        const intx::uint256& price = result.get();

        CHECK(price == expected_price);
    }

    SECTION("when there are 60 blocks with 0x7 base fee and tnxs with decreasing max_priority_fee_per_gas and max_fee_per_gas") {
        VariableBlockData data = {0x7, 0x200, -0x9, 0x200, -0x9};
        const intx::uint256 expected_price = 0x1f0;

        blocks.reserve(60);
        fill_blocks_vector(blocks, kBeneficiary, data);

        auto result = boost::asio::co_spawn(pool, gas_price_oracle.suggested_price(1), boost::asio::use_future);
        const intx::uint256& price = result.get();

        CHECK(price == expected_price);
    }

    SECTION("when there are 60 blocks with 0x0 base fee and tnxs with  max_priority_fee_per_gas and max_fee_per_gas increasing over threshold") {
        VariableBlockData data = {0x0, kDefaultMaxPrice - intx::uint256{0x200}, 0x9, kDefaultMaxPrice - intx::uint256{0x200}, 0x9};
        const intx::uint256 expected_price = 0x746a528609;

        blocks.reserve(60);
        fill_blocks_vector(blocks, kBeneficiary, data);

        auto result = boost::asio::co_spawn(pool, gas_price_oracle.suggested_price(1), boost::asio::use_future);
        const intx::uint256& price = result.get();

        CHECK(price == expected_price);
    }
}

}  // namespace silkworm::rpc
