// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <iostream>
#include <optional>
#include <vector>

#include <evmc/evmc.hpp>
#include <intx/intx.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/transaction.hpp>
#include <silkworm/rpc/types/block.hpp>
#include <silkworm/rpc/types/transaction.hpp>

namespace silkworm::rpc {

// Gas limit cap for eth_call (increased wrt RPCDaemon)
inline constexpr uint64_t kDefaultGasLimit{50'000'000};

struct Call {
    std::optional<evmc::address> from;
    std::optional<evmc::address> to;
    std::optional<uint64_t> gas;
    std::optional<intx::uint256> gas_price;
    std::optional<intx::uint256> max_priority_fee_per_gas;
    std::optional<intx::uint256> max_fee_per_gas;
    std::optional<intx::uint256> value;
    std::optional<silkworm::Bytes> data;
    std::optional<uint64_t> nonce;
    AccessList access_list;

    silkworm::Transaction to_transaction(
        const std::optional<AccessList>& override_access_list = std::nullopt,
        const std::optional<uint64_t> override_nonce = std::nullopt) const {
        silkworm::Transaction txn{};
        txn.set_sender(from ? *from : evmc::address{});
        txn.to = to;
        if (override_nonce) {
            txn.nonce = *override_nonce;
        } else if (nonce) {
            txn.nonce = *nonce;
        }

        if (override_access_list) {
            txn.access_list = *override_access_list;
        } else if (!access_list.empty()) {
            txn.access_list = access_list;
        }
        txn.gas_limit = gas.value_or(kDefaultGasLimit);
        if (gas > kDefaultGasLimit) {
            txn.gas_limit = kDefaultGasLimit;
        }

        if (gas_price) {
            // We need to update JSON RPC validation spec to uncomment the following assertion
            // SILKWORM_ASSERT(!max_priority_fee_per_gas && !max_fee_per_gas);
            txn.type = TransactionType::kLegacy;
            txn.max_priority_fee_per_gas = gas_price.value();
            txn.max_fee_per_gas = gas_price.value();
        } else {
            // We need to update JSON RPC validation spec to uncomment the following assertion
            // SILKWORM_ASSERT(!gas_price);
            txn.type = TransactionType::kDynamicFee;
            txn.max_priority_fee_per_gas = max_priority_fee_per_gas.value_or(intx::uint256{0});
            txn.max_fee_per_gas = max_fee_per_gas.value_or(intx::uint256{0});
        }

        txn.value = value.value_or(intx::uint256{0});
        txn.data = data.value_or(silkworm::Bytes{});
        return txn;
    }
};

std::ostream& operator<<(std::ostream& out, const Call& call);

struct BlockOverrides {
    std::optional<BlockNum> block_num;
    std::optional<evmc::address> coin_base;
    std::optional<std::uint64_t> timestamp;
    std::optional<intx::uint256> difficulty;
    std::optional<std::uint64_t> gas_limit;
    std::optional<std::uint64_t> base_fee;
    std::map<std::uint64_t, evmc::bytes32> block_hash;
};

struct SimulationContext {
    BlockNumOrHash block_num{0};
    std::int32_t transaction_index{-1};
};

struct AccountOverrides {
    std::optional<std::uint64_t> nonce;
    std::optional<intx::uint256> balance;
    std::optional<silkworm::Bytes> code;
    std::optional<evmc::bytes32> code_hash;
    std::map<evmc::bytes32, intx::uint256> state;
    std::map<evmc::bytes32, intx::uint256> state_diff;
};

struct Bundle {
    std::vector<Call> transactions;
    BlockOverrides block_override;
};

using Bundles = std::vector<Bundle>;
using AccountsOverrides = std::map<evmc::address, AccountOverrides>;

std::ostream& operator<<(std::ostream& out, const Bundles& bundles);
std::ostream& operator<<(std::ostream& out, const Bundle& bundle);
std::ostream& operator<<(std::ostream& out, const BlockOverrides& bo);
std::ostream& operator<<(std::ostream& out, const SimulationContext& sc);
std::ostream& operator<<(std::ostream& out, const AccountsOverrides& ao);
std::ostream& operator<<(std::ostream& out, const AccountOverrides& ao);

}  // namespace silkworm::rpc
