// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "call.hpp"

#include <string>

#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/rpc/common/util.hpp>

namespace silkworm::rpc {

static std::string optional_uint256_to_string(const std::optional<intx::uint256>& u) {
    return silkworm::to_hex(silkworm::endian::to_big_compact(u.value_or(intx::uint256{})));
}

static std::string optional_bytes_to_string(const std::optional<silkworm::Bytes>& u) {
    return silkworm::to_hex(u.value_or(silkworm::Bytes{}));
}

std::ostream& operator<<(std::ostream& out, const Call& call) {
    out << "from: " << call.from.value_or(evmc::address{}) << " "
        << "to: " << call.to.value_or(evmc::address{}) << " "
        << "gas: " << call.gas.value_or(0) << " "
        << "gas_price: " << optional_uint256_to_string(call.gas_price) << " "
        << "max_priority_fee_per_gas: " << optional_uint256_to_string(call.max_priority_fee_per_gas) << " "
        << "max_fee_per_gas: " << optional_uint256_to_string(call.max_fee_per_gas) << " "
        << "value: " << optional_uint256_to_string(call.value) << " "
        << "data: " << optional_bytes_to_string(call.data);
    return out;
}

std::ostream& operator<<(std::ostream& out, const Bundles& bundles) {
    out << "[";
    bool first = true;
    for (const auto& bundle : bundles) {
        if (!first) {
            out << ", ";
        }
        out << "{" << bundle << "}";
        first = false;
    }
    out << "]";
    return out;
}

std::ostream& operator<<(std::ostream& out, const Bundle& bundle) {
    out << "transactions: [";
    for (const auto& transaction : bundle.transactions) {
        out << transaction;
    }
    out << "] ";
    out << "block_override: " << bundle.block_override;

    return out;
}

std::ostream& operator<<(std::ostream& out, const BlockOverrides& bo) {
    out << "block_num: " << bo.block_num.value_or(0) << " ";

    return out;
}

std::ostream& operator<<(std::ostream& out, const SimulationContext& sc) {
    out << "block_num: " << sc.block_num << " "
        << "transaction_index: " << sc.transaction_index;
    return out;
}

std::ostream& operator<<(std::ostream& out, const AccountsOverrides& ao) {
    out << "{";
    bool first = true;
    for (const auto& item : ao) {
        if (!first) {
            out << ", ";
        }
        out << item.first << ": {" << item.second << "}";
        first = false;
    }
    out << "} ";

    return out;
}

std::ostream& operator<<(std::ostream& out, const AccountOverrides& ao) {
    out << "balance: " << optional_uint256_to_string(ao.balance) << " "
        << "nonce: " << ao.nonce.value_or(0) << " "
        << "code: " << optional_bytes_to_string(ao.code) << " "
        << "state: #" << ao.state.size() << " "
        << "state_diff: #" << ao.state_diff.size() << " ";

    return out;
}

}  // namespace silkworm::rpc
