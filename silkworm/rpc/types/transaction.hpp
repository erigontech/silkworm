// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <map>
#include <optional>
#include <string>
#include <vector>

#include <evmc/evmc.hpp>
#include <intx/intx.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/transaction.hpp>

namespace silkworm::rpc {

struct Transaction : public silkworm::Transaction {
    evmc::bytes32 block_hash;
    BlockNum block_num{0};
    std::optional<intx::uint256> block_base_fee_per_gas{std::nullopt};
    uint64_t transaction_index{0};
    bool queued_in_pool{false};

    intx::uint256 effective_gas_price() const;  // EIP-1559
};

struct Rlp {
    silkworm::Bytes buffer;
};

struct TransactionWithBlock {
    std::shared_ptr<BlockWithHash> block_with_hash{nullptr};
    Transaction transaction;
};

using AccessList = std::vector<silkworm::AccessListEntry>;

struct AccessListResult {
    AccessList access_list;
    std::optional<std::string> error;
    uint64_t gas_used{0};
};

struct TxPoolStatusInfo {
    unsigned int base_fee;
    unsigned int pending;
    unsigned int queued;
};

using TransactionContent = std::map<std::string, std::map<std::string, std::map<std::string, Transaction>>>;

std::ostream& operator<<(std::ostream& out, const Transaction& t);
std::ostream& operator<<(std::ostream& out, const silkworm::Transaction& t);

}  // namespace silkworm::rpc
