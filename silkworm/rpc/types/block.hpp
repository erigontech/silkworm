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

#include <iostream>
#include <memory>
#include <string>
#include <variant>

#include <intx/intx.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/receipt.hpp>

#include "receipt.hpp"

namespace silkworm::rpc {

struct Block {
    std::shared_ptr<BlockWithHash> block_with_hash{nullptr};
    bool full_tx{false};

    uint64_t get_block_size() const;
};

std::ostream& operator<<(std::ostream& out, const Block& b);

class BlockNumOrHash {
  public:
    explicit BlockNumOrHash(const std::string& block_num_or_hash) { build(block_num_or_hash); }
    explicit BlockNumOrHash(BlockNum block_num) noexcept : value_{block_num} {}

    virtual ~BlockNumOrHash() noexcept = default;

    BlockNumOrHash(const BlockNumOrHash&) noexcept = default;
    BlockNumOrHash& operator=(const BlockNumOrHash&) = default;

    BlockNumOrHash(BlockNumOrHash&&) = default;
    BlockNumOrHash& operator=(BlockNumOrHash&&) noexcept = default;

    bool is_number() const {
        return std::holds_alternative<uint64_t>(value_);
    }

    uint64_t number() const {
        return is_number() ? *std::get_if<uint64_t>(&value_) : 0;
    }

    bool is_hash() const {
        return std::holds_alternative<evmc::bytes32>(value_);
    }

    evmc::bytes32 hash() const {
        return is_hash() ? *std::get_if<evmc::bytes32>(&value_) : evmc::bytes32{0};
    }

    bool is_tag() const {
        return std::holds_alternative<std::string>(value_);
    }

    std::string tag() const {
        return is_tag() ? *std::get_if<std::string>(&value_) : "";
    }

  private:
    void build(std::string const& block_num_or_hash);

    std::variant<uint64_t, evmc::bytes32, std::string> value_;
};

std::ostream& operator<<(std::ostream& out, const BlockNumOrHash& b);

struct BlockDetails {
    uint64_t block_size;
    evmc::bytes32 hash;
    silkworm::BlockHeader header;
    uint64_t transaction_count{0};
    std::vector<silkworm::BlockHeader> ommers;
    std::optional<std::vector<Withdrawal>> withdrawals{std::nullopt};
};

struct IssuanceDetails {
    intx::uint256 miner_reward{0};
    intx::uint256 ommers_reward{0};
    intx::uint256 total_reward{0};
};

struct BlockDetailsResponse {
    BlockDetails block;
    IssuanceDetails issuance{};
    intx::uint256 total_fees{0};
};

struct BlockTransactionsResponse {
    uint64_t block_size{0};
    evmc::bytes32 hash;
    silkworm::BlockHeader header;
    uint64_t transaction_count{0};
    std::vector<silkworm::BlockHeader> ommers;
    std::vector<silkworm::rpc::Receipt> receipts;
    std::vector<silkworm::Transaction> transactions;
    std::optional<std::vector<Withdrawal>> withdrawals{std::nullopt};
};

struct TransactionsWithReceipts {
    bool first_page{false};
    bool last_page{false};
    std::vector<silkworm::rpc::Receipt> receipts;
    std::vector<silkworm::Transaction> transactions;
    std::vector<BlockDetails> blocks;
    std::vector<BlockHeader> headers;
};

}  // namespace silkworm::rpc
