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

struct Block : public silkworm::BlockWithHash {
    intx::uint256 total_difficulty{0};
    bool full_tx{false};

    [[nodiscard]] uint64_t get_block_size() const;
};

std::ostream& operator<<(std::ostream& out, const Block& b);

class BlockNumberOrHash {
  public:
    explicit BlockNumberOrHash(std::string const& bnoh) { build(bnoh); }
    explicit BlockNumberOrHash(BlockNum number) noexcept : value_{number} {}

    virtual ~BlockNumberOrHash() noexcept = default;

    BlockNumberOrHash(BlockNumberOrHash&& bnoh) = default;
    BlockNumberOrHash(BlockNumberOrHash const& bnoh) noexcept = default;

    BlockNumberOrHash& operator=(BlockNumberOrHash const& bnoh) = default;

    [[nodiscard]] bool is_number() const {
        return std::holds_alternative<uint64_t>(value_);
    }

    [[nodiscard]] uint64_t number() const {
        return is_number() ? *std::get_if<uint64_t>(&value_) : 0;
    }

    [[nodiscard]] bool is_hash() const {
        return std::holds_alternative<evmc::bytes32>(value_);
    }

    [[nodiscard]] evmc::bytes32 hash() const {
        return is_hash() ? *std::get_if<evmc::bytes32>(&value_) : evmc::bytes32{0};
    }

    [[nodiscard]] bool is_tag() const {
        return std::holds_alternative<std::string>(value_);
    }

    [[nodiscard]] std::string tag() const {
        return is_tag() ? *std::get_if<std::string>(&value_) : "";
    }

  private:
    void build(std::string const& bnoh);

    std::variant<uint64_t, evmc::bytes32, std::string> value_;
};

std::ostream& operator<<(std::ostream& out, const BlockNumberOrHash& b);

struct BlockDetails {
    uint64_t block_size;
    evmc::bytes32 hash;
    silkworm::BlockHeader header;
    intx::uint256 total_difficulty{0};
    uint64_t transaction_count{0};
    std::vector<silkworm::BlockHeader> ommers;
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
    uint64_t block_size;
    evmc::bytes32 hash;
    silkworm::BlockHeader header;
    intx::uint256 total_difficulty{0};
    uint64_t transaction_count{0};
    std::vector<silkworm::BlockHeader> ommers;
    std::vector<silkworm::rpc::Receipt> receipts;
    std::vector<silkworm::Transaction> transactions;
};

struct TransactionsWithReceipts {
    bool first_page;
    bool last_page;
    std::vector<silkworm::rpc::Receipt> receipts;
    std::vector<silkworm::Transaction> transactions;
    std::vector<BlockDetails> blocks;
};

}  // namespace silkworm::rpc
