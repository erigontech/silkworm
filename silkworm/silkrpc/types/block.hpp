/*
   Copyright 2020 The Silkrpc Authors

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

namespace silkrpc {

struct Block : public silkworm::BlockWithHash {
    intx::uint256 total_difficulty{0};
    bool full_tx{false};

    [[nodiscard]] uint64_t get_block_size() const;
};

std::ostream& operator<<(std::ostream& out, const Block& b);

class BlockNumberOrHash {
public:
    explicit BlockNumberOrHash(std::string const& bnoh) { build(bnoh); }
    explicit BlockNumberOrHash(uint64_t number) noexcept : value_{number} {}

    virtual ~BlockNumberOrHash() noexcept = default;

    BlockNumberOrHash(BlockNumberOrHash &&bnoh) = default;
    BlockNumberOrHash(BlockNumberOrHash const& bnoh) noexcept = default;

    BlockNumberOrHash& operator=(BlockNumberOrHash const& bnoh) {
        value_ = bnoh.value_;
        return *this;
    }

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

} // namespace silkrpc

