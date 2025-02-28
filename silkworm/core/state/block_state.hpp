/*
   Copyright 2022 The Silkworm Authors

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

#include <optional>

#include <intx/intx.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/types/block.hpp>

namespace silkworm {

class BlockState {
  public:
    virtual ~BlockState() = default;

    virtual std::optional<BlockHeader> read_header(
        BlockNum block_num,
        const evmc::bytes32& block_hash) const noexcept = 0;

    // Returns true on success and false on missing block
    [[nodiscard]] virtual bool read_body(
        BlockNum block_num,
        const evmc::bytes32& block_hash,
        BlockBody& out) const noexcept = 0;

    virtual std::optional<intx::uint256> total_difficulty(
        uint64_t block_num,
        const evmc::bytes32& block_hash) const noexcept = 0;
};

}  // namespace silkworm
