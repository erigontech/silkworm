/*
   Copyright 2020-2021 The Silkworm Authors

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

#ifndef SILKWORM_HEADER_ONLY_CHAIN_STATE_HPP_
#define SILKWORM_HEADER_ONLY_CHAIN_STATE_HPP_

#include <optional>

#include <silkworm/common/base.hpp>
#include <silkworm/types/block.hpp>

namespace silkworm {

class BlockState {
  public:
    virtual ~BlockState() = default;

    virtual std::optional<BlockHeader> read_header(BlockNum block_number,
                                                   const evmc::bytes32& block_hash) const noexcept = 0;

    virtual std::optional<BlockBody> read_body(BlockNum block_number,
                                               const evmc::bytes32& block_hash) const noexcept = 0;
};

}  // namespace silkworm

#endif  // SILKWORM_HEADER_ONLY_CHAIN_STATE_HPP_
