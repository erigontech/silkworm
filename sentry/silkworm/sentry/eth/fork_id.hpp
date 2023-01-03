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

#include <vector>

#include <silkworm/common/base.hpp>
#include <silkworm/common/decoding_result.hpp>

namespace silkworm::sentry::eth {

class ForkId {
  public:
    ForkId(
        ByteView genesis_hash,
        const std::vector<BlockNum>& fork_block_numbers,
        BlockNum head_block_num);

    ForkId(uint32_t hash, BlockNum next);

    ForkId() : ForkId(0, 0) {}

    [[nodiscard]] uint32_t hash() const;

    [[nodiscard]] BlockNum next() const { return next_; }
    [[nodiscard]] BlockNum& next() { return next_; }

    [[nodiscard]] ByteView hash_bytes() const { return hash_bytes_; }
    [[nodiscard]] Bytes& hash_bytes() { return hash_bytes_; }

    [[nodiscard]] Bytes rlp_encode() const;
    [[nodiscard]] static ForkId rlp_decode(ByteView data);

    bool is_compatible_with(
        ByteView genesis_hash,
        const std::vector<BlockNum>& fork_block_numbers,
        BlockNum head_block_num) const;

    friend bool operator==(const ForkId&, const ForkId&) = default;

  private:
    void add_fork_block_number(BlockNum fork_block_num);

    Bytes hash_bytes_;
    BlockNum next_;
};

// RLP
size_t length(const ForkId& value);
void encode(Bytes& to, const ForkId& value);
DecodingResult decode(ByteView& from, ForkId& value) noexcept;

}  // namespace silkworm::sentry::eth
