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

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/rlp/decode.hpp>

namespace silkworm::sentry::eth {

class ForkId {
  public:
    ForkId(
        ByteView genesis_hash,
        const std::vector<BlockNum>& fork_block_numbers,
        const std::vector<BlockTime>& fork_block_times,
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

    /**
     * Encode ForkId for EnrRecord.eth1_fork_id_data.
     * It expects to be wrapped in an extra RLP list: RLP([RLP(this)]),
     * because in geth forkid.ID struct is contained within an enrEntry struct and each struct forms a list.
     */
    [[nodiscard]] Bytes rlp_encode_enr_entry() const;
    [[nodiscard]] static ForkId rlp_decode_enr_entry(ByteView data);

    [[nodiscard]] bool is_compatible_with(
        ByteView genesis_hash,
        const std::vector<BlockNum>& fork_block_numbers,
        const std::vector<BlockTime>& fork_block_times,
        BlockNum head_block_num) const;

    friend bool operator==(const ForkId&, const ForkId&) = default;

  private:
    void add_fork_point(uint64_t fork_point);

    Bytes hash_bytes_;
    BlockNum next_;
};

// RLP
size_t length(const ForkId& value);
void encode(Bytes& to, const ForkId& value);
DecodingResult decode(ByteView& from, ForkId& value, rlp::Leftover mode = rlp::Leftover::kProhibit) noexcept;

}  // namespace silkworm::sentry::eth
