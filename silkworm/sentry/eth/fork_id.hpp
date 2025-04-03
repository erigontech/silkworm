// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
        const std::vector<BlockNum>& fork_block_nums,
        const std::vector<BlockTime>& fork_block_times,
        BlockNum head_block_num);

    ForkId(uint32_t hash, BlockNum next);

    ForkId() : ForkId(0, 0) {}

    uint32_t hash() const;

    BlockNum next() const { return next_; }
    BlockNum& next() { return next_; }

    ByteView hash_bytes() const { return hash_bytes_; }
    Bytes& hash_bytes() { return hash_bytes_; }

    Bytes rlp_encode() const;
    static ForkId rlp_decode(ByteView data);

    /**
     * Encode ForkId for EnrRecord.eth1_fork_id_data.
     * It expects to be wrapped in an extra RLP list: RLP([RLP(this)]),
     * because in geth forkid.ID struct is contained within an enrEntry struct and each struct forms a list.
     */
    Bytes rlp_encode_enr_entry() const;
    static ForkId rlp_decode_enr_entry(ByteView data);

    bool is_compatible_with(
        ByteView genesis_hash,
        const std::vector<BlockNum>& fork_block_nums,
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
