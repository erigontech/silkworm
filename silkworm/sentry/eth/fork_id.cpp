// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "fork_id.hpp"

#include <Crc32.h>

#include <optional>
#include <vector>

#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/rlp/decode_vector.hpp>
#include <silkworm/core/rlp/encode_vector.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>

namespace silkworm::sentry::eth {

size_t length(const ForkId& value) {
    return rlp::length(value.hash_bytes(), value.next());
}

void encode(Bytes& to, const ForkId& value) {
    rlp::encode(to, value.hash_bytes(), value.next());
}

DecodingResult decode(ByteView& from, ForkId& value, rlp::Leftover mode) noexcept {
    return rlp::decode(from, mode, value.hash_bytes(), value.next());
}

ForkId::ForkId(uint32_t hash, BlockNum next)
    : hash_bytes_(sizeof(uint32_t), 0), next_(next) {
    endian::store_big_u32(hash_bytes_.data(), hash);
}

ForkId::ForkId(
    ByteView genesis_hash,
    const std::vector<BlockNum>& fork_block_nums,
    const std::vector<BlockTime>& fork_block_times,
    BlockNum head_block_num) : ForkId() {
    uint32_t hash = crc32_fast(genesis_hash.data(), genesis_hash.size());
    endian::store_big_u32(hash_bytes_.data(), hash);

    // Both fork_block_nums and fork_block_times are sorted in ascending order
    // First fork block time (Shanghai) is greater than last fork block number
    std::vector<uint64_t> fork_points{fork_block_nums};
    fork_points.insert(fork_points.end(), fork_block_times.cbegin(), fork_block_times.cend());
    for (uint64_t fork : fork_points) {
        if (fork > head_block_num) {
            next_ = fork;
            break;
        }

        add_fork_point(fork);
    }
}

void ForkId::add_fork_point(uint64_t fork_point) {
    Bytes fork_bytes(sizeof(uint64_t), 0);
    endian::store_big_u64(fork_bytes.data(), fork_point);

    uint32_t hash = crc32_fast(fork_bytes.data(), fork_bytes.size(), this->hash());
    endian::store_big_u32(hash_bytes_.data(), hash);
}

uint32_t ForkId::hash() const {
    return endian::load_big_u32(hash_bytes_.data());
}

Bytes ForkId::rlp_encode() const {
    Bytes data;
    encode(data, *this);
    return data;
}

ForkId ForkId::rlp_decode(ByteView data) {
    ForkId value;
    success_or_throw(decode(data, value), "Failed to decode ForkId RLP");
    return value;
}

Bytes ForkId::rlp_encode_enr_entry() const {
    Bytes data;
    rlp::encode(data, std::vector<rlp::RlpBytes>{rlp::RlpBytes{rlp_encode()}});
    return data;
}

ForkId ForkId::rlp_decode_enr_entry(ByteView data) {
    std::vector<rlp::RlpByteView> list;
    success_or_throw(rlp::decode(data, list), "Failed to decode ForkId ENR entry RLP: no wrapping list");

    if (list.empty())
        throw DecodingException(DecodingError::kUnexpectedListElements, "Failed to decode ForkId ENR entry RLP: wrapping list is empty");

    return rlp_decode(list[0].data);
}

bool ForkId::is_compatible_with(
    ByteView genesis_hash,
    const std::vector<BlockNum>& fork_block_nums,
    const std::vector<BlockTime>& fork_block_times,
    BlockNum head_block_num) const {
    // Both fork_block_nums and fork_block_times are sorted in ascending order
    // First fork block time (Shanghai) is greater than last fork block number
    std::vector<uint64_t> fork_points{fork_block_nums};
    fork_points.insert(fork_points.end(), fork_block_times.cbegin(), fork_block_times.cend());

    // common_fork is a fork block point with a matching hash (or 0 if we are at genesis)
    std::optional<uint64_t> common_fork;
    // next_fork is the next known fork block number after the common_fork
    auto next_fork = fork_points.cbegin();

    // find common and next fork block numbers
    ForkId other{genesis_hash, {}, {}, head_block_num};
    if (this->hash() == other.hash()) {
        common_fork = {0};
    } else {
        while (next_fork != fork_points.cend()) {
            auto fork = *next_fork++;
            other.add_fork_point(fork);
            if (this->hash() == other.hash()) {
                common_fork = {fork};
                break;
            }
        }
    }

    if (!common_fork)
        return false;

    bool is_next_fork_before_head = (next_fork != fork_points.cend()) &&
                                    (*next_fork <= head_block_num);

    return (head_block_num < common_fork.value()) ||
           (is_next_fork_before_head && (this->next() == *next_fork)) ||
           (!is_next_fork_before_head && ((this->next() == 0) || (this->next() > head_block_num)));
}

}  // namespace silkworm::sentry::eth
