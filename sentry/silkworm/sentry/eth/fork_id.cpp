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

#include "fork_id.hpp"

#include <Crc32.h>

#include <optional>

#include <silkworm/common/endian.hpp>
#include <silkworm/rlp/decode.hpp>
#include <silkworm/rlp/encode_vector.hpp>

namespace silkworm::sentry::eth {

size_t length(const ForkId& value) {
    return rlp::length(value.hash_bytes(), value.next());
}

void encode(Bytes& to, const ForkId& value) {
    rlp::encode(to, value.hash_bytes(), value.next());
}

DecodingResult decode(ByteView& from, ForkId& value) noexcept {
    return rlp::decode(from, value.hash_bytes(), value.next());
}

ForkId::ForkId(uint32_t hash, BlockNum next)
    : hash_bytes_(sizeof(uint32_t), 0), next_(next) {
    endian::store_big_u32(hash_bytes_.data(), hash);
}

ForkId::ForkId(
    ByteView genesis_hash,
    const std::vector<BlockNum>& fork_block_numbers,
    BlockNum head_block_num) : ForkId() {
    uint32_t hash = crc32_fast(genesis_hash.data(), genesis_hash.size());
    endian::store_big_u32(hash_bytes_.data(), hash);

    for (auto fork_block_num : fork_block_numbers) {
        if (fork_block_num > head_block_num) {
            next_ = fork_block_num;
            break;
        }

        add_fork_block_number(fork_block_num);
    }
}

void ForkId::add_fork_block_number(BlockNum fork_block_num) {
    Bytes fork_bytes(sizeof(uint64_t), 0);
    endian::store_big_u64(fork_bytes.data(), fork_block_num);

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
    auto err = decode(data, value);
    if (err != DecodingResult::kOk)
        throw std::runtime_error("Failed to decode ForkId RLP");
    return value;
}

bool ForkId::is_compatible_with(
    ByteView genesis_hash,
    const std::vector<BlockNum>& fork_block_numbers,
    BlockNum head_block_num) const {
    // common_fork is a fork block number with a matching hash (or 0 if we are at genesis)
    std::optional<BlockNum> common_fork;
    // next_fork is the next known fork block number after the common_fork
    auto next_fork = fork_block_numbers.cbegin();

    // find common and next fork block numbers
    ForkId other{genesis_hash, {}, head_block_num};
    if (this->hash() == other.hash()) {
        common_fork = {0};
    } else {
        while (next_fork != fork_block_numbers.cend()) {
            auto fork = *next_fork++;
            other.add_fork_block_number(fork);
            if (this->hash() == other.hash()) {
                common_fork = {fork};
                break;
            }
        }
    }

    if (!common_fork)
        return false;

    bool is_next_fork_before_head = (next_fork != fork_block_numbers.cend()) &&
                                    (*next_fork <= head_block_num);

    return (head_block_num < common_fork.value()) ||
           (is_next_fork_before_head && (this->next() == *next_fork)) ||
           (!is_next_fork_before_head && ((this->next() == 0) || (this->next() > head_block_num)));
}

}  // namespace silkworm::sentry::eth
