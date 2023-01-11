/*  hashtree.cpp
 *
 *  This file is part of Mammon.
 *  mammon is a greedy and selfish ETH consensus client.
 *
 *  Copyright (c) 2021 - Reimundo Heluani (potuz) potuz@potuz.net
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "../ssz/hashtree.hpp"

#include <stdexcept>

#include "../common/bytes.hpp"
#include "../helpers/math.hpp"
// #include "../ssz/hasher.hpp"
// #include "../ssz/ssz.hpp"

namespace {
using namespace ssz;
Chunk hash_2_chunks(const Chunk& first, const Chunk& second, const Hasher& hasher) {
    std::array<std::uint8_t, 2 * constants::BYTES_PER_CHUNK> sum;  // NOLINT
    std::copy(first.begin(), first.end(), sum.begin());
    std::copy(second.begin(), second.end(), sum.begin() + constants::BYTES_PER_CHUNK);
    Chunk ret;
    hasher.hash_64b_blocks(ret.data(), sum.data(), 1);
    return ret;
}
// clang-format off
const auto ZERO_HASH_DEPTH{42};
constexpr Chunk zero_hash{};

template <std::size_t N> requires(N > 0)
auto zero_hash_array_helper() {
    std::array<Chunk, N> ret; // NOLINT
    ret[0] = zero_hash;
    ssz::Hasher hasher{};
    for (auto it = ret.begin() + 1; it != ret.end(); ++it) *it = hash_2_chunks(*std::prev(it), *std::prev(it), hasher);
    return ret;
}
// clang-format on

const auto zero_hash_array = zero_hash_array_helper<ZERO_HASH_DEPTH>();

/**
 *   \brief Packs a vector of bytes into chunks of 32 bytes
 *   \details If the length of vec is not a multiple of 32, it pads with null bytes in the end
 *   \param[in] vec  a vector of std::uint8_ts.
 */
std::vector<Chunk> pack_and_pad(const std::vector<std::uint8_t>& vec) {
    std::vector<Chunk> ret{};
    if (vec.empty())
        ret.push_back(zero_hash);
    else {
        ret.reserve((vec.size() + sizeof(Chunk) - 1) / sizeof(Chunk));
        for (auto it = vec.cbegin(); it < vec.end(); it += constants::BYTES_PER_CHUNK) {
            Chunk chunk{};
            std::copy(it, std::min(it + constants::BYTES_PER_CHUNK, vec.end()), chunk.begin());
            ret.push_back(chunk);
        }
    }
    return ret;
}

void merkleize(const std::vector<Chunk>& vec, std::vector<Chunk>& hash_tree, std::size_t limit, const Hasher& hasher) {
    auto depth = std::ceil(std::log2(limit));
    auto first = hash_tree.begin();
    auto last = first + (vec.size() + 1) / 2;  // NOLINT
    if (vec.size() > 1) hasher.hash_64b_blocks(hash_tree[0].begin(), vec[0].begin(), vec.size() / 2);
    if (vec.size() % 2) *std::prev(last) = hash_2_chunks(vec.back(), zero_hash, hasher);
    auto dist = std::distance(first, last);
    auto height = 1;
    while (dist > 1) {
        hasher.hash_64b_blocks((*last).begin(), (*first).begin(), std::size_t(dist / 2));
        first = last;
        last += (dist + 1) / 2;
        // NOLINTNEXTLINE 
        if (dist % 2) *std::prev(last) = hash_2_chunks(*std::prev(first), zero_hash_array[std::size_t(height)], hasher);
        height++;
        dist = std::distance(first, last);
    }
    while (height < depth) {
        *last = hash_2_chunks(*std::prev(last), zero_hash_array[std::size_t(height)], hasher);  // NOLINT
        last++;
        height++;
    }
    hash_tree.resize(std::size_t(std::distance(hash_tree.begin(), last)));
}

}  // namespace

namespace ssz {
#ifndef CUSTOM_HASHER
const auto HashTree::hasher = Hasher{};
#endif
HashTree::HashTree(const std::vector<Chunk>& chunks, std::uint64_t limit) {
    // return early if only one chunk:
    if (limit <= 1 && chunks.size() == 1)
        hash_tree_ = chunks;
    else {
        if (chunks.empty()) throw std::out_of_range("empty chunks is not allowed");
        auto effective_depth = std::ceil(std::log2(chunks.size()));
        auto depth = (limit == 0) ? effective_depth : std::ceil(std::log2(limit));
        auto cache_size = depth - effective_depth + double(std::bit_ceil(chunks.size())) - 1;
        // if limit > chunk_count assume it's a list and reserve for the mix_in
        if (depth > effective_depth) cache_size++;
        hash_tree_.resize(std::max(std::size_t(cache_size), 1ul));

        if (limit == 0) limit = std::bit_ceil(chunks.size());
        merkleize(chunks, hash_tree_, limit, hasher);
    }
}

void HashTree::mix_in(std::size_t length) {
    auto length_bytes = eth::Bytes32(length);
    hash_tree_.push_back(hash_2_chunks(this->hash_tree_root(), length_bytes.to_array(), hasher));
}

HashTree::HashTree(const std::vector<std::uint8_t>& vec, std::uint64_t limit) : HashTree{pack_and_pad(vec), limit} {}

}  // namespace ssz
