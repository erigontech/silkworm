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

#include "hash_tree.hpp"

#include <array>
#include <bit>
#include <cmath>
#include <stdexcept>

#include <silkworm/common/base.hpp>
#include <silkworm/lightclient/ssz/hasher.hpp>

namespace silkworm::ssz {

Hash32 hash_2_chunks(const Hash32& first, const Hash32& second, const Hasher& hasher) {
    std::array<std::uint8_t, 2 * kHashLength> sum; // NOLINT
    std::copy(std::begin(first.bytes), std::end(first.bytes), sum.begin());
    std::copy(std::begin(second.bytes), std::end(second.bytes), sum.begin() + kHashLength);
    Hash32 parent;
    hasher.hash_64b_blocks(parent.bytes, sum.data(), 1);
    return parent;
}

constexpr int kZeroHashDepth{42};
constexpr Hash32 kZeroHash{};

template <std::size_t N> requires(N > 0)
auto zero_hash_array_helper() {
   std::array<Hash32, N> hashes; // NOLINT
   hashes[0] = kZeroHash;
   ssz::Hasher hasher{};
   for (auto it = hashes.begin() + 1; it != hashes.end(); ++it) {
       *it = hash_2_chunks(*std::prev(it), *std::prev(it), hasher);
   }
   return hashes;
}

const auto zero_hash_array = zero_hash_array_helper<kZeroHashDepth>();

//! Packs a vector of bytes into chunks of 32 bytes
//! \details If the length of vec is not a multiple of 32, it pads with null bytes in the end
//! \param[in] v a vector of std::uint8_ts
std::vector<Hash32> pack_and_pad(const Bytes& v) {
    std::vector<Hash32> hash_chunks{};
    if (v.empty()) {
       hash_chunks.push_back(kZeroHash);
    } else {
       hash_chunks.reserve((v.size() + sizeof(Hash32) - 1) / sizeof(Hash32));
        for (auto it = v.cbegin(); it < v.end(); it += kHashLength) {
            Hash32 chunk{};
            std::copy(it, std::min(it + kHashLength, v.end()), std::begin(chunk.bytes));
            hash_chunks.push_back(chunk);
        }
    }
    return hash_chunks;
}

void merkleize(const std::vector<Hash32>& v, std::vector<Hash32>& hash_tree, std::size_t limit, const Hasher& hasher) {
    const auto depth = std::ceil(std::log2(limit));
    auto first = hash_tree.begin();
    auto last = first + (v.size() + 1) / 2;  // NOLINT
    if (v.size() > 1) {
        hasher.hash_64b_blocks(std::begin(hash_tree[0].bytes), std::begin(v[0].bytes), v.size() / 2);
    }
    if (v.size() % 2) {
        *std::prev(last) = hash_2_chunks(v.back(), kZeroHash, hasher);
    }
    auto dist = std::distance(first, last);
    int height = 1;
    while (dist > 1) {
        hasher.hash_64b_blocks(std::begin((*last).bytes), std::begin((*first).bytes), std::size_t(dist / 2));
        first = last;
        last += (dist + 1) / 2;
        // NOLINTNEXTLINE
        if (dist % 2) {
            *std::prev(last) = hash_2_chunks(*std::prev(first), zero_hash_array[std::size_t(height)], hasher);
        }
        height++;
        dist = std::distance(first, last);
    }
    while (height < depth) {
        *last = hash_2_chunks(*std::prev(last), zero_hash_array[std::size_t(height)], hasher);  // NOLINT
        last++;
        height++;
    }
    hash_tree.resize(static_cast<std::size_t>(std::distance(hash_tree.begin(), last)));
}

#ifndef CUSTOM_HASHER
const auto HashTree::hasher_ = Hasher{};
#endif

HashTree::HashTree(const Bytes& chunk_stream, std::uint64_t limit)
    : HashTree{pack_and_pad(chunk_stream), limit} {}

HashTree::HashTree(const Hash32Sequence& chunks, std::uint64_t limit) {
    // return early if only one chunk
    if (limit <= 1 && chunks.size() == 1) {
        hash_tree_ = chunks;
    } else {
        if (chunks.empty()) throw std::out_of_range("empty chunks is not allowed");
        auto effective_depth = std::ceil(std::log2(chunks.size()));
        auto depth = (limit == 0) ? effective_depth : std::ceil(std::log2(limit));
        auto cache_size = depth - effective_depth + double(std::bit_ceil(chunks.size())) - 1;
        // if limit > chunk_count assume it's a list and reserve for the mix_in
        if (depth > effective_depth) cache_size++;
        hash_tree_.resize(std::max(std::size_t(cache_size), 1ul));

        if (limit == 0) limit = std::bit_ceil(chunks.size());
        merkleize(chunks, hash_tree_, limit, hasher_);
    }
}

}  // namespace silkworm::ssz