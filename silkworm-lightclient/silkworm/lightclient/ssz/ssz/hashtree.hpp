/*  hashtree.hpp
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

#pragma once

#include <array>
#include <cstddef>
#include <cstring>
#include <vector>

#include "../ssz/hasher.hpp"
#include "../ssz/ssz.hpp"

namespace ssz {

class HashTree {
   private:
    static inline const Hasher hasher;
    std::vector<Chunk> hash_tree_;

   public:
    explicit HashTree(const std::vector<Chunk>& chunks, std::uint64_t limit = 0);
    explicit HashTree(const std::vector<std::uint8_t>& vec, std::uint64_t limit = 0);

    void mix_in(std::size_t length);
    [[nodiscard]] std::vector<Chunk> hash_tree() const { return hash_tree_; }
    [[nodiscard]] Chunk hash_tree_root() const { return hash_tree_.back(); }
};

}  // namespace ssz
