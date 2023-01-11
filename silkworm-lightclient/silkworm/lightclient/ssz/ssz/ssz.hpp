/*  ssz.hpp
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
#include <cstdint>

namespace constants {
constexpr std::uint32_t BYTES_PER_LENGTH_OFFSET = 4;
constexpr unsigned int BYTES_PER_CHUNK = 32;
constexpr unsigned int BITS_PER_BYTE = 8;
}  // namespace constants

namespace ssz {
using Chunk = std::array<std::uint8_t, constants::BYTES_PER_CHUNK>;
}
