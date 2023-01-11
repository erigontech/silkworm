/*  bytes_to_int.hpp
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
#include <concepts>
#include <cstddef>
#include <string>

namespace {
struct Table {
    std::array<long long, 128> tab;
    constexpr Table() : tab{} {
        tab['1'] = 1;
        tab['2'] = 2;
        tab['3'] = 3;
        tab['4'] = 4;
        tab['5'] = 5;
        tab['6'] = 6;
        tab['7'] = 7;
        tab['8'] = 8;
        tab['9'] = 9;
        tab['a'] = 10;
        tab['A'] = 10;
        tab['b'] = 11;
        tab['B'] = 11;
        tab['c'] = 12;
        tab['C'] = 12;
        tab['d'] = 13;
        tab['D'] = 13;
        tab['e'] = 14;
        tab['E'] = 14;
        tab['f'] = 15;
        tab['F'] = 15;
    }
    constexpr long long operator[](char const idx) const { return tab[std::size_t(idx)]; }
} constexpr table;
}  // namespace

namespace helpers {

// The caller is responsible to check the bounds
template <typename T>
requires(std::unsigned_integral<T>) T to_integer_little_endian(const std::uint8_t *arr) {
    auto ptr = reinterpret_cast<const T *>(arr);
    return *ptr;
}

constexpr int hextoint(char number) { return table[static_cast<std::size_t>(number)]; }

constexpr int strhex2int(std::string_view const &str) {
    int ret = 0;
    for (int i(str.size() - 1), j(1); i >= 0; --i, j *= 16) ret += (hextoint(str[std::size_t(i)]) * j);
    return ret;
}
}  // namespace helpers
