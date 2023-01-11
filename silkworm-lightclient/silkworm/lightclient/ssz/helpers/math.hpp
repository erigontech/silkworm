/*  math.hpp
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
#include <algorithm>
#include <array>
#include <bit>
#include <climits>
#include <cmath>
#include <concepts>
#include <utility>

namespace helpers {

template <typename T>
constexpr T sqrt_helper(T x, T lo, T hi) {
    if (lo == hi) return lo;

    const T mid = (lo + hi + 1) / 2;
    if (x / mid < mid)
        return sqrt_helper<T>(x, lo, mid - 1);
    else
        return sqrt_helper(x, mid, hi);
}

template <typename T>
constexpr T ct_sqrt(T x) {
    return sqrt_helper<T>(x, 0, x / 2 + 1);
}

template <typename T>
T integer_squareroot(T x) {
    T r = static_cast<T>(std::sqrt(double(x)));
    T sqrt_max = ct_sqrt(std::numeric_limits<T>::max());

    while (r < sqrt_max && r * r < x) r++;
    while (r > sqrt_max || r * r > x) r--;

    return r;
}

int log2ceil(std::unsigned_integral auto n) { return n ? CHAR_BIT * sizeof(n) - std::countl_zero(n - 1) : 0; }

}  // namespace helpers
