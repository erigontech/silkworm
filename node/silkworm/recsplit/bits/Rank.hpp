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

/*
 * Sux: Succinct data structures
 *
 * Copyright (C) 2019-2020 Stefano Marchini and Sebastiano Vigna
 *
 *  This library is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU Lesser General Public License as published by the Free
 *  Software Foundation; either version 3 of the License, or (at your option)
 *  any later version.
 *
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 3, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * Under Section 7 of GPL version 3, you are granted additional permissions
 * described in the GCC Runtime Library Exception, version 3.1, as published by
 * the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License and a copy of
 * the GCC Runtime Library Exception along with this program; see the files
 * COPYING3 and COPYING.RUNTIME respectively.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <cstddef>
#include <cstdint>

namespace sux {

using namespace std;

/** An interface specifying ranking primitives.
 *
 * This inferface specifies primitives both on ones and on zeroes because ranking on
 * ones automatically makes it possible ranking on zeros, and viceversa. This interface
 * provides template methods for rank(std::size_t, std::size_t), rankZero(std::size_t) and rankZero(std::size_t,std::size_t)
 * using just rank(std::size_t).
 */

class Rank {
  public:
    virtual ~Rank() = default;

    /** Returns the number of ones before the given posistion.
     *
     * @param pos A position from 0 to size() (included).
     * @return the number of ones from the start of the bit vector up to the given position (excluded).
     */
    virtual uint64_t rank(std::size_t pos) = 0;

    /** Returns the number of ones between two given positions.
     *
     * @param from A starting position from 0 to size() (included).
     * @param to An ending position from `from` to size() (included).
     * @return the number of ones from the starting position (included) to the ending position (excluded).
     */
    uint64_t rank(std::size_t from, std::size_t to) { return rank(to) - rank(from); }

    /** Returns the number of zeros before the given posistion.
     *
     * @param pos A position from 0 to size() (included).
     * @return the number of zeros from the start of the bit vector up to the given position (excluded).
     */
    virtual uint64_t rankZero(std::size_t pos) { return pos - rank(pos); }

    /** Returns the number of zeros between two given positions.
     *
     * @param from A starting position from 0 to size() (included).
     * @param to An ending position from `from` to size() (included).
     * @return the number of zeros from the starting position (included) to the ending position (excluded).
     */
    uint64_t rankZero(std::size_t from, std::size_t to) { return rankZero(to) - rankZero(from); }

    /** Returns the length (in bits) of the underlying bit vector. */
    virtual std::size_t size() const = 0;
};

}  // namespace sux
