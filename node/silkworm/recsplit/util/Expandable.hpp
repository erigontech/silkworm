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

#include <assert.h>

#include <iostream>
#include <string>

#include <sys/mman.h>

#include "../support/common.hpp"

namespace silkworm::succinct::util {

/** A generic interface for classes that have size (the current
 * number of elements) and capacity (the number of elements
 * that can be added before a reallocation happens). */

class Expandable {
  public:
    virtual ~Expandable() = default;

    /** Enlarges this expandable so that it can contain a given number of elements
     *  without memory reallocation.
     *
     * If the current capacity is sufficient, nothing happens. Otherwise, the
     * expandable is enlarged to the provided capacity.
     *
     * @param capacity the desired new capacity.
     */
    virtual void reserve(size_t capacity) = 0;

    /** Enlarges this expandable so that it can contain
     * a given number of elements, plus possibly extra space.
     *
     * If the current capacity is sufficient, nothing happens. Otherwise, the
     * expandable is enlarged, usually to the maximum between the provided
     * capacity and 50% more than the current capacity.
     *
     * @param capacity the desired new capacity.
     */
    virtual void grow(size_t capacity) = 0;

    /** Changes the expandable size to the given value.
     *
     * If the argument is smaller than or equal to the current size,
     * there is no memory reallocation. Otherwise, reallocation
     * happens with grow().
     *
     * @param size the desired new size.
     */
    virtual void resize(size_t size) = 0;

    /** Returns the number of elements in this expandable. */
    virtual size_t size() const = 0;

    /** Changes the expandable size and capacity to the given value.
     *
     * @param size the desired new size and capacity.
     */
    virtual void size(size_t size) = 0;

    /** Trims the data structure to the given capacity
     *
     * provided it is larger than the current size.
     * @param capacity the new desired capacity.
     */
    virtual void trim(size_t capacity) = 0;

    /** Trims the the memory allocated so that size and capacity are the same. */
    void trimToFit() { trim(size()); };
};

}  // namespace silkworm::succinct::util
