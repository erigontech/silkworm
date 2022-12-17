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
 * Copyright (C) 2019-2020 Stefano Marchini
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
#include <utility>

#include <sys/mman.h>

#include "../support/common.hpp"
#include "Expandable.hpp"

namespace silkworm::succinct::util {

/** Possible types of memory allocation.
 *
 * \see https://www.kernel.org/doc/html/latest/admin-guide/mm/hugetlbpage.html
 * \see https://www.kernel.org/doc/html/latest/admin-guide/mm/transhuge.html
 */
enum AllocType {
    /** Standard allocation with `malloc()` (usually, the default). */
    MALLOC,
    /** Allocation with `mmap()`. Allocations are aligned on a memory page (typically, 4KiB). */
    SMALLPAGE,
    /** Transparent huge pages support through `mmap()` and `madvise()`
     * on Linux. Allocations are usually a mutiple of 4KiB, but they can be defragmented in blocks of 2MiB each. */
    TRANSHUGEPAGE,
    /** Direct huge page support through `mmap()` on Linux.
     * In this case allocations are aligned on a huge (typically, 2MiB) memory page.
     * This feature is usually disabled by default and it requires the administrator
     * to pre-reserve space for huge memory pages as documented in the reported external references  */
    FORCEHUGEPAGE
};

/** An expandable vector with settable type of memory allocation.
 *
 * Instances of this class have a behavior similar to std::vector.
 * However, the strategy used for allocation memory can be selected.
 * Moreover, the class is just a thin wrapper around a backing array:
 * in particular, there are no bound checks.
 *
 * Once enough capacity has been allocated through reserve(size_t),
 * the operator operator&() will return a pointer to the backing array
 * and the allocated space can be used directly, if necessary.
 *
 * This class implements the standard `<<` and `>>` operators for simple
 * serialization and deserialization.
 *
 * @tparam T the data type of an element.
 * @tparam AT a type of memory allocation out of ::AllocType.
 */

template <typename T, AllocType AT = MALLOC>
class Vector : public Expandable {
#ifndef MAP_HUGETLB
#pragma message("Huge pages not supported")
#define MAP_HUGETLB 0
#define MADV_HUGEPAGE 0
#endif

  public:
    static constexpr int PROT = PROT_READ | PROT_WRITE;
    static constexpr int FLAGS = MAP_PRIVATE | MAP_ANONYMOUS | (AT == FORCEHUGEPAGE ? MAP_HUGETLB : 0);

  private:
    size_t _size = 0, _capacity = 0;
    T* data = nullptr;

  public:
    Vector() = default;

    explicit Vector(size_t length) { size(length); }

    explicit Vector(const T* input_data, size_t length) : Vector(length) { memcpy(this->data, input_data, length); }

    ~Vector() {
        if (data) {
            if (AT == MALLOC) {
                free(data);
            } else {
                int result = munmap(data, _capacity);
                assert(result == 0 && "mmunmap failed");
                (void)result;
            }
        }
    }

    // Delete copy operators
    Vector(const Vector&) = delete;
    Vector& operator=(const Vector&) = delete;

    // Define move operators
    Vector(Vector<T, AT>&& oth) : _size(std::exchange(oth._size, 0)), _capacity(std::exchange(oth._capacity, 0)), data(std::exchange(oth.data, nullptr)) {}

    Vector<T, AT>& operator=(Vector<T, AT>&& oth) {
        swap(*this, oth);
        return *this;
    }

    /** Trim the the memory allocated so that it holds at most the given number of elements.
     * @param capacity the new desired capacity.
     */
    void trim(size_t capacity) {
        if (capacity >= _size && capacity < _capacity) remap(capacity);
    }

    /** Trim the the memory allocated so that it holds exactly size() elements. */
    void trimToFit() { trim(_size); }

    /** Enlarges the backing array to that it can contain a given number of elements.
     *
     * If the current capacity is sufficient, nothing happens. Otherwise, the
     * backing is enlarged to the provided capacity.
     *
     * @param capacity the desired new capacity.
     */
    void reserve(size_t capacity) {
        if (capacity > _capacity) remap(capacity);
    }

    /** Enlarges the backing array to that it can contain a given number of elements, plus possibly extra space.
     *
     * If the current capacity is sufficient, nothing happens. Otherwise, the
     * backing is enlarged to the maximum between the provided capacity and
     * 50% more than the current capacity.
     *
     * @param capacity the desired new capacity.
     */
    void grow(size_t capacity) {
        if (capacity > _capacity) remap(max(capacity, _capacity + (_capacity / 2)));
    }

    /** Changes the vector size to the given value.
     *
     * If the argument is smaller than or equal to the current size,
     * the backing array is unmodified. Otherwise, the backing array
     * is enlarged to the given size using grow(). New elements are
     * initialized to zero.
     *
     * @param size the desired new size.
     */
    void resize(size_t size) {
        grow(size);
        _size = size;
    }

    /** Changes the vector size and capacity to the given value.
     *
     * Both size and capacity are set to the provided size.
     * If necessary, new elements are initialized to zero.
     *
     * @param size the desired new size.
     */
    void size(size_t size) {
        reserve(size);
        _size = size;
        trimToFit();
    }

    /** Adds a given element at the end of this vector.
     *
     * @param elem an element.
     */
    void pushBack(T elem) {
        resize(_size + 1);
        data[_size - 1] = elem;
    }

    /** Pops the element at the end of this vector.
     *
     *  The last element of this vector is removed and
     *  returned.
     *
     * @return the last element of this vector.
     */
    T popBack() { return data[--_size]; }

    friend void swap(Vector<T, AT>& first, Vector<T, AT>& second) noexcept {
        std::swap(first._size, second._size);
        std::swap(first._capacity, second._capacity);
        std::swap(first.data, second.data);
    }

    /** Returns a pointer at the start of the backing array. */
    inline T* operator&() const { return data; }

    /** Returns the given element of the vector. */
    inline const T& operator[](size_t i) const { return data[i]; };

    /** Returns the given element of the vector. */
    inline T& operator[](size_t i) { return data[i]; };

    /** Returns the number of elements in this vector. */
    inline size_t size() const { return _size; }

    /** Returns the number of elements that this vector
     * can hold currently without increasing its capacity.
     *
     * @return the number of elements that this vector
     * can hold currently without increasing its capacity.
     */
    inline size_t capacity() const { return _capacity; }

    /** Returns the number of bits used by this vector.
     * @return the number of bits used by this vector.
     */
    size_t bitCount() const { return sizeof(*this) * 8 + _capacity * sizeof(T) * 8; }

  private:
    static size_t page_aligned(size_t size) {
        if (AT == FORCEHUGEPAGE)
            return ((2 * 1024 * 1024 - 1) | (size * sizeof(T) - 1)) + 1;
        else
            return ((4 * 1024 - 1) | (size * sizeof(T) - 1)) + 1;
    }

    void remap(size_t size) {
        if (size == 0) return;

        void* mem;
        size_t space;  // Space to allocate, in bytes

        if (AT == MALLOC) {
            space = size * sizeof(T);
            mem = _capacity == 0 ? malloc(space) : realloc(data, space);
            assert(mem != NULL && "malloc failed");
        } else {
            space = page_aligned(size);
            if (_capacity == 0)
                mem = mmap(nullptr, space, PROT, FLAGS, -1, 0);
            else {
#ifndef MREMAP_MAYMOVE
                mem = mmap(nullptr, space, PROT, FLAGS, -1, 0);
                memcpy(mem, data, page_aligned(_capacity));
#else
                mem = mremap(data, page_aligned(_capacity), space, MREMAP_MAYMOVE, -1, 0);
#endif
            }
            assert(mem != MAP_FAILED && "mmap failed");

            if (AT == TRANSHUGEPAGE) {
                int adv = madvise(mem, space, MADV_HUGEPAGE);
                assert(adv == 0 && "madvise failed");
                (void)adv;
            }
        }

        if (_capacity * sizeof(T) < space) memset(static_cast<char*>(mem) + _capacity * sizeof(T), 0, space - _capacity * sizeof(T));

        _capacity = space / sizeof(T);
        data = static_cast<T*>(mem);
    }

    friend std::ostream& operator<<(std::ostream& os, const Vector<T, AT>& vector) {
        uint64_t nsize = vector.size();
        os.write(reinterpret_cast<char*>(&nsize), sizeof(uint64_t));
        os.write(reinterpret_cast<char*>(&vector), vector.size() * sizeof(T));
        return os;
    }

    friend std::istream& operator>>(std::istream& is, Vector<T, AT>& vector) {
        uint64_t nsize;
        is.read(reinterpret_cast<char*>(&nsize), sizeof(uint64_t));
        vector = Vector<T, AT>(nsize);
        is.read(reinterpret_cast<char*>(&vector), vector.size() * sizeof(T));
        return is;
    }
};

}  // namespace silkworm::succinct::util
