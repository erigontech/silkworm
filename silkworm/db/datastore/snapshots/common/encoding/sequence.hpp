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

#pragma once

#include <cstdint>
#include <iostream>
#include <vector>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/common/endian.hpp>
#include <silkworm/infra/common/ensure.hpp>

namespace silkworm::snapshots::encoding {

template <UnsignedIntegral T>
using UnsignedIntegralSequence = std::vector<T>;

//! Max integer sequence length capped at hard limit to fit in memory
inline constexpr size_t kMaxUnsignedIntegralSequenceSize{15 * kMebi};

using Uint32Sequence = UnsignedIntegralSequence<uint32_t>;
using Uint64Sequence = UnsignedIntegralSequence<uint64_t>;

template <UnsignedIntegral T>
std::ostream& operator<<(std::ostream& os, const UnsignedIntegralSequence<T>& s) {
    // Serialize the integer sequence size using 8-bytes
    const uint64_t size = s.size();
    Bytes buffer(sizeof(uint64_t), '\0');
    endian::store_big_u64(buffer.data(), size);
    os.write(reinterpret_cast<const char*>(buffer.data()), sizeof(uint64_t));

    // Serialize the integer sequence
    os.write(reinterpret_cast<const char*>(s.data()), static_cast<std::streamsize>(size * sizeof(T)));
    return os;
}

template <UnsignedIntegral T>
std::istream& operator>>(std::istream& is, UnsignedIntegralSequence<T>& s) {
    // Deserialize the integer sequence size using 8-bytes
    Bytes buffer(sizeof(uint64_t), '\0');
    is.read(reinterpret_cast<char*>(buffer.data()), sizeof(uint64_t));
    const uint64_t size = endian::load_big_u64(buffer.data());
    ensure(size <= kMaxUnsignedIntegralSequenceSize,
           [&] { return "decoded sequence size is too big: " + std::to_string(size); });

    // Deserialize the integer sequence
    s.resize(size);
    is.read(reinterpret_cast<char*>(s.data()), static_cast<std::streamsize>(size * sizeof(T)));
    return is;
}

}  // namespace silkworm::snapshots::encoding
