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

#include <silkworm/common/base.hpp>

namespace silkworm::succinct {

template <UnsignedIntegral T>
using UnsignedIntegralSequence = std::vector<T>;

using Uint32Sequence = UnsignedIntegralSequence<uint32_t>;
using Uint64Sequence = UnsignedIntegralSequence<uint64_t>;

template <UnsignedIntegral T>
std::ostream& operator<<(std::ostream& os, const UnsignedIntegralSequence<T>& s) {
    const uint64_t size = s.size();
    os.write(reinterpret_cast<const char*>(&size), sizeof(T));
    os.write(reinterpret_cast<const char*>(s.data()), static_cast<std::streamsize>(size * sizeof(T)));
    return os;
}

template <UnsignedIntegral T>
std::istream& operator>>(std::istream& is, UnsignedIntegralSequence<T>& s) {
    uint64_t size{0};
    is.read(reinterpret_cast<char*>(&size), sizeof(T));
    s.resize(size);
    is.read(reinterpret_cast<char*>(s.data()), static_cast<std::streamsize>(size * sizeof(T)));
    return is;
}

}  // namespace silkworm::succinct
