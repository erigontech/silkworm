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

#include <silkworm/core/common/base.hpp>
#include <silkworm/lightclient/ssz/ssz_container.hpp>

namespace silkworm::cl {

//! \brief Variable-length integer (Varint) encoding based on continuation bits
template <typename int_t = uint64_t>
std::size_t encode_varint(int_t value, Bytes& output) {
    std::size_t varint_size{0};
    while (value > 127) {
        output.push_back(static_cast<uint8_t>(value & 127) | 128);
        value >>= 7;
        ++varint_size;
    }
    output.push_back(static_cast<uint8_t>(value) & 127);
    return ++varint_size;
}

//! \brief Variable-length integer (Varint) decoding based on continuation bits
template <typename int_t = uint64_t>
std::size_t decode_varint(ByteView input, int_t& value) {
    std::size_t varint_size{0};
    value = 0;
    int bits{0};
    auto input_it = input.cbegin();
    while (*input_it & 128) {
        value += (static_cast<int_t>(*input_it & 127) << bits);
        value >>= 7;
        ++input_it;
        bits += 7;
        ++varint_size;
    }
    value += (static_cast<int_t>(*input_it & 127) << bits);
    return ++varint_size;
}

}  // namespace silkworm::cl
