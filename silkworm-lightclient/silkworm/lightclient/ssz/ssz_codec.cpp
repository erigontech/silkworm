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

#include "ssz_codec.hpp"

namespace silkworm::ssz {

void encode(uint32_t from, Bytes& to) noexcept {
    for (std::size_t i{0}; i < sizeof(uint32_t); ++i) {
        to += reinterpret_cast<uint8_t*>(&from)[i];
    }
}

void encode(uint64_t from, Bytes& to) noexcept {
    for (std::size_t i{0}; i < sizeof(uint64_t); ++i) {
        to += reinterpret_cast<uint8_t*>(&from)[i];
    }
}

template <>
void encode(evmc::bytes32& from, Bytes& to) noexcept {
    for (std::size_t i{0}; i < kHashLength; ++i) {
        to += from.bytes[i];
    }
}

DecodingResult decode(ByteView& from, uint32_t& to) noexcept {
    if (from.size() < sizeof(uint32_t)) {
        return DecodingResult::kInputTooShort;
    }
    for (std::size_t i{0}; i < sizeof(uint32_t); ++i) {
        to += static_cast<uint32_t>(from[i]) << (i*8);
    }
    from.remove_prefix(sizeof(uint32_t));
    return DecodingResult::kOk;
}

DecodingResult decode(ByteView& from, uint64_t& to) noexcept {
    if (from.size() < sizeof(uint64_t)) {
        return DecodingResult::kInputTooShort;
    }
    for (std::size_t i{0}; i < sizeof(uint64_t); ++i) {
        to += static_cast<uint64_t>(from[i]) << (i*8);
    }
    from.remove_prefix(sizeof(uint64_t));
    return DecodingResult::kOk;
}

template <>
DecodingResult decode(ByteView& from, evmc::bytes32& to) noexcept {
    if (from.size() < kHashLength) {
        return DecodingResult::kInputTooShort;
    }
    for (std::size_t i{0}; i < kHashLength; ++i) {
        to.bytes[i] = from[i];
    }
    from.remove_prefix(kHashLength);
    return DecodingResult::kOk;
}

void encode_offset(uint32_t from, Bytes& to) noexcept {
    encode(from, to);
}

DecodingResult decode_offset(ByteView& from, uint32_t& to) noexcept {
    return decode(from, to);
}

}  // namespace silkworm::ssz
