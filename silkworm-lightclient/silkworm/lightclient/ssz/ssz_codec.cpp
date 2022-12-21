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

#include <bit>

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

DecodingResult decode(ByteView from, uint32_t& to) noexcept {
    if (from.size() < sizeof(uint32_t)) {
        return DecodingResult::kInputTooShort;
    }
    for (std::size_t i{0}; i < sizeof(uint32_t); ++i) {
        to += static_cast<uint32_t>(from[i]) << (i*8);
    }
    return DecodingResult::kOk;
}

DecodingResult decode(ByteView from, uint64_t& to) noexcept {
    if (from.size() < sizeof(uint64_t)) {
        return DecodingResult::kInputTooShort;
    }
    for (std::size_t i{0}; i < sizeof(uint64_t); ++i) {
        to += static_cast<uint64_t>(from[i]) << (i*8);
    }
    return DecodingResult::kOk;
}

template <>
DecodingResult decode(ByteView from, evmc::bytes32& to) noexcept {
    if (from.size() < kHashLength) {
        return DecodingResult::kInputTooShort;
    }
    for (std::size_t i{0}; i < kHashLength; ++i) {
        to.bytes[i] = from[i];
    }
    return DecodingResult::kOk;
}

void encode_offset(uint32_t from, Bytes& to) noexcept {
    encode(from, to);
}

DecodingResult decode_offset(ByteView from, uint32_t& to) noexcept {
    return decode(from, to);
}

DecodingResult validate_bitlist(ByteView buffer, std::size_t bit_limit) noexcept {
    const std::size_t size = buffer.size();
    if (size == 0) {
        return DecodingResult::kInputTooShort;  // TODO(canepat) kInvalidZeroLength
    }

    // Maximum possible bytes in a bitlist with provided bit limit
    const std::size_t max_bytes = (bit_limit >> 3) + 1;
    if (size > max_bytes) {
        return DecodingResult::kUnexpectedLength;
    }

    // The most significant bit is present in the last byte in the array
    const uint8_t last_byte = buffer[size - 1];
    if (last_byte == 0) {
        return DecodingResult::kInvalidFieldset;  // TODO(canepat) kTrailingByteIsZero
    }

    // Determine the position of the most significant bit i.e. the minimum number of bits to represent last byte
    const uint8_t msb = std::bit_width(last_byte);

    // The absolute position of the most significant bit will be the number of
    // bits in the preceding bytes plus the position of the most significant
    // bit. Subtract this value by 1 to determine the length of the bitlist
    const auto num_of_bits = 8 * (size - 1) + msb - 1;
    if (num_of_bits > bit_limit) {
        return DecodingResult::kUnexpectedLength;
    }

    return DecodingResult::kOk;
}

}  // namespace silkworm::ssz
