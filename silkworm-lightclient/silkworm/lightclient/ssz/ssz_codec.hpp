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

#include <array>

#include <evmc/evmc.hpp>

#include <silkworm/common/base.hpp>
#include <silkworm/common/decoding_result.hpp>

namespace silkworm::ssz {

void encode(uint32_t from, Bytes& to) noexcept;

void encode(uint64_t from, Bytes& to) noexcept;

template <class T>
void encode(T& from, Bytes& to) noexcept;

template <class T, std::size_t N>
requires std::convertible_to<T, uint8_t>
void encode(T (&from)[N], Bytes& to) noexcept {
    for (std::size_t i{0}; i < N; ++i) {
        to += from[i];
    }
}

template <>
void encode(evmc::bytes32& from, Bytes& to) noexcept;

DecodingResult decode(ByteView from, uint32_t& to) noexcept;

DecodingResult decode(ByteView from, uint64_t& to) noexcept;

template <class T>
DecodingResult decode(ByteView from, T& to) noexcept;

template <class T, std::size_t N>
requires std::convertible_to<T, uint8_t>
DecodingResult decode(ByteView from, T (&to)[N]) noexcept {
    if (from.size() < N) {
        return DecodingResult::kInputTooShort;
    }
    for (std::size_t i{0}; i < N; ++i) {
        to[i] = static_cast<uint8_t>(from[i]);
    }
    from.remove_prefix(N);
    return DecodingResult::kOk;
}

template <>
DecodingResult decode(ByteView from, evmc::bytes32& to) noexcept;

void encode_offset(uint32_t from, Bytes& to) noexcept;

DecodingResult decode_offset(ByteView from, uint32_t& to) noexcept;

DecodingResult validate_bitlist(ByteView from, std::size_t bit_limit) noexcept;

}  // namespace silkworm::ssz
