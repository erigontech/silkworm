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
#include <functional>

#include <evmc/evmc.hpp>
#include <magic_enum.hpp>
#include <tl/expected.hpp>

#include <silkworm/common/base.hpp>
#include <silkworm/common/decoding_result.hpp>
#include <silkworm/common/encoding_result.hpp>

namespace silkworm::ssz {

//! Number of bytes per serialized length offset
static constexpr uint32_t kBytesPerLengthOffset{sizeof(uint32_t)};

void encode(uint32_t from, Bytes& to) noexcept;

void encode(uint64_t from, Bytes& to) noexcept;

template <class T>
EncodingResult encode(T& from, Bytes& to) noexcept;

template <class T, std::size_t N>
requires std::convertible_to<T, uint8_t>
EncodingResult encode(T (&from)[N], Bytes& to) noexcept {
    for (std::size_t i{0}; i < N; ++i) {
        to += from[i];
    }
    return EncodingResult::kOk;
}

void encode(evmc::address& from, Bytes& to) noexcept;

void encode(evmc::bytes32& from, Bytes& to) noexcept;

DecodingResult decode(ByteView from, uint32_t& to) noexcept;

DecodingResult decode(ByteView from, uint64_t& to) noexcept;

template <class T>
DecodingResult decode(ByteView from, T& to) noexcept;

template <class T, std::size_t N>
requires std::convertible_to<T, uint8_t>
DecodingResult decode(ByteView from, T (&to)[N]) noexcept {
    if (from.size() < N) {
        return tl::unexpected(DecodingError::kInputTooShort);
    }
    for (std::size_t i{0}; i < N; ++i) {
        to[i] = static_cast<uint8_t>(from[i]);
    }
    from.remove_prefix(N);
    return {};
}

template <>
DecodingResult decode(ByteView from, evmc::address& to) noexcept;

template <>
DecodingResult decode(ByteView from, evmc::bytes32& to) noexcept;

void encode_offset(uint32_t from, Bytes& to) noexcept;

DecodingResult decode_offset(ByteView from, uint32_t& to) noexcept;

DecodingResult decode_dynamic_length(ByteView from, std::size_t max_length, std::size_t& length) noexcept;

using DynamicReader = std::function<DecodingResult(std::size_t, ByteView)>;
DecodingResult decode_dynamic(ByteView from, std::size_t length, const DynamicReader& read_one) noexcept;

DecodingResult validate_bitlist(ByteView from, std::size_t bit_limit) noexcept;

inline void success_or_throw(EncodingResult result) {
    if (result != EncodingResult::kOk) {
        throw std::runtime_error{"encoding error: " + std::string(magic_enum::enum_name(result))};
    }
}

template <class T>
[[nodiscard]] evmc::bytes32 hash_tree_root(T& /*object*/) {
    return evmc::bytes32{};
}

}  // namespace silkworm::ssz
