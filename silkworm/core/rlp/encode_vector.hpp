// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <numeric>
#include <span>
#include <vector>

#include <silkworm/core/rlp/encode.hpp>

namespace silkworm::rlp {

// std::span to RLP overloads

template <typename T>
size_t length_items(const std::span<const T>& v) {
    return std::accumulate(v.begin(), v.end(), size_t{0}, [](size_t sum, const T& x) { return sum + length(x); });
}

template <typename T>
size_t length(const std::span<const T>& v) {
    const size_t payload_length = length_items(v);
    return length_of_length(payload_length) + payload_length;
}

template <typename T>
void encode_items(Bytes& to, const std::span<const T>& v) {
    for (const T& x : v) {
        encode(to, x);
    }
}

template <typename T>
void encode(Bytes& to, const std::span<const T>& v) {
    const Header h{.list = true, .payload_length = length_items(v)};
    to.reserve(to.size() + length_of_length(h.payload_length) + h.payload_length);
    encode_header(to, h);
    encode_items(to, v);
}

// std::vector to RLP overloads

template <typename T>
size_t length_items(const std::vector<T>& v) {
    return length_items(std::span<const T>{v.data(), v.size()});
}

template <typename T>
size_t length(const std::vector<T>& v) {
    return length(std::span<const T>{v.data(), v.size()});
}

template <typename T>
void encode_items(Bytes& to, const std::vector<T>& v) {
    encode_items(to, std::span<const T>{v.data(), v.size()});
}

template <typename T>
void encode(Bytes& to, const std::vector<T>& v) {
    encode(to, std::span<const T>{v.data(), v.size()});
}

// variadic arguments to RLP overloads

template <typename Arg1, typename Arg2>
size_t length_items(const Arg1& arg1, const Arg2& arg2) {
    return length(arg1) + length(arg2);
}

template <typename Arg1, typename Arg2, typename... Args>
size_t length_items(const Arg1& arg1, const Arg2& arg2, const Args&... args) {
    return length(arg1) + length_items(arg2, args...);
}

template <typename Arg1, typename Arg2, typename... Args>
size_t length(const Arg1& arg1, const Arg2& arg2, const Args&... args) {
    const size_t payload_length = length_items(arg1, arg2, args...);
    return length_of_length(payload_length) + payload_length;
}

template <typename Arg1, typename Arg2>
void encode_items(Bytes& to, const Arg1& arg1, const Arg2& arg2) {
    encode(to, arg1);
    encode(to, arg2);
}

template <typename Arg1, typename Arg2, typename... Args>
void encode_items(Bytes& to, const Arg1& arg1, const Arg2& arg2, const Args&... args) {
    encode(to, arg1);
    encode_items(to, arg2, args...);
}

template <typename Arg1, typename Arg2, typename... Args>
void encode(Bytes& to, const Arg1& arg1, const Arg2& arg2, const Args&... args) {
    const Header h{/*list=*/true, /*payload_length=*/length_items(arg1, arg2, args...)};
    to.reserve(to.size() + length_of_length(h.payload_length) + h.payload_length);
    encode_header(to, h);
    encode_items(to, arg1, arg2, args...);
}

// RlpBytes to RLP overloads

/**
 * RlpBytes represents a raw RLP-encoded list item.
 * It is useful when RLP structure has a dynamic list with elements of different types.
 * Each item can be encoded separately and then assembled using the methods below.
 */
struct RlpBytes {
    Bytes data;
    explicit RlpBytes(Bytes data1) : data(std::move(data1)) {}
};

//! see RlpBytes
struct RlpByteView {
    ByteView data;
    explicit RlpByteView(ByteView data1) : data(data1) {}
};

template <>
inline void encode(Bytes& to, const std::span<const RlpByteView>& v) {
    Header header{true, 0};
    for (const auto& item : v) {
        header.payload_length += item.data.size();
    }
    to.reserve(to.size() + length_of_length(header.payload_length) + header.payload_length);

    encode_header(to, header);
    for (const auto& item : v) {
        to.append(item.data);
    }
}

template <>
inline void encode(Bytes& to, const std::vector<RlpByteView>& v) {
    encode(to, std::span<const RlpByteView>{v.data(), v.size()});
}

template <>
inline void encode(Bytes& to, const std::span<const RlpBytes>& v) {
    std::vector<RlpByteView> views;
    views.reserve(v.size());
    for (const auto& item : v) {
        views.emplace_back(item.data);
    }
    encode(to, views);
}

template <>
inline void encode(Bytes& to, const std::vector<RlpBytes>& v) {
    encode(to, std::span<const RlpBytes>{v.data(), v.size()});
}

}  // namespace silkworm::rlp
