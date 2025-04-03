// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <tuple>

#include <silkworm/core/common/bytes.hpp>

namespace silkworm::db::kv::api {

struct KeyValue {
    Bytes key;
    Bytes value;

    KeyValue() noexcept = default;

    KeyValue(Bytes k, Bytes v) : key{std::move(k)}, value{std::move(v)} {}

    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    KeyValue(Bytes k) : key{std::move(k)} {}

    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    KeyValue(std::pair<Bytes, Bytes> kv_pair)
        : key{std::move(kv_pair.first)}, value{std::move(kv_pair.second)} {}
};

inline bool operator<(const KeyValue& lhs, const KeyValue& rhs) {
    return lhs.key < rhs.key;
}

inline bool operator==(const KeyValue& lhs, const KeyValue& rhs) {
    return lhs.key == rhs.key;
}

}  // namespace silkworm::db::kv::api
