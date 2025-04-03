// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <functional>
#include <string>
#include <string_view>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/common/bytes_to_string.hpp>

namespace silkworm::sentry {

class EccPublicKey {
  public:
    explicit EccPublicKey(Bytes data) : data_(std::move(data)) {}

    ByteView data() const { return data_; }
    Bytes::size_type size() const { return data_.size(); }

    Bytes serialized_std(bool is_compressed = false) const;
    Bytes serialized() const;
    std::string hex() const;

    static EccPublicKey deserialize_std(ByteView serialized_data);
    static EccPublicKey deserialize(ByteView serialized_data);
    static EccPublicKey deserialize_hex(std::string_view hex);

    friend bool operator==(const EccPublicKey&, const EccPublicKey&) = default;

  private:
    Bytes data_;
};

//! for using EccPublicKey as a key of std::map
bool operator<(const EccPublicKey& lhs, const EccPublicKey& rhs);

}  // namespace silkworm::sentry

namespace std {

//! for using EccPublicKey as a key of std::unordered_map
template <>
struct hash<silkworm::sentry::EccPublicKey> {
    size_t operator()(const silkworm::sentry::EccPublicKey& public_key) const noexcept {
        auto data_str = silkworm::byte_view_to_string_view(public_key.data());
        return std::hash<std::string_view>{}(data_str);
    }
};

}  // namespace std
