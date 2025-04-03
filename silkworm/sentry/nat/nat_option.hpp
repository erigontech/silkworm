// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>
#include <string>
#include <string_view>

#include <boost/asio/ip/address.hpp>

namespace silkworm::sentry::nat {

enum class NatMode {
    kNone,
    kExternalIP,
    kStun,
};

struct NatOption {
    NatMode mode{NatMode::kStun};
    std::optional<boost::asio::ip::address> value;
};

bool lexical_cast(const std::string& input, NatOption& value);
bool lexical_cast(std::string_view input, NatOption& value);

}  // namespace silkworm::sentry::nat
