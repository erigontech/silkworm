// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <boost/asio/ip/address.hpp>

namespace silkworm::sentry::discovery::disc_v4 {

enum class IpAddressType {
    kRegular,
    kUnspecified,
    kLoopback,
    kMulticast,
    kBroadcast,
    kLAN,
    // https://www.iana.org/assignments/iana-ipv4-special-registry/
    // https://www.iana.org/assignments/iana-ipv6-special-registry/
    kSpecial,
};

IpAddressType ip_classify(const boost::asio::ip::address& ip);

}  // namespace silkworm::sentry::discovery::disc_v4
