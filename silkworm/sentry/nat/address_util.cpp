// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "address_util.hpp"

#include <stdexcept>

namespace silkworm::sentry::nat {

using namespace boost::asio;

ip::address make_address_from_sockaddr(const sockaddr* address) {
    switch (address->sa_family) {
        case AF_INET: {
            auto address_v4 = reinterpret_cast<const sockaddr_in*>(address);
            auto raw_value = ntohl(address_v4->sin_addr.s_addr);
            return ip::address{ip::address_v4{raw_value}};
        }
        case AF_INET6: {
            auto address_v6 = reinterpret_cast<const sockaddr_in6*>(address);
            auto raw_value = reinterpret_cast<const std::array<unsigned char, 16>&>(address_v6->sin6_addr.s6_addr);
            return ip::address{ip::address_v6{raw_value, address_v6->sin6_scope_id}};
        }
        default:
            throw std::runtime_error("stun_ip_resolver: unexpected address family");
    }
}

}  // namespace silkworm::sentry::nat
