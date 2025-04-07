// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "ip_resolver.hpp"

#include "local_ip_resolver.hpp"
#include "stun_ip_resolver.hpp"

namespace silkworm::sentry::nat {

Task<boost::asio::ip::address> ip_resolver(const NatOption& option) {
    switch (option.mode) {
        case NatMode::kNone:
            co_return (co_await local_ip_resolver());
        case NatMode::kExternalIP:
            co_return option.value.value();
        case NatMode::kStun:
            co_return (co_await stun_ip_resolver());
    }
}

}  // namespace silkworm::sentry::nat
