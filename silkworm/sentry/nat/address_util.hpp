// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <boost/asio/ip/address.hpp>

namespace silkworm::sentry::nat {

boost::asio::ip::address make_address_from_sockaddr(const sockaddr* address);

}  // namespace silkworm::sentry::nat
