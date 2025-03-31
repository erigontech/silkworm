// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "local_ip_resolver.hpp"

#include <boost/asio/ip/udp.hpp>
#include <boost/asio/this_coro.hpp>

namespace silkworm::sentry::nat {

using namespace boost::asio;
using namespace boost::asio::ip;

Task<address> local_ip_resolver() {
    auto executor = co_await this_coro::executor;
    udp::socket socket(executor);
    socket.connect(udp::endpoint{make_address("1.1.1.1"), 53});
    co_return socket.local_endpoint().address();
}

}  // namespace silkworm::sentry::nat
