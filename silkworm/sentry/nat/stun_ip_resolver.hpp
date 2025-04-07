// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/ip/address.hpp>

namespace silkworm::sentry::nat {

Task<boost::asio::ip::address> stun_ip_resolver();

}  // namespace silkworm::sentry::nat
