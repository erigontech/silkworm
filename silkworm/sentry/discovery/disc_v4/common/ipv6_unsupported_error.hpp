// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <stdexcept>

namespace silkworm::sentry::discovery::disc_v4 {

class IPV6UnsupportedError : public std::runtime_error {
  public:
    IPV6UnsupportedError() : std::runtime_error("IPv6 is not supported") {}
};

}  // namespace silkworm::sentry::discovery::disc_v4
