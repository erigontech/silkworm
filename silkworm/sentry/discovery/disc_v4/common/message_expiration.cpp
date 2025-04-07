// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "message_expiration.hpp"

namespace silkworm::sentry::discovery::disc_v4 {

std::chrono::time_point<std::chrono::system_clock> make_message_expiration() {
    using namespace std::chrono_literals;
    static constexpr std::chrono::seconds kTtl = 20s;
    return std::chrono::system_clock::now() + kTtl;
}

bool is_expired_message_expiration(std::chrono::time_point<std::chrono::system_clock> expiration) {
    return is_time_in_past(expiration);
}

bool is_time_in_past(std::chrono::time_point<std::chrono::system_clock> time) {
    return time < std::chrono::system_clock::now();
}

}  // namespace silkworm::sentry::discovery::disc_v4
