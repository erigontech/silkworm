// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once
#include <chrono>

namespace silkworm::sentry::discovery::disc_v4 {

std::chrono::time_point<std::chrono::system_clock> make_message_expiration();
bool is_expired_message_expiration(std::chrono::time_point<std::chrono::system_clock> expiration);
bool is_time_in_past(std::chrono::time_point<std::chrono::system_clock> time);

}  // namespace silkworm::sentry::discovery::disc_v4
