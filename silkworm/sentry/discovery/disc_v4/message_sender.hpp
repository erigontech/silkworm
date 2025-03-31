// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "enr/message_sender.hpp"
#include "find/message_sender.hpp"
#include "ping/message_sender.hpp"

namespace silkworm::sentry::discovery::disc_v4 {

struct MessageSender
    : ping::MessageSender,
      enr::MessageSender,
      find::MessageSender {
};

}  // namespace silkworm::sentry::discovery::disc_v4
