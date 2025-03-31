// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "enr/message_handler.hpp"
#include "find/message_handler.hpp"
#include "ping/message_handler.hpp"

namespace silkworm::sentry::discovery::disc_v4 {

struct MessageHandler
    : ping::MessageHandler,
      enr::MessageHandler,
      find::MessageHandler {
};

}  // namespace silkworm::sentry::discovery::disc_v4
