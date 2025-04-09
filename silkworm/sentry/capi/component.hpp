// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>
#include <thread>

#include <boost/asio/cancellation_signal.hpp>

namespace silkworm::sentry::capi {

struct Component {
    std::unique_ptr<std::thread> sentry_thread;
    boost::asio::cancellation_signal sentry_stop_signal;
};

}  // namespace silkworm::sentry::capi
