// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <atomic>

#include <silkworm/infra/concurrency/signal_handler.hpp>

namespace silkworm {

//! \brief Components implementing stop-ability should derive from this
class Stoppable {
  public:
    //! \brief Sets a stop request for instance;
    //! \return True if the stop request has been triggered otherwise false (i.e. was already stopping)
    virtual bool stop() {
        bool expected{false};
        return stopping_.compare_exchange_strong(expected, true);
    }

    //! \brief Whether a stop request has been issued
    bool is_stopping() { return stopping_.load() || SignalHandler::signalled(); }

    virtual ~Stoppable() = default;

  private:
    std::atomic_bool stopping_{false};
};

}  // namespace silkworm
