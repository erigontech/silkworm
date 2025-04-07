// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <utility>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/steady_timer.hpp>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/infra/concurrency/signal_handler.hpp>

namespace silkworm {

using namespace std::chrono_literals;

class TimerImpl;

//! \brief Asynchronous periodic timer relying on boost:asio timer facility
//! \note This class supports RAII pattern: the Timer destructor will stop the timer
//! \warning after stop the timer expiration callback *may* be called once more
class Timer {
  public:
    //! Create a new periodic timer
    //! \param executor [in] : executor running the timer
    //! \param interval [in] : length of wait interval (in milliseconds)
    //! \param callback [in] : the call back function to be called
    //! \param auto_start [in] : whether to start the timer immediately
    Timer(const boost::asio::any_io_executor& executor,
          uint32_t interval,
          std::function<bool()> callback,
          bool auto_start = true);

    //! Stop and destroy the timer
    //! \warning after stop the timer expiration callback *may* be called once more
    ~Timer();

    //! \brief Start the timer asynchronously. Eventually callback gets executed and timer automatically rescheduled
    //! \details this call is idempotent
    void start();

    //! \brief Stop the timer and cancel any pending expiration
    //! \details Callback may still be executed *once* if timer gets cancelled after expiration but before completion
    //! handler dispatching
    //! \details this call is idempotent
    void stop();

    //! \brief Cancel the next timer expiration and reschedule for a new interval if still running
    void reset();

  private:
    std::shared_ptr<TimerImpl> p_impl_;
};

}  // namespace silkworm
