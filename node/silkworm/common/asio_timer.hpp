/*
    Copyright 2021-2022 The Silkworm Authors

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/

#pragma once
#ifndef SILKWORM_COMMON_ASIO_TIMER_HPP_
#define SILKWORM_COMMON_ASIO_TIMER_HPP_

#include <atomic>
#include <chrono>
#include <cstdint>
#include <utility>

#ifdef __APPLE__
// otherwise <boost/asio/detail/socket_types.hpp> dependency doesn't compile
#define _DARWIN_C_SOURCE
#endif
#include <boost/asio/deadline_timer.hpp>
#include <boost/asio/io_context.hpp>

#include <silkworm/common/assert.hpp>
#include <silkworm/concurrency/signal_handler.hpp>

namespace silkworm {

using namespace std::chrono_literals;

//! \brief Implementation of an asynchronous timer relying on boost:asio
class Timer {
  public:
    //! \param asio_context [in] : boost's asio context
    //! \param interval [in] : length of wait interval (in milliseconds)
    //! \param call_back [in] : the call back function to be called
    //! \param auto_start [in] : whether to start the timer immediately
    explicit Timer(boost::asio::io_context& asio_context, uint32_t interval, std::function<bool()> call_back,
                   bool auto_start = false)
        : interval_(interval), timer_(asio_context), call_back_(std::move(call_back)) {
        SILKWORM_ASSERT(interval > 0);
        if (auto_start) {
            start();
        }
    };

    ~Timer() { stop(); }

    //! \brief Starts timer and waits for interval to expire. Eventually call back action is executed and timer
    //! resubmitted for another interval
    void start() {
        bool expected_running{false};
        if (is_running.compare_exchange_strong(expected_running, true)) {
            launch();
        }
    }

    //! \brief Stops timer and cancels pending execution. No callback is executed and no resubmission
    void stop() {
        bool expected_running{true};
        if (is_running.compare_exchange_strong(expected_running, false)) {
            (void)timer_.cancel();
        }
    }

    //! \brief Cancels execution of awaiting callback and, if still in running state, submits timer for a new interval
    void reset() { (void)timer_.cancel(); }

  private:
    //! \brief Launches async timer
    void launch() {
        timer_.expires_from_now(boost::posix_time::milliseconds(interval_));
        (void)timer_.async_wait([&, this](const boost::system::error_code& ec) {
            if (!ec && call_back_) {
                call_back_();
            }
            if (is_running.load()) {
                launch();
            }
        });
    }

    std::atomic_bool is_running{false};
    const uint32_t interval_;
    boost::asio::deadline_timer timer_;
    std::function<bool()> call_back_;
};

}  // namespace silkworm

#endif  // SILKWORM_COMMON_ASIO_TIMER_HPP_
