// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "timer.hpp"

namespace silkworm {

//! \brief Implementation of an asynchronous periodic timer relying on boost:asio timer facility
//! \warning At least one TimerImpl shared pointer must exist when using it (precondition of shared_from_this())
//! \warning This is achieved by static TimerImpl::create and non-public constructor, subclasses must obey the same rule
class TimerImpl : public std::enable_shared_from_this<TimerImpl> {
  public:
    //! Factory method enforcing instances are managed *only* through shared pointers
    //! \param executor [in] : executor running the timer
    //! \param interval [in] : length of wait interval (in milliseconds)
    //! \param callback [in] : the call back function to be called
    //! \param auto_start [in] : whether to start the timer immediately
    static std::shared_ptr<TimerImpl> create(const boost::asio::any_io_executor& executor,
                                             uint32_t interval,
                                             std::function<bool()> callback,
                                             bool auto_start = true) {
        auto timer = std::shared_ptr<TimerImpl>(new TimerImpl{executor, interval, std::move(callback)});
        if (auto_start) timer->start();
        return timer;
    }

    ~TimerImpl() { stop(); }

    //! \brief Start timer asynchronously. Eventually callback action is executed and timer automatically rescheduled
    //! for another interval
    void start() {
        bool expected_running{false};
        if (is_running_.compare_exchange_strong(expected_running, true)) {
            launch();
        }
    }

    //! \brief Stop timer and cancel any pending execution. Callback may still be executed *once* if timer gets cancelled
    //! after expiration but before completion handler dispatching.
    void stop() {
        bool expected_running{true};
        if (is_running_.compare_exchange_strong(expected_running, false)) {
            (void)timer_.cancel();
        }
    }

    //! \brief Cancel next execution of awaiting callback and reschedule for a new interval if still running
    void reset() {
        (void)timer_.cancel();
        if (is_running_) {
            launch();
        }
    }

  protected:
    //! \brief Not public to force creation only through TimerImpl::create
    //! \param executor [in] : executor running the timer
    //! \param interval [in] : length of wait interval (in milliseconds)
    //! \param call_back [in] : the call back function to be called
    TimerImpl(const boost::asio::any_io_executor& executor, uint32_t interval, std::function<bool()> call_back)
        : interval_(interval), timer_(executor), callback_(std::move(call_back)) {
        SILKWORM_ASSERT(interval > 0);
    };

  private:
    //! \brief Launches async timer
    void launch() {
        timer_.expires_after(std::chrono::milliseconds(interval_));

        // Start the timer and capture it as shared pointer to extend its lifetime to the completion handler invocation
        (void)timer_.async_wait([self = shared_from_this()](const boost::system::error_code& ec) {
            if (ec == boost::asio::error::operation_aborted) {  // If timer gets cancelled before expiration
                return;
            }
            // If timer gets cancelled after expiration but before completion handler dispatching, we may arrive here
            if (!ec && self->callback_) {
                self->callback_();
            }
            if (self->is_running_) {
                self->launch();
            }
        });
    }

    std::atomic_bool is_running_{false};
    const uint32_t interval_;
    boost::asio::steady_timer timer_;
    std::function<bool()> callback_;
};

Timer::Timer(const boost::asio::any_io_executor& executor,
             uint32_t interval,
             std::function<bool()> callback,
             bool auto_start)
    : p_impl_{TimerImpl::create(executor, interval, std::move(callback), auto_start)} {}

Timer::~Timer() {
    p_impl_->stop();
}

void Timer::start() {
    p_impl_->start();
}

void Timer::stop() {
    p_impl_->stop();
}

void Timer::reset() {
    p_impl_->reset();
}

}  // namespace silkworm
