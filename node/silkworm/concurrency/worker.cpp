/*
   Copyright 2020 - 2021 The Silkworm Authors

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

#include "worker.hpp"

#include <memory>

#include <silkworm/common/log.hpp>

namespace silkworm {

Worker::~Worker() { stop(/*wait=*/true); }

void Worker::start(bool wait) {
    State expected_stopped{State::kStopped};
    if (!state_.compare_exchange_strong(expected_stopped, State::kStarting)) {
        return;
    }

    exception_ptr_ = nullptr;
    kicked_.store(false);

    thread_ = std::make_unique<std::thread>([&]() {
        State expected_starting{State::kStarting};
        if (state_.compare_exchange_strong(expected_starting, State::kStarted)) {
            signal_started(this);
            try {
                work();
            } catch (const std::exception& ex) {
                log::Error() << "Exception thrown in " << name_ << " thread : " << ex.what();
                exception_ptr_ = std::current_exception();
            }
        }
        state_.store(State::kStopped);
        signal_stopped(this);
    });

    while (wait) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        if (auto state{get_state()}; state == State::kStarted) {
            break;
        }
    }
}

void Worker::stop(bool wait) {
    if (!thread_) return;

    State expected_state{State::kStarted};
    if (state_.compare_exchange_strong(expected_state, State::kStopping)) {
        kick();
    }

    if (wait) {
        thread_->join();
        thread_.reset();
    }
}

void Worker::kick() {
    kicked_.store(true);
    kicked_cv_.notify_all();
}

bool Worker::wait_for_kick(uint32_t timeout_milliseconds) {
    while (!SignalHandler::signalled()) {
        bool expected_kick_value{true};
        if (!kicked_.compare_exchange_strong(expected_kick_value, false)) {
            std::unique_lock l(kick_mtx_);
            (void)kicked_cv_.wait_for(l, std::chrono::milliseconds(timeout_milliseconds));
            continue;
        }
        break;
    }
    return !is_stopping();
}

std::string Worker::what() {
    std::string ret{};
    if (has_exception()) {
        try {
            std::rethrow_exception(exception_ptr_);
        } catch (const std::exception& ex) {
            ret = ex.what();
        } catch (const std::string& ex) {
            ret = ex;
        } catch (const char* ex) {
            ret = ex;
        } catch (...) {
            ret = "Undefined error";
        }
    }
    return ret;
}

void Worker::rethrow() {
    if (has_exception()) {
        std::rethrow_exception(exception_ptr_);
    }
}

}  //  namespace silkworm
