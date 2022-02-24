/*
   Copyright 2020-2022 The Silkworm Authors

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
        log::set_thread_name(name_.c_str());
        State expected_starting{State::kStarting};
        if (state_.compare_exchange_strong(expected_starting, State::kStarted)) {
            signal_worker_started(this);
            try {
                work();
            } catch (const std::exception& ex) {
                log::Error(name_, {"exception", std::string(ex.what())});
                exception_ptr_ = std::current_exception();
            }
        }
        state_.store(State::kStopped);
        signal_worker_stopped(this);
    });

    while (wait) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        if (auto state{get_state()}; state == State::kStarted || state == State::kKickWaiting) {
            break;
        }
    }
}

void Worker::stop(bool wait) {
    if (!thread_) return;

    state_.store(State::kStopping);
    kick();

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
    bool expected_kicked_value{true};
    while (!kicked_.compare_exchange_strong(expected_kicked_value, false)) {
        auto current_state{get_state()};
        if (current_state == Worker::State::kStarted) {
            state_.store(Worker::State::kKickWaiting);
        } else if (current_state == State::kStopping) {
            break;
        }
        if (timeout_milliseconds) {
            std::unique_lock l(kick_mtx_);
            (void)kicked_cv_.wait_for(l, std::chrono::milliseconds(timeout_milliseconds));
        } else {
            std::this_thread::yield();
        }
        expected_kicked_value = true;
    }

    if (is_stopping()) {
        return false;
    }
    state_.store(State::kStarted);
    return true;
}

std::string Worker::what() {
    std::string ret{};
    try {
        rethrow();
    } catch (const std::exception& ex) {
        ret = ex.what();
    } catch (const std::string& ex) {
        ret = ex;
    } catch (const char* ex) {
        ret = ex;
    } catch (...) {
        ret = "Undefined error";
    }
    return ret;
}

void Worker::rethrow() {
    if (has_exception()) {
        std::rethrow_exception(exception_ptr_);
    }
}

}  //  namespace silkworm
