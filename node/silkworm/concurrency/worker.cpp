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

Worker::~Worker() {
    if (state_.load() != WorkerState::kStopped) {
        state_.store(WorkerState::kStopping);
        thread_->join();
        thread_.reset(nullptr);
    }
}

void Worker::start(bool wait) {
    WorkerState expected_stopped{WorkerState::kStopped};
    if (!state_.compare_exchange_strong(expected_stopped, WorkerState::kStarting)) {
        WorkerState expected_exception_thrown{WorkerState::kExceptionThrown};
        if (!state_.compare_exchange_strong(expected_exception_thrown, WorkerState::kStarting)){
            return;
        }
    }

    exception_ptr_ = nullptr;
    kicked_.store(false);

    thread_ = std::make_unique<std::thread>([&]() {
        WorkerState expected_starting{WorkerState::kStarting};
        if (state_.compare_exchange_strong(expected_starting, WorkerState::kStarted)) {
            try {
                work();
                state_.store(WorkerState::kStopped);
            } catch (const std::exception& ex) {
                log::Error() << "Exception thrown in worker thread : " << ex.what();
                exception_ptr_ = std::current_exception();
                state_.store(WorkerState::kExceptionThrown);
            }
        }
    });

    while (wait) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        auto state{get_state()};
        if (state == WorkerState::kStarted) {
            break;
        }
    }
}

void Worker::stop(bool wait) {
    WorkerState expected_state{WorkerState::kStarted};
    if (state_.compare_exchange_strong(expected_state, WorkerState::kStopping)) {
        kick();
    }
    if (wait) {
        thread_->join();
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

}  //  namespace silkworm
