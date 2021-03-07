/*
   Copyright 2020 The Silkworm Authors

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

namespace silkworm {
Worker::~Worker() {
    if (state_.load() != WorkerState::kStopped) {
        state_.store(WorkerState::kStopping);
        thread_->join();
        thread_.reset(nullptr);
    }
}
void Worker::start(bool wait) {
    WorkerState expected_state{WorkerState::kStopped};
    if (!state_.compare_exchange_strong(expected_state, WorkerState::kStarting)) {
        return;
    }

    thread_.reset(new std::thread([&]() {
        WorkerState expected_state{WorkerState::kStarting};
        if (state_.compare_exchange_strong(expected_state, WorkerState::kStarted)) {
            try {
                work();
            } catch (const std::exception& ex) {
                std::cerr << "Exception thrown in worker thread : " << ex.what() << std::endl;
            }
        }
        state_.store(WorkerState::kStopped);
    }));

    while (wait) {
        if (state_.load(std::memory_order_relaxed) != WorkerState::kStarting) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
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
    kicked_.store(true, std::memory_order_relaxed);
    kicked_cv_.notify_one();
}
}  //  namespace silkworm
