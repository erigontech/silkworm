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

#ifndef SILKWORM_WORKER_H_
#define SILKWORM_WORKER_H_

#include <atomic>
#include <condition_variable>
#include <iostream>
#include <thread>

namespace silkworm {

class Worker {
   public:
    enum class WorkerState { kStopped, kStarting, kStarted, kStopping };

    Worker() = default;

    Worker(Worker const&) = delete;
    Worker& operator=(Worker const&) = delete;

    virtual ~Worker();

    void start();                  // Start worker thread
    void stop(bool wait = false);  // Stops worker thread (optionally wait for complete stop)
    void kick();                   // Kicks worker thread if waiting

    // Whether or not this worker/thread should stop
    bool should_stop() { return state_.load() == WorkerState::kStopping; }

    // Retrieves current state of thread
    WorkerState get_state() { return state_; }

   protected:
    std::atomic<WorkerState> state_{WorkerState::kStopped};
    std::unique_ptr<std::thread> thread_{nullptr};

    std::atomic<bool> kicked_{false};
    std::condition_variable kicked_signal_{};
    mutable std::mutex xwork_;

   private:
    virtual void work() = 0;
};
}  // namespace silkworm

#endif  // SILKWORM_WORKER_H_
