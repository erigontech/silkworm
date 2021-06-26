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

#ifndef SILKWORM_WORKER_HPP_
#define SILKWORM_WORKER_HPP_

#include <atomic>
#include <condition_variable>
#include <iostream>
#include <thread>

namespace silkworm {

class Worker {
  public:
    enum class WorkerState { kStopped, kStarting, kStarted, kStopping };

    Worker() = default;

    /* Not moveable / copyable */
    Worker(Worker const&) = delete;
    Worker& operator=(Worker const&) = delete;

    virtual ~Worker();

    void start(bool wait = true);  // Start worker thread (by default waits for status)
    void stop(bool wait = false);  // Stops worker thread (optionally wait for complete stop)
    void kick();                   // Kicks worker thread if waiting

    // Whether or not this worker/thread should stop
    bool should_stop() { return state_.load() == WorkerState::kStopping; }

    // Retrieves current state of thread
    WorkerState get_state() { return state_.load(); }

  protected:
    /**
     * @brief Puts the underlying thread in non-busy wait for a kick
     * to waken up and do work.
     * Returns True if the kick has been received and should go ahead
     * otherwise False (i.e. the thread has been asked to stop)
     *
     * @param timeout: Timeout for conditional variable wait (seconds)
     */
    bool wait_for_kick(uint32_t timeout_seconds = 1);  // Puts a thread in non-busy wait for data to process
    std::atomic_bool kicked_{false};                   // Whether or not the kick has been received
    std::condition_variable kicked_cv_{};              // Condition variable to wait for kick
    std::mutex kick_mtx_{};                            // Mutex for conditional wait of kick

  private:
    std::atomic<WorkerState> state_{WorkerState::kStopped};
    std::unique_ptr<std::thread> thread_{nullptr};
    virtual void work() = 0;  // Derived classes must override
};
}  // namespace silkworm

#endif  // SILKWORM_WORKER_HPP_
