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

#ifndef SILKWORM_CONCURRENCY_WORKER_HPP_
#define SILKWORM_CONCURRENCY_WORKER_HPP_

#include <atomic>
#include <condition_variable>
#include <iostream>
#include <thread>

#include <boost/signals2/signal.hpp>

#include <silkworm/concurrency/signal_handler.hpp>

namespace silkworm {

// If you only need stoppability, use ActiveComponent instead.
class Worker {
  public:
    enum class State { kStopped, kStarting, kStarted, kKickWaiting, kStopping };

    Worker() : name_{"worker"} {}
    explicit Worker(std::string& name) : name_{name} {}
    explicit Worker(std::string&& name) : name_{std::move(name)} {}

    /* Not movable nor copyable */
    Worker(Worker const&) = delete;
    Worker& operator=(Worker const&) = delete;

    virtual ~Worker();

    void start(bool wait = true);          // Start worker thread (by default waits for status)
    virtual void stop(bool wait = false);  // Stops worker thread (optionally wait for complete stop)
    void kick();                           // Kicks worker thread if waiting

    //! \brief Whether this worker/thread has received a stop request
    bool is_stopping() const { return state_.load() == State::kStopping; }

    //! \brief Retrieves current state of thread
    State get_state() { return state_.load(); }

    //! \brief Whether this worker/thread has encountered an exception
    bool has_exception() const { return exception_ptr_ != nullptr; }

    //! \brief Returns the message of captured exception (if any)
    std::string what();

    //! \brief Rethrows captured exception (if any)
    void rethrow();

    //! \brief Signals connected handlers the underlying thread is about to start
    boost::signals2::signal<void(Worker* sender)> signal_worker_started;

    //! \brief Signals connected handlers the underlying thread is terminated
    boost::signals2::signal<void(Worker* sender)> signal_worker_stopped;

  protected:
    /**
     * @brief Puts the underlying thread in non-busy wait for a kick
     * to waken up and do work.
     * Returns True if the kick has been received and should go ahead
     * otherwise False (i.e. the thread has been asked to stop)
     *
     * @param [in] timeout: Timeout for conditional variable wait (milliseconds). Defaults to 100 ms
     */
    bool wait_for_kick(uint32_t timeout_milliseconds = 100);  // Puts a thread in non-busy wait for data to process
    std::atomic_bool kicked_{false};                          // Whether the kick has been received
    std::condition_variable kicked_cv_{};                     // Condition variable to wait for kick
    std::mutex kick_mtx_{};                                   // Mutex for conditional wait of kick
    std::string name_;

  private:
    std::atomic<State> state_{State::kStopped};
    std::unique_ptr<std::thread> thread_{nullptr};
    std::exception_ptr exception_ptr_{nullptr};
    virtual void work() = 0;  // Derived classes must override
};

}  // namespace silkworm

#endif  // SILKWORM_CONCURRENCY_WORKER_HPP_
