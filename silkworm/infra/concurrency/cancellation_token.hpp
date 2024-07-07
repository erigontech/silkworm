/*
   Copyright 2024 The Silkworm Authors

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

#include <condition_variable>
#include <mutex>

#include <boost/asio/cancellation_signal.hpp>

namespace silkworm {

class CancellationToken {
  public:
    [[nodiscard]] bool is_cancelled() const { return cancelled_; }

    template <typename CancellationHandler>
    bool assign(CancellationHandler&& handler) {
        std::unique_lock lock{cancellation_mutex_};
        if (cancelled_) {
            return true;
        }
        cancellation_signal_.slot().assign(std::forward<CancellationHandler>(handler));
        lock.unlock();
        cancellation_available_.notify_all();
        return false;
    }

    bool clear() {
        std::unique_lock lock{cancellation_mutex_};
        if (cancelled_) {
            return false;
        }
        cancellation_signal_.slot().clear();
        return true;
    }

    void signal_cancellation() {
        std::unique_lock lock{cancellation_mutex_};
        cancellation_available_.wait(lock, [&] { return cancellation_signal_.slot().has_handler(); });
        cancellation_signal_.emit(boost::asio::cancellation_type::all);
        cancelled_ = true;
    }

  private:
    //! The mutual exclusion access to the cancellation signal
    std::mutex cancellation_mutex_;

    //! The signal used to cancel the register-and-receive stream loop
    boost::asio::cancellation_signal cancellation_signal_;

    //! The condition variable signaling that cancellation is possible
    std::condition_variable cancellation_available_;

    //! Flag indicating that the stream has been cancelled
    bool cancelled_{false};
};

}  // namespace silkworm
