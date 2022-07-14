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

#include "cancellation_signal.hpp"
#include <chrono>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/detail/errc.hpp>
#include <boost/system/system_error.hpp>

namespace silkworm::concurrency {

CancellationSignal::CancellationSignal(boost::asio::io_context& context) : timer_(context) {
    timer_.expires_at(std::chrono::system_clock::time_point::max());
}

boost::asio::awaitable<void> CancellationSignal::await() {
    try {
        co_await timer_.async_wait(boost::asio::use_awaitable);
    } catch (const boost::system::system_error &e) {
        if (e.code() != boost::system::errc::operation_canceled)
            throw;
    }
}

void CancellationSignal::emit() {
    timer_.cancel();
}

}  // namespace silkworm::concurrency
