/*
   Copyright 2023 The Silkworm Authors

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

#include <functional>

#include <silkworm/infra/concurrency/coroutine.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/signal_set.hpp>

namespace silkworm::cmd::common {

class ShutdownSignal {
  public:
    explicit ShutdownSignal(boost::asio::io_context& io_context)
        : signals_(io_context, SIGINT, SIGTERM) {}

    using SignalNumber = int;

    void on_signal(std::function<void(SignalNumber)> callback);

    boost::asio::awaitable<SignalNumber> wait();

  private:
    boost::asio::signal_set signals_;
};

}  // namespace silkworm::cmd::common
