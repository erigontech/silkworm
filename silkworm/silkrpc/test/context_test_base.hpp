/*
   Copyright 2020 The Silkrpc Authors

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

#include <chrono>
#include <memory>
#include <utility>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_future.hpp>

#include <silkworm/silkrpc/config.hpp>
#include <silkworm/silkrpc/concurrency/context_pool.hpp>

namespace silkrpc::test {

class ContextTestBase {
  public:
    ContextTestBase();

    template <typename AwaitableOrFunction>
    auto spawn(AwaitableOrFunction&& awaitable) {
        return boost::asio::co_spawn(io_context_, std::forward<AwaitableOrFunction>(awaitable), boost::asio::use_future);
    }

    template <typename AwaitableOrFunction>
    auto spawn_and_wait(AwaitableOrFunction&& awaitable) {
        return spawn(std::forward<AwaitableOrFunction>(awaitable)).get();
    }

    static void sleep_for(std::chrono::milliseconds sleep_time_ms) {
        std::this_thread::sleep_for(sleep_time_ms);
    }

    ~ContextTestBase();

  private:
    bool init_dummy;

  public:
    Context context_;
    boost::asio::io_context& io_context_;
    agrpc::GrpcContext& grpc_context_;
    std::thread context_thread_;
};

}  // namespace silkrpc::test

