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

#include <chrono>
#include <utility>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_future.hpp>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/spawn.hpp>
#include <silkworm/infra/grpc/client/client_context_pool.hpp>
#include <silkworm/infra/test_util/log.hpp>

namespace silkworm::test_util {

class ContextTestBase {
  public:
    ContextTestBase();

    template <typename AwaitableOrFunction>
    auto spawn(AwaitableOrFunction&& awaitable) {
        return concurrency::spawn_future(ioc_, std::forward<AwaitableOrFunction>(awaitable));
    }

    template <typename AwaitableOrFunction>
    auto spawn_and_wait(AwaitableOrFunction&& awaitable) {
        return spawn(std::forward<AwaitableOrFunction>(awaitable)).get();
    }

    static void sleep_for(std::chrono::milliseconds sleep_time_ms) {
        std::this_thread::sleep_for(sleep_time_ms);
    }

    ~ContextTestBase();

    agrpc::GrpcContext& grpc_context() { return grpc_context_; }

  protected:
    rpc::ClientContext context_;
    boost::asio::io_context& ioc_;
    agrpc::GrpcContext& grpc_context_;
    std::thread context_thread_;
};

}  // namespace silkworm::test_util
