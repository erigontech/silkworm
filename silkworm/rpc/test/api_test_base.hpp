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

#include <memory>
#include <utility>

#include <boost/asio/thread_pool.hpp>

#include <silkworm/rpc/test/context_test_base.hpp>

namespace silkworm::rpc::test {

template <typename JsonApi>
class JsonApiTestBase : public ContextTestBase {
  public:
    template <auto method, typename... Args>
    auto run(Args&&... args) {
        JsonApi api{io_context_};
        return spawn_and_wait((api.*method)(std::forward<Args>(args)...));
    }
};

template <typename JsonApi>
class JsonApiWithWorkersTestBase : public ContextTestBase {
  public:
    explicit JsonApiWithWorkersTestBase() : ContextTestBase(), workers_{1} {}

    template <auto method, typename... Args>
    auto run(Args&&... args) {
        JsonApi api{io_context_, workers_};
        return spawn_and_wait((api.*method)(std::forward<Args>(args)...));
    }

    boost::asio::thread_pool workers_;
};

template <typename GrpcApi, typename Stub>
class GrpcApiTestBase : public ContextTestBase {
  public:
    template <auto method, typename... Args>
    auto run(Args&&... args) {
        GrpcApi api{io_context_.get_executor(), std::move(stub_), grpc_context_};
        return spawn_and_wait((api.*method)(std::forward<Args>(args)...));
    }

    std::unique_ptr<Stub> stub_{std::make_unique<Stub>()};
};

}  // namespace silkworm::rpc::test
