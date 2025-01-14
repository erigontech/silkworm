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

#include <silkworm/rpc/common/worker_pool.hpp>
#include <silkworm/rpc/test_util/service_context_test_base.hpp>

namespace silkworm::rpc::test_util {

template <typename JsonApi>
class JsonApiTestBase : public ServiceContextTestBase {
  public:
    template <auto method, typename... Args>
    auto run(Args&&... args) {
        JsonApi api{ioc_};
        return spawn_and_wait((api.*method)(std::forward<Args>(args)...));
    }
};

template <typename JsonApi>
class JsonApiWithWorkersTestBase : public ServiceContextTestBase {
  public:
    explicit JsonApiWithWorkersTestBase() : ServiceContextTestBase(), workers_{1} {}

    template <auto method, typename... Args>
    auto run(Args&&... args) {
        JsonApi api{ioc_, workers_};
        return spawn_and_wait((api.*method)(std::forward<Args>(args)...));
    }

  protected:
    WorkerPool workers_;
};

template <typename GrpcApi, typename Stub>
class GrpcApiTestBase : public ServiceContextTestBase {
  public:
    template <auto method, typename... Args>
    auto run(Args&&... args) {
        GrpcApi api{std::move(stub_), grpc_context_};
        return spawn_and_wait((api.*method)(std::forward<Args>(args)...));
    }

  protected:
    std::unique_ptr<Stub> stub_{std::make_unique<Stub>()};
};

}  // namespace silkworm::rpc::test_util
