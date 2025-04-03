// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
