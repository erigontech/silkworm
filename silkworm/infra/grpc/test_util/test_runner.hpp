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

#include <memory>

#include <agrpc/asio_grpc.hpp>
#include <boost/asio/executor_work_guard.hpp>

#include "../../test_util/task_runner.hpp"

namespace silkworm::grpc::test_util {

using namespace silkworm::test_util;

/**
 * A helper to run gRPC calls on boost::asio::io_context + agrpc::GrpcContext in tests
 */
template <typename GrpcApiClient, typename Stub>
class TestRunner : public TaskRunner {
  public:
    TestRunner() : grpc_context_work_{boost::asio::make_work_guard(grpc_context_.get_executor())} {}

    template <auto method, typename... Args>
    auto run_service_method(Args&&... args) {
        GrpcApiClient api = make_api_client();
        auto service = api.service();
        return run((service.get()->*method)(std::forward<Args>(args)...));
    }

  protected:
    agrpc::GrpcContext grpc_context_;
    boost::asio::executor_work_guard<agrpc::GrpcContext::executor_type> grpc_context_work_;
    std::unique_ptr<Stub> stub_{std::make_unique<Stub>()};

    void restart_ioc() override {
        TaskRunner::restart_ioc();
        grpc_context_.reset();
    }

    void poll_ioc_once() override {
        TaskRunner::poll_ioc_once();
        grpc_context_.poll_completion_queue();
    }

    virtual GrpcApiClient make_api_client() = 0;
};

}  // namespace silkworm::grpc::test_util
