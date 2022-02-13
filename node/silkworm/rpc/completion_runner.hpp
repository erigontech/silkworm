/*
   Copyright 2022 The Silkworm Authors

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

#ifndef SILKWORM_RPC_COMPLETION_RUNNER_HPP_
#define SILKWORM_RPC_COMPLETION_RUNNER_HPP_

#include <boost/asio/io_context.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/common/log.hpp>

namespace silkworm::rpc {

class CompletionRunner {
  public:
    CompletionRunner(grpc::CompletionQueue& queue, boost::asio::io_context& io_context)
    : queue_(queue), io_context_(io_context) {}

    ~CompletionRunner() { stop(); }

    CompletionRunner(const CompletionRunner&) = delete;
    CompletionRunner& operator=(const CompletionRunner&) = delete;

    void run();

    void stop();

  private:
    grpc::CompletionQueue& queue_;
    boost::asio::io_context& io_context_;
};

} // namespace silkworm::rpc

#endif  // SILKWORM_RPC_COMPLETION_RUNNER_HPP_
