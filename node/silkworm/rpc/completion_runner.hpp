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

#include <grpcpp/grpcpp.h>

namespace silkworm::rpc {

//! Execution loop dedicated to read completion notifications from one gRPC completion queue.
class CompletionRunner {
  public:
    CompletionRunner(grpc::CompletionQueue& queue) : queue_(queue) {}

    CompletionRunner(const CompletionRunner&) = delete;
    CompletionRunner& operator=(const CompletionRunner&) = delete;

    //! Run at most one execution cycle polling gRPC completion queue for one event.
    int poll_one();

    //! Shutdown and drain the gRPC completion queue.
    void shutdown();

  private:
    //! The gRPC completion queue to read async completion notifications from.
    grpc::CompletionQueue& queue_;
};

} // namespace silkworm::rpc

#endif  // SILKWORM_RPC_COMPLETION_RUNNER_HPP_
