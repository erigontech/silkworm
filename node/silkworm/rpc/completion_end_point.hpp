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

#ifndef SILKWORM_RPC_COMPLETION_END_POINT_HPP_
#define SILKWORM_RPC_COMPLETION_END_POINT_HPP_

#include <cstddef>

#include <boost/asio/io_context.hpp>
#include <grpcpp/grpcpp.h>

namespace silkworm::rpc {

//! Application end-point dedicated to read completion notifications from one gRPC completion queue.
class CompletionEndPoint {
  public:
    CompletionEndPoint(grpc::CompletionQueue& queue) : queue_(queue) {}

    CompletionEndPoint(const CompletionEndPoint&) = delete;
    CompletionEndPoint& operator=(const CompletionEndPoint&) = delete;

    //! Check if the end-point has been shut down or not.
    bool closed() const { return closed_; }

    //! Run at most one execution cycle polling gRPC completion queue for one event.
    std::size_t poll_one();

    //! Post to scheduler at most one execution task polling gRPC completion queue for one event.
    bool post_one(boost::asio::io_context& scheduler);

    //! Shutdown and drain the gRPC completion queue.
    void shutdown();

  protected:
    //! Flag indicating if the end-point has been shut down or not.
    bool closed_{false};

  private:
    //! The gRPC completion queue to read async completion notifications from.
    grpc::CompletionQueue& queue_;
};

} // namespace silkworm::rpc

#endif  // SILKWORM_RPC_COMPLETION_END_POINT_HPP_
