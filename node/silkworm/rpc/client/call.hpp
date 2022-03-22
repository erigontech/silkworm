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

#ifndef SILKWORM_RPC_CLIENT_CALL_HPP_
#define SILKWORM_RPC_CLIENT_CALL_HPP_

#include <chrono>
#include <functional>

#include <grpcpp/grpcpp.h>
#include <grpcpp/impl/codegen/async_unary_call.h>
#include <grpcpp/impl/codegen/client_callback.h>
#include <grpcpp/impl/codegen/client_context.h>
#include <grpcpp/impl/codegen/completion_queue.h>
#include <grpcpp/impl/codegen/stub_options.h>
#include <magic_enum.hpp>

#include <silkworm/common/log.hpp>
#include <silkworm/rpc/completion_tag.hpp>

namespace silkworm::rpc {

struct UnaryStats {
    uint64_t started_count{0};
    uint64_t completed_count{0};
    uint64_t ok_count{0};
    uint64_t ko_count{0};
};

inline std::ostream& operator<<(std::ostream& out, const UnaryStats& stats) {
    out << "started=" << stats.started_count << " completed=" << stats.completed_count
        << " [OK=" << stats.ok_count << " KO=" << stats.ko_count << "]";
    return out;
}

class AsyncCall {
  public:
    static UnaryStats stats() { return unary_stats_; }

    explicit AsyncCall(grpc::CompletionQueue* queue) : queue_(queue) {}
    virtual ~AsyncCall() = default;

    virtual bool proceed(bool ok) = 0;

    void cancel() { client_context_.TryCancel(); }

    std::string peer() const { return client_context_.peer(); }

    std::chrono::steady_clock::time_point start_time() const { return start_time_; }

    grpc::Status status() const { return status_; }

  protected:
    static UnaryStats unary_stats_;

    grpc::ClientContext client_context_;
    grpc::CompletionQueue* queue_;
    std::chrono::steady_clock::time_point start_time_;
    grpc::Status status_;
};

template <typename Reply>
using AsyncResponseReaderPtr = std::unique_ptr<grpc::ClientAsyncResponseReaderInterface<Reply>>;

template<
    typename Request,
    typename Reply,
    typename StubInterface,
    typename Stub,
    AsyncResponseReaderPtr<Reply>(StubInterface::*PrepareAsyncUnary)(grpc::ClientContext*, const Request&, grpc::CompletionQueue*)
>
class AsyncUnaryCall : public AsyncCall {
  public:
    using CompletionFunc = std::function<void(AsyncUnaryCall<Request, Reply, StubInterface, Stub, PrepareAsyncUnary>*)>;

    explicit AsyncUnaryCall(grpc::CompletionQueue* queue, CompletionFunc completion_handler, std::unique_ptr<Stub>& stub)
    : AsyncCall(queue), stub_(stub), completion_handler_(completion_handler) {
        process_proceed_ = [this](bool ok) {
            proceed(ok); // no need to check return value, unary calls always complete in one step
            completion_handler_(this);
        };
    }

    void start(const Request& request) {
        SILK_TRACE << "AsyncUnaryCall::start_async START";
        auto response_reader = (stub_.get()->*PrepareAsyncUnary)(&client_context_, request, queue_);
        response_reader->StartCall();
        response_reader->Finish(&reply_, &status_, &process_proceed_);
        start_time_ = std::chrono::steady_clock::now();
        ++unary_stats_.started_count;
        SILK_TRACE << "AsyncUnaryCall::start_async END";
    }

    Reply reply() const { return reply_; }

  protected:
    std::unique_ptr<Stub>& stub_;
    Reply reply_;
    TagProcessor process_proceed_;
    CompletionFunc completion_handler_;
};

} // namespace silkworm::rpc

#endif // SILKWORM_RPC_CLIENT_CALL_HPP_
