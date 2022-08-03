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

#pragma once

#include <chrono>
#include <functional>

#include <grpcpp/grpcpp.h>
#include <grpcpp/impl/codegen/async_unary_call.h>
#include <grpcpp/impl/codegen/async_stream.h>
#include <grpcpp/impl/codegen/client_callback.h>
#include <grpcpp/impl/codegen/client_context.h>
#include <grpcpp/impl/codegen/completion_queue.h>
#include <grpcpp/impl/codegen/stub_options.h>
#include <magic_enum.hpp>

#include <silkworm/common/assert.hpp>
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
    explicit AsyncCall(grpc::CompletionQueue* queue) : queue_(queue) {}
    virtual ~AsyncCall() = default;

    void cancel() { client_context_.TryCancel(); }

    std::string peer() const { return client_context_.peer(); }

    std::chrono::steady_clock::time_point start_time() const { return start_time_; }
    std::chrono::steady_clock::time_point end_time() const { return end_time_; }
    std::chrono::steady_clock::duration latency() const { return end_time_ - start_time_; }

    grpc::Status status() const { return status_; }

  protected:
    grpc::ClientContext client_context_;
    grpc::CompletionQueue* queue_;
    std::chrono::steady_clock::time_point start_time_;
    std::chrono::steady_clock::time_point end_time_;
    grpc::Status status_;
};

template <typename Reply>
using AsyncResponseReaderPtr = std::unique_ptr<grpc::ClientAsyncResponseReaderInterface<Reply>>;

template<
    typename Request,
    typename Reply,
    typename StubInterface,
    AsyncResponseReaderPtr<Reply>(StubInterface::*PrepareAsyncUnary)(grpc::ClientContext*, const Request&, grpc::CompletionQueue*)
>
class AsyncUnaryCall : public AsyncCall {
  public:
    using CompletionFunc = std::function<void(AsyncUnaryCall<Request, Reply, StubInterface, PrepareAsyncUnary>*)>;

    static UnaryStats stats() { return unary_stats_; }

    explicit AsyncUnaryCall(grpc::CompletionQueue* queue, StubInterface* stub, CompletionFunc completion_handler = {})
    : AsyncCall(queue), stub_(stub), completion_handler_(completion_handler) {
        finish_processor_ = [&](bool ok) { process_finish(ok); };
    }

    void start(const Request& request) {
        SILK_TRACE << "AsyncUnaryCall::start START";
        auto response_reader = (stub_->*PrepareAsyncUnary)(&client_context_, request, queue_);
        response_reader->StartCall();
        response_reader->Finish(&reply_, &status_, &finish_processor_);
        start_time_ = std::chrono::steady_clock::now();
        ++unary_stats_.started_count;
        SILK_TRACE << "AsyncUnaryCall::start END";
    }

    Reply reply() const { return reply_; }

  protected:
    void process_finish(bool ok) {
        end_time_ = std::chrono::steady_clock::now();
        ++unary_stats_.completed_count;
        if (ok && status_.ok()) {
            ++unary_stats_.ok_count;
        } else {
            ++unary_stats_.ko_count;
        }
        handle_finish(ok);
        if (completion_handler_) {
            completion_handler_(this);
        }
    }

    virtual void handle_finish(bool /*ok*/) {}

    inline static UnaryStats unary_stats_;

    StubInterface* stub_;
    Reply reply_;
    TagProcessor finish_processor_;
    CompletionFunc completion_handler_;
};

struct ServerStreamingStats {
    uint64_t started_count{0};
    uint64_t received_count{0};
    uint64_t completed_count{0};
    uint64_t cancelled_count{0};
    uint64_t ok_count{0};
    uint64_t ko_count{0};
};

inline std::ostream& operator<<(std::ostream& out, const ServerStreamingStats& stats) {
    out << "started=" << stats.started_count << " received=" << stats.received_count
        << " completed=" << stats.completed_count << " cancelled=" << stats.cancelled_count
        << " [OK=" << stats.ok_count << " KO=" << stats.ko_count << "]";
    return out;
}

template <typename Reply>
using AsyncReaderPtr = std::unique_ptr<grpc::ClientAsyncReaderInterface<Reply>>;

template <
    typename Request,
    typename Reply,
    typename StubInterface,
    AsyncReaderPtr<Reply>(StubInterface::*PrepareAsyncServerStreaming)(grpc::ClientContext*, const Request&, grpc::CompletionQueue*)
>
class AsyncServerStreamingCall : public AsyncCall {
  public:
      static ServerStreamingStats stats() { return server_streaming_stats_; }

    explicit AsyncServerStreamingCall(grpc::CompletionQueue* queue, StubInterface* stub)
        : AsyncCall(queue), stub_(stub) {
        start_processor_ = [&](bool ok) { process_start(ok); };
        read_processor_ = [&](bool ok) { process_read(ok); };
        finish_processor_ = [&](bool ok) { process_finish(ok); };
    }

    void start(const Request& request) {
        SILK_TRACE << "AsyncServerStreamingCall::start START";
        reader_ = (stub_->*PrepareAsyncServerStreaming)(&client_context_, request, queue_);
        reader_->StartCall(&start_processor_);
        start_time_ = std::chrono::steady_clock::now();
        ++server_streaming_stats_.started_count;
        SILK_TRACE << "AsyncServerStreamingCall::start END";
    }

    void cancel() {
        SILK_TRACE << "AsyncServerStreamingCall::cancel START";
        client_context_.TryCancel();
        ++server_streaming_stats_.cancelled_count;
        SILK_TRACE << "AsyncServerStreamingCall::cancel END";
    }

  protected:
    virtual void read() {
        SILK_TRACE << "AsyncServerStreamingCall::read START";
        reader_->Read(&reply_, &read_processor_);
        SILK_TRACE << "AsyncServerStreamingCall::read END";
    }

    virtual void finish() {
        SILK_TRACE << "AsyncServerStreamingCall::finish START";
        reader_->Finish(&status_, &finish_processor_);
        SILK_TRACE << "AsyncServerStreamingCall::finish END";
    }

    void process_start(bool ok) {
        SILK_DEBUG << "AsyncServerStreamingCall::process_start ok: " << ok;
        if (ok) {
            started_ = true;
            SILK_DEBUG << "AsyncServerStreamingCall call started";
            // Schedule next async READ event.
            read();
            SILK_DEBUG << "AsyncServerStreamingCall read scheduled";
        } else {
            SILK_DEBUG << "AsyncServerStreamingCall interrupted started: " << started_;
            done_ = true;
            finish();
        }
    }

    void process_read(bool ok) {
        SILK_DEBUG << "AsyncServerStreamingCall::process_read ok: " << ok;
        if (ok) {
            handle_read();
            ++server_streaming_stats_.received_count;
            SILK_DEBUG << "AsyncServerStreamingCall new message received: " << server_streaming_stats_.received_count;
            // Schedule next async READ event.
            read();
            SILK_DEBUG << "AsyncServerStreamingCall read scheduled";
        } else {
            SILK_DEBUG << "AsyncServerStreamingCall interrupted started: " << started_;
            done_ = true;
            finish();
        }
    }

    void process_finish(bool ok) {
        SILK_DEBUG << "AsyncServerStreamingCall::process_finish ok: " << ok;
        if (ok) {
            end_time_ = std::chrono::steady_clock::now();
            ++server_streaming_stats_.completed_count;
            if (status_.ok()) {
                ++server_streaming_stats_.ok_count;
            } else {
                ++server_streaming_stats_.ko_count;
            }
        } else {
            SILK_DEBUG << "AsyncServerStreamingCall finished done: " << done_;
            SILKWORM_ASSERT(done_);
        }
        handle_finish();
    }

    virtual void handle_read() = 0;
    virtual void handle_finish() = 0;

    inline static ServerStreamingStats server_streaming_stats_;

    TagProcessor start_processor_;
    TagProcessor read_processor_;
    TagProcessor finish_processor_;

    StubInterface* stub_;
    AsyncReaderPtr<Reply> reader_;
    grpc::Status status_;
    Reply reply_;
    bool started_{false};
    bool done_{false};
};

} // namespace silkworm::rpc
