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

#include <chrono>
#include <condition_variable>
#include <functional>
#include <iostream>
#include <memory>
#include <thread>
#include <utility>
#include <vector>

#include <CLI/CLI.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/process/environment.hpp>
#include <grpcpp/grpcpp.h>
#include <magic_enum.hpp>
#include <remote/ethbackend.grpc.pb.h>
#include <remote/kv.grpc.pb.h>

#include <silkworm/common/assert.hpp>
#include <silkworm/common/endian.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/common/util.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/rpc/common/completion_tag.hpp>
#include <silkworm/rpc/common/conversion.hpp>
#include <silkworm/rpc/common/util.hpp>

using namespace std::literals;

using silkworm::rpc::TagProcessor;

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

    std::string peer() const { return client_context_.peer(); }

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

template <
    typename Request,
    typename Reply,
    typename StubInterface,
    AsyncResponseReaderPtr<Reply> (StubInterface::*PrepareAsyncUnary)(grpc::ClientContext*, const Request&, grpc::CompletionQueue*)>
class AsyncUnaryCall : public AsyncCall {
  public:
    using CompletionFunc = std::function<void(AsyncUnaryCall<Request, Reply, StubInterface, PrepareAsyncUnary>*)>;

    static UnaryStats stats() { return unary_stats_; }

    explicit AsyncUnaryCall(grpc::CompletionQueue* queue, StubInterface* stub, CompletionFunc completion_handler = {})
        : AsyncCall(queue), stub_(stub), completion_handler_(std::move(completion_handler)) {
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
    AsyncReaderPtr<Reply> (StubInterface::*PrepareAsyncServerStreaming)(grpc::ClientContext*, const Request&, grpc::CompletionQueue*)>
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

struct BidirectionalStreamingStats {
    uint64_t started_count{0};
    uint64_t received_count{0};
    uint64_t sent_count{0};
    uint64_t completed_count{0};
    uint64_t ok_count{0};
    uint64_t ko_count{0};
};

std::ostream& operator<<(std::ostream& out, const BidirectionalStreamingStats& stats) {
    out << "started=" << stats.started_count << " sent=" << stats.sent_count << " received=" << stats.received_count
        << " completed=" << stats.completed_count << " [OK=" << stats.ok_count << " KO=" << stats.ko_count << "]";
    return out;
}

template <typename Request, typename Reply>
using AsyncReaderWriterPtr = std::unique_ptr<grpc::ClientAsyncReaderWriterInterface<Request, Reply>>;

template <typename Request, typename Reply, typename StubInterface,
          AsyncReaderWriterPtr<Request, Reply> (StubInterface::*PrepareAsyncBidirectionalStreaming)(
              grpc::ClientContext*, grpc::CompletionQueue*)>
class AsyncBidirectionalStreamingCall : public AsyncCall {
  public:
    static BidirectionalStreamingStats stats() { return bidi_streaming_stats_; }

    explicit AsyncBidirectionalStreamingCall(grpc::CompletionQueue* queue, StubInterface* stub)
        : AsyncCall(queue), stub_(stub) {
        start_processor_ = [&](bool ok) { process_start(ok); };
        read_processor_ = [&](bool ok) { process_read(ok); };
        write_processor_ = [&](bool ok) { process_write(ok); };
        writes_done_processor_ = [&](bool ok) { process_writes_done(ok); };
        finish_processor_ = [&](bool ok) { process_finish(ok); };
    }

    void start() {
        SILK_TRACE << "AsyncBidirectionalStreamingCall::start START";
        stream_ = (stub_->*PrepareAsyncBidirectionalStreaming)(&client_context_, queue_);
        state_ = State::kStarted;
        stream_->StartCall(&start_processor_);
        start_time_ = std::chrono::steady_clock::now();
        ++bidi_streaming_stats_.started_count;
        SILK_TRACE << "AsyncBidirectionalStreamingCall::start END";
    }

  protected:
    void read() {
        SILK_TRACE << "AsyncBidirectionalStreamingCall::read START";
        stream_->Read(&reply_, &read_processor_);
        SILK_TRACE << "AsyncBidirectionalStreamingCall::read END";
    }

    void write() {
        SILK_TRACE << "AsyncBidirectionalStreamingCall::write START";
        stream_->Write(request_, &write_processor_);
        SILK_TRACE << "AsyncBidirectionalStreamingCall::write END";
    }

    void writes_done() {
        SILK_TRACE << "AsyncBidirectionalStreamingCall::writes_done START";
        stream_->WritesDone(&writes_done_processor_);
        SILK_TRACE << "AsyncBidirectionalStreamingCall::writes_done END";
    }

    void finish() {
        SILK_TRACE << "AsyncBidirectionalStreamingCall::finish START";
        stream_->Finish(&status_, &finish_processor_);
        SILK_TRACE << "AsyncBidirectionalStreamingCall::finish END";
    }

    void process_start(bool ok) {
        SILK_DEBUG << "AsyncBidirectionalStreamingCall::process_start ok: " << ok;
        SILKWORM_ASSERT(state_ == State::kStarted);
        if (ok) {
            const bool request_read = handle_start();
            if (request_read) {
                // Schedule first async READ event.
                state_ = State::kReading;
                read();
                SILK_DEBUG << "AsyncBidirectionalStreamingCall schedule read state: " << magic_enum::enum_name(state_);
            } else {
                // Schedule first async WRITE event.
                state_ = State::kWriting;
                write();
                SILK_DEBUG << "AsyncBidirectionalStreamingCall schedule write state: " << magic_enum::enum_name(state_);
            }
        } else {
            SILK_DEBUG << "AsyncBidirectionalStreamingCall closed by peer state: " << magic_enum::enum_name(state_);
            state_ = State::kDone;
            finish();
        }
    }

    void process_read(bool ok) {
        SILK_DEBUG << "AsyncBidirectionalStreamingCall::process_read ok: " << ok;
        SILKWORM_ASSERT(state_ == State::kReading);
        if (ok) {
            ++bidi_streaming_stats_.received_count;
            SILK_DEBUG << "AsyncBidirectionalStreamingCall new response received: " << bidi_streaming_stats_.received_count;
            const bool done = handle_read();
            if (done) {
                state_ = State::kClosed;
                SILK_DEBUG << "AsyncBidirectionalStreamingCall closed by us state: " << magic_enum::enum_name(state_);
                writes_done();
            } else {
                // Schedule next async WRITE event.
                state_ = State::kWriting;
                write();
                SILK_DEBUG << "AsyncBidirectionalStreamingCall schedule write state: " << magic_enum::enum_name(state_);
            }
        } else {
            SILK_DEBUG << "AsyncBidirectionalStreamingCall closed by peer in state " << magic_enum::enum_name(state_);
            state_ = State::kDone;
            finish();
        }
    }

    void process_write(bool ok) {
        SILK_DEBUG << "AsyncBidirectionalStreamingCall::process_write ok: " << ok;
        SILKWORM_ASSERT(state_ == State::kWriting);
        if (ok) {
            ++bidi_streaming_stats_.sent_count;
            SILK_DEBUG << "AsyncBidirectionalStreamingCall new request sent: " << bidi_streaming_stats_.sent_count;
            const bool done = handle_write();
            if (done) {
                state_ = State::kClosed;
                SILK_DEBUG << "AsyncBidirectionalStreamingCall closed by us state: " << magic_enum::enum_name(state_);
                writes_done();
            } else {
                // Schedule next async READ event.
                state_ = State::kReading;
                read();
                SILK_DEBUG << "AsyncBidirectionalStreamingCall schedule read state: " << magic_enum::enum_name(state_);
            }
        } else {
            SILK_DEBUG << "AsyncBidirectionalStreamingCall closed by peer state: " << magic_enum::enum_name(state_);
            state_ = State::kDone;
            finish();
        }
    }

    void process_writes_done(bool ok) {
        SILK_DEBUG << "AsyncBidirectionalStreamingCall::process_writes_done ok: " << ok;
        SILKWORM_ASSERT(state_ == State::kClosed);
        if (ok) {
            SILK_DEBUG << "AsyncBidirectionalStreamingCall closed state: " << magic_enum::enum_name(state_);
            state_ = State::kDone;
            SILK_DEBUG << "AsyncBidirectionalStreamingCall finishing state: " << magic_enum::enum_name(state_);
            finish();
        } else {
            state_ = State::kDone;
            SILK_DEBUG << "AsyncBidirectionalStreamingCall closed by peer state: " << magic_enum::enum_name(state_);
            finish();
        }
    }

    void process_finish(bool ok) {
        SILK_DEBUG << "AsyncBidirectionalStreamingCall::process_finish ok: " << ok;
        SILKWORM_ASSERT(state_ == State::kDone);
        if (ok) {
            SILK_DEBUG << "AsyncBidirectionalStreamingCall finished state: " << magic_enum::enum_name(state_);
            ++bidi_streaming_stats_.completed_count;
            if (status_.ok()) {
                ++bidi_streaming_stats_.ok_count;
            } else {
                ++bidi_streaming_stats_.ko_count;
            }
        } else {
            SILK_ERROR << "AsyncBidirectionalStreamingCall cannot finish state: " << magic_enum::enum_name(state_);
        }
        handle_finish();
    }

    virtual bool handle_start() = 0;
    virtual bool handle_read() = 0;
    virtual bool handle_write() = 0;
    virtual void handle_finish() = 0;

    inline static BidirectionalStreamingStats bidi_streaming_stats_;

    enum class State {
        kIdle,
        kStarted,
        kWriting,
        kReading,
        kClosed,
        kDone,
    };

    TagProcessor start_processor_;
    TagProcessor read_processor_;
    TagProcessor write_processor_;
    TagProcessor writes_done_processor_;
    TagProcessor finish_processor_;

    StubInterface* stub_;
    AsyncReaderWriterPtr<Request, Reply> stream_;
    grpc::Status status_;
    Request request_;
    Reply reply_;
    State state_{State::kIdle};
};

class AsyncEtherbaseCall : public AsyncUnaryCall<
                               remote::EtherbaseRequest, remote::EtherbaseReply,
                               remote::ETHBACKEND::StubInterface,
                               &remote::ETHBACKEND::StubInterface::PrepareAsyncEtherbase> {
  public:
    explicit AsyncEtherbaseCall(grpc::CompletionQueue* queue, remote::ETHBACKEND::StubInterface* stub)
        : AsyncUnaryCall(queue, stub, [](auto* call) { delete call; }) {}

    void handle_finish(bool ok) override {
        SILK_DEBUG << "AsyncEtherbaseCall::handle_finish ok: " << ok << " status: " << status_;

        if (ok && status_.ok()) {
            if (reply_.has_address()) {
                const auto h160_address = reply_.address();
                const auto address = silkworm::to_hex(silkworm::rpc::address_from_H160(h160_address));
                SILK_INFO << "Etherbase reply: " << address << " [latency=" << latency() / 1ns << " ns]";
            } else {
                SILK_INFO << "Etherbase reply: no address";
            }
        } else {
            SILK_ERROR << "Etherbase failed: " << status_;
        }
    }
};

class AsyncNetVersionCall : public AsyncUnaryCall<
                                remote::NetVersionRequest,
                                remote::NetVersionReply,
                                remote::ETHBACKEND::StubInterface,
                                &remote::ETHBACKEND::StubInterface::PrepareAsyncNetVersion> {
  public:
    explicit AsyncNetVersionCall(grpc::CompletionQueue* queue, remote::ETHBACKEND::StubInterface* stub)
        : AsyncUnaryCall(queue, stub, [](auto* call) { delete call; }) {}

    void handle_finish(bool ok) override {
        SILK_DEBUG << "AsyncNetVersionCall::handle_finish ok: " << ok << " status: " << status_;

        if (ok && status_.ok()) {
            SILK_INFO << "NetVersion reply: id=" << reply_.id() << " [latency=" << latency() / 1ns << " ns]";
        } else {
            SILK_ERROR << "NetVersion failed: " << status_;
        }
    }
};

class AsyncNetPeerCountCall : public AsyncUnaryCall<
                                  remote::NetPeerCountRequest,
                                  remote::NetPeerCountReply,
                                  remote::ETHBACKEND::StubInterface,
                                  &remote::ETHBACKEND::StubInterface::PrepareAsyncNetPeerCount> {
  public:
    explicit AsyncNetPeerCountCall(grpc::CompletionQueue* queue, remote::ETHBACKEND::StubInterface* stub)
        : AsyncUnaryCall(queue, stub, [](auto* call) { delete call; }) {}

    void handle_finish(bool ok) override {
        SILK_DEBUG << "AsyncNetPeerCountCall::handle_finish ok: " << ok << " status: " << status_;

        if (ok && status_.ok()) {
            SILK_INFO << "NetPeerCount reply: count=" << reply_.count() << " [latency=" << latency() / 1ns << " ns]";
        } else {
            SILK_ERROR << "NetPeerCount failed: " << status_;
        }
    }
};

class AsyncBackEndVersionCall : public AsyncUnaryCall<
                                    google::protobuf::Empty,
                                    types::VersionReply,
                                    remote::ETHBACKEND::StubInterface,
                                    &remote::ETHBACKEND::StubInterface::PrepareAsyncVersion> {
  public:
    explicit AsyncBackEndVersionCall(grpc::CompletionQueue* queue, remote::ETHBACKEND::StubInterface* stub)
        : AsyncUnaryCall(queue, stub, [](auto* call) { delete call; }) {}

    void handle_finish(bool ok) override {
        SILK_DEBUG << "AsyncBackEndVersionCall::handle_finish ok: " << ok << " status: " << status_;

        if (ok && status_.ok()) {
            const auto major = reply_.major();
            const auto minor = reply_.minor();
            const auto patch = reply_.patch();
            SILK_INFO << "BackEnd Version reply: " << major << "." << minor << "." << patch << " [latency=" << latency() / 1ns << " ns]";
        } else {
            SILK_ERROR << "BackEnd Version failed: " << status_;
        }
    }
};

class AsyncProtocolVersionCall : public AsyncUnaryCall<
                                     remote::ProtocolVersionRequest,
                                     remote::ProtocolVersionReply,
                                     remote::ETHBACKEND::StubInterface,
                                     &remote::ETHBACKEND::StubInterface::PrepareAsyncProtocolVersion> {
  public:
    explicit AsyncProtocolVersionCall(grpc::CompletionQueue* queue, remote::ETHBACKEND::StubInterface* stub)
        : AsyncUnaryCall(queue, stub, [](auto* call) { delete call; }) {}

    void handle_finish(bool ok) override {
        SILK_DEBUG << "AsyncProtocolVersionCall::handle_finish ok: " << ok << " status: " << status_;

        if (ok && status_.ok()) {
            SILK_INFO << "ProtocolVersion reply: id=" << reply_.id() << " [latency=" << latency() / 1ns << " ns]";
        } else {
            SILK_ERROR << "ProtocolVersion failed: " << status_;
        }
    }
};

class AsyncClientVersionCall : public AsyncUnaryCall<
                                   remote::ClientVersionRequest,
                                   remote::ClientVersionReply,
                                   remote::ETHBACKEND::StubInterface,
                                   &remote::ETHBACKEND::StubInterface::PrepareAsyncClientVersion> {
  public:
    explicit AsyncClientVersionCall(grpc::CompletionQueue* queue, remote::ETHBACKEND::StubInterface* stub)
        : AsyncUnaryCall(queue, stub, [](auto* call) { delete call; }) {}

    void handle_finish(bool ok) override {
        SILK_DEBUG << "AsyncClientVersionCall::handle_finish ok: " << ok << " status: " << status_;

        if (ok && status_.ok()) {
            SILK_INFO << "ClientVersion reply: node name=" << reply_.nodename() << " [latency=" << latency() / 1ns << " ns]";
        } else {
            SILK_ERROR << "ClientVersion failed: " << status_;
        }
    }
};

class AsyncSubscribeCall : public AsyncServerStreamingCall<remote::SubscribeRequest, remote::SubscribeReply,
                                                           remote::ETHBACKEND::StubInterface,
                                                           &remote::ETHBACKEND::StubInterface::PrepareAsyncSubscribe> {
  public:
    explicit AsyncSubscribeCall(grpc::CompletionQueue* queue, remote::ETHBACKEND::StubInterface* stub)
        : AsyncServerStreamingCall(queue, stub) {}

    void handle_read() override {
        SILK_INFO << "Subscribe reply: type=" << reply_.type() << " data=" << reply_.data();
    }

    void handle_finish() override {
        if (status_.ok()) {
            SILK_INFO << "Subscribe completed status: " << status_;
        } else {
            SILK_ERROR << "Subscribe failed: " << status_;
        }
        delete this;
    }
};

class AsyncNodeInfoCall : public AsyncUnaryCall<
                              remote::NodesInfoRequest,
                              remote::NodesInfoReply,
                              remote::ETHBACKEND::StubInterface,
                              &remote::ETHBACKEND::StubInterface::PrepareAsyncNodeInfo> {
  public:
    explicit AsyncNodeInfoCall(grpc::CompletionQueue* queue, remote::ETHBACKEND::StubInterface* stub)
        : AsyncUnaryCall(queue, stub) {}

    void handle_finish(bool ok) override {
        SILK_DEBUG << "AsyncNodeInfoCall::handle_finish ok: " << ok << " status: " << status_;

        if (ok && status_.ok()) {
            SILK_INFO << "NodeInfo reply: nodes info size=" << reply_.nodesinfo_size() << " [latency=" << latency() / 1ns << " ns]";
        } else {
            SILK_ERROR << "NodeInfo failed: " << status_;
        }
    }
};

class AsyncKvVersionCall : public AsyncUnaryCall<
                               google::protobuf::Empty,
                               types::VersionReply,
                               remote::KV::StubInterface,
                               &remote::KV::StubInterface::PrepareAsyncVersion> {
  public:
    explicit AsyncKvVersionCall(grpc::CompletionQueue* queue, remote::KV::StubInterface* stub)
        : AsyncUnaryCall(queue, stub) {}

    void handle_finish(bool ok) override {
        SILK_DEBUG << "AsyncKvVersionCall::handle_finish ok: " << ok << " status: " << status_;

        if (ok && status_.ok()) {
            const auto major = reply_.major();
            const auto minor = reply_.minor();
            const auto patch = reply_.patch();
            SILK_INFO << "KV Version reply: " << major << "." << minor << "." << patch << " [latency=" << latency() / 1ns << " ns]";
        } else {
            SILK_ERROR << "KV Version failed: " << status_;
        }
    }
};

namespace remote {
inline std::ostream& operator<<(std::ostream& out, const Pair& kv_pair) {
    out << "k=" << silkworm::to_hex(silkworm::Bytes(kv_pair.k().begin(), kv_pair.k().end()))
        << " v= " << silkworm::to_hex(silkworm::Bytes(kv_pair.v().begin(), kv_pair.v().end()));
    return out;
}
}  // namespace remote

class AsyncTxCall
    : public AsyncBidirectionalStreamingCall<remote::Cursor, remote::Pair, remote::KV::StubInterface,
                                             &remote::KV::StubInterface::PrepareAsyncTx> {
  public:
    explicit AsyncTxCall(grpc::CompletionQueue* queue, remote::KV::StubInterface* stub)
        : AsyncBidirectionalStreamingCall(queue, stub) {}

    bool handle_start() override {
        SILK_INFO << "Tx started: reading database view";
        return true;
    }

    bool handle_read() override {
        if (view_id_ == kInvalidViewId) {
            SILK_INFO << "Tx database view: txid=" << reply_.txid();
            view_id_ = reply_.txid();
            SILK_INFO << "Tx announced: opening cursor";
            request_.set_op(remote::Op::OPEN);
            request_.set_bucketname(table_name_);
            return false;
        }
        if (query_count_ == 0) {
            if (cursor_id_ == kInvalidCursorId) {
                SILK_DEBUG << "Tx cursor closed, closing tx";
                return true;  // reads done, close tx
            } else {
                SILK_INFO << "Tx queried: " << reply_ << ", queries done closing cursor";
                request_.set_op(remote::Op::CLOSE);
                request_.set_cursor(cursor_id_);
                cursor_id_ = kInvalidCursorId;
                return false;
            }
        } else {
            if (cursor_id_ == kInvalidCursorId) {
                SILK_INFO << "Tx opened: cursor=" << reply_.cursorid();
                cursor_id_ = reply_.cursorid();
                SILK_DEBUG << "Tx: prepare request FIRST cursor=" << cursor_id_;
                request_.set_op(remote::Op::FIRST);
                request_.set_cursor(cursor_id_);
            } else {
                SILK_INFO << "Tx queried: " << reply_;
                --query_count_;
                SILK_DEBUG << "Tx: prepare request NEXT cursor=" << cursor_id_;
                request_.set_op(remote::Op::NEXT);
                request_.set_cursor(cursor_id_);
            }
            return false;
        }
    }

    bool handle_write() override {
        SILK_DEBUG << "Tx request: cursor op=" << remote::Op_Name(request_.op());
        return false;
    }

    void handle_finish() override {
        if (status_.ok()) {
            SILK_INFO << "Tx completed: status: " << status_;
        } else {
            SILK_ERROR << "Tx failed: " << status_;
        }
        delete this;
    }

  private:
    inline static const uint32_t kInvalidViewId{0};
    inline static const uint32_t kInvalidCursorId{0};

    uint32_t view_id_{kInvalidViewId};
    std::string table_name_{silkworm::db::table::kCanonicalHashes.name};
    uint32_t query_count_{5};
    uint32_t cursor_id_{kInvalidCursorId};
};

class AsyncStateChangesCall
    : public AsyncServerStreamingCall<remote::StateChangeRequest, remote::StateChangeBatch, remote::KV::StubInterface,
                                      &remote::KV::StubInterface::PrepareAsyncStateChanges> {
  public:
    static std::size_t num_pending_calls() { return pending_calls_.size(); }

    static void add_pending_call(AsyncStateChangesCall* call) {
        pending_calls_.push_back(call);
    }

    static void remove_pending_call(AsyncStateChangesCall* call) {
        pending_calls_.erase(std::find(pending_calls_.begin(), pending_calls_.end(), call));
        std::unique_ptr<AsyncStateChangesCall> call_ptr{call};
    }

    static void cancel_pending_calls() {
        for (AsyncStateChangesCall* call : pending_calls_) {
            std::unique_ptr<AsyncStateChangesCall> call_ptr{call};
            call_ptr->cancel();
        }
        pending_calls_.clear();
    }

    explicit AsyncStateChangesCall(grpc::CompletionQueue* queue, remote::KV::StubInterface* stub)
        : AsyncServerStreamingCall(queue, stub) {}

    void handle_read() override {
        SILK_INFO << "StateChanges batch: change batch size=" << reply_.changebatch_size()
                  << " database view id=" << reply_.databaseviewid()
                  << " pending block base fee=" << reply_.pendingblockbasefee()
                  << " block gas limit=" << reply_.blockgaslimit();
    }

    void handle_finish() override {
        if (status_.ok()) {
            SILK_INFO << "StateChanges completed status: " << status_;
        } else {
            SILK_ERROR << "StateChanges failed: " << status_;
        }
        remove_pending_call(this);
    }

  private:
    inline static std::vector<AsyncStateChangesCall*> pending_calls_;
};

enum class Rpc {
    etherbase = 0,
    net_version = 1,
    net_peer_count = 2,
    backend_version = 3,
    protocol_version = 4,
    client_version = 5,
    subscribe = 6,
    node_info = 7,
    kv_version = 8,
    tx = 9,
    state_changes = 10
};

struct BatchOptions {
    int batch_size{1};
    std::vector<Rpc> configured_calls;
    int64_t interval_between_calls{100};

    [[nodiscard]] bool is_configured(Rpc call) const {
        return configured_calls.empty() || contains_call(call);
    }

  private:
    [[nodiscard]] bool contains_call(Rpc call) const {
        return std::find(configured_calls.begin(), configured_calls.end(), call) != configured_calls.end();
    }
};

class AsyncCallFactory {
  public:
    AsyncCallFactory(const std::shared_ptr<grpc::Channel>& channel, grpc::CompletionQueue* queue)
        : queue_(queue),
          ethbackend_stub_{remote::ETHBACKEND::NewStub(channel, grpc::StubOptions{})},
          kv_stub_{remote::KV::NewStub(channel, grpc::StubOptions{})} {}

    void start_batch(std::atomic_bool& stop, const BatchOptions& batch_options) {
        for (auto i{0}; i < batch_options.batch_size && !stop; i++) {
            if (batch_options.is_configured(Rpc::etherbase)) {
                auto* etherbase = new AsyncEtherbaseCall(queue_, ethbackend_stub_.get());
                etherbase->start(remote::EtherbaseRequest{});
                SILK_DEBUG << "New Etherbase async call started: " << etherbase;
            }

            if (batch_options.is_configured(Rpc::net_version)) {
                auto* net_version = new AsyncNetVersionCall(queue_, ethbackend_stub_.get());
                net_version->start(remote::NetVersionRequest{});
                SILK_DEBUG << "New NetVersion async call started: " << net_version;
            }

            if (batch_options.is_configured(Rpc::net_peer_count)) {
                auto* net_peer_count = new AsyncNetPeerCountCall(queue_, ethbackend_stub_.get());
                net_peer_count->start(remote::NetPeerCountRequest{});
                SILK_DEBUG << "New NetPeerCount async call started: " << net_peer_count;
            }

            if (batch_options.is_configured(Rpc::backend_version)) {
                auto* backend_version = new AsyncBackEndVersionCall(queue_, ethbackend_stub_.get());
                backend_version->start(google::protobuf::Empty{});
                SILK_DEBUG << "New ETHBACKEND Version async call started: " << backend_version;
            }

            if (batch_options.is_configured(Rpc::protocol_version)) {
                auto* protocol_version = new AsyncProtocolVersionCall(queue_, ethbackend_stub_.get());
                protocol_version->start(remote::ProtocolVersionRequest{});
                SILK_DEBUG << "New ProtocolVersion async call started: " << protocol_version;
            }

            if (batch_options.is_configured(Rpc::client_version)) {
                auto* client_version = new AsyncClientVersionCall(queue_, ethbackend_stub_.get());
                client_version->start(remote::ClientVersionRequest{});
                SILK_DEBUG << "New ClientVersion async call started: " << client_version;
            }

            if (batch_options.is_configured(Rpc::subscribe)) {
                auto* subscribe = new AsyncSubscribeCall(queue_, ethbackend_stub_.get());
                subscribe->start(remote::SubscribeRequest{});
                SILK_DEBUG << "New Subscribe async call started: " << subscribe;
            }

            if (batch_options.is_configured(Rpc::node_info)) {
                auto* node_info = new AsyncNodeInfoCall(queue_, ethbackend_stub_.get());
                node_info->start(remote::NodesInfoRequest{});
                SILK_DEBUG << "New NodeInfo async call started: " << node_info;
            }

            if (batch_options.is_configured(Rpc::kv_version)) {
                auto* kv_version = new AsyncKvVersionCall(queue_, kv_stub_.get());
                kv_version->start(google::protobuf::Empty{});
                SILK_DEBUG << "New KV Version async call started: " << kv_version;
            }

            if (batch_options.is_configured(Rpc::tx)) {
                auto* tx = new AsyncTxCall(queue_, kv_stub_.get());
                tx->start();
                SILK_DEBUG << "New Tx async call started: " << tx;
            }

            if (batch_options.is_configured(Rpc::state_changes) && AsyncStateChangesCall::num_pending_calls() < 10000) {
                auto* state_changes = new AsyncStateChangesCall(queue_, kv_stub_.get());
                state_changes->start(remote::StateChangeRequest{});
                SILK_DEBUG << "New StateChanges async call started: " << state_changes;
                AsyncStateChangesCall::add_pending_call(state_changes);
            }
        }
    }

  private:
    grpc::CompletionQueue* queue_;
    std::unique_ptr<remote::ETHBACKEND::Stub> ethbackend_stub_;
    std::unique_ptr<remote::KV::Stub> kv_stub_;
};

void print_stats(const BatchOptions& batch_options) {
    if (batch_options.is_configured(Rpc::etherbase)) {
        SILK_LOG << "Unary stats Etherbase: " << AsyncEtherbaseCall::stats();
    }
    if (batch_options.is_configured(Rpc::net_version)) {
        SILK_LOG << "Unary stats NetVersion: " << AsyncNetVersionCall::stats();
    }
    if (batch_options.is_configured(Rpc::net_peer_count)) {
        SILK_LOG << "Unary stats NetPeerCount: " << AsyncNetPeerCountCall::stats();
    }
    if (batch_options.is_configured(Rpc::backend_version)) {
        SILK_LOG << "Unary stats ETHBACKEND Version: " << AsyncBackEndVersionCall::stats();
    }
    if (batch_options.is_configured(Rpc::protocol_version)) {
        SILK_LOG << "Unary stats ProtocolVersion: " << AsyncProtocolVersionCall::stats();
    }
    if (batch_options.is_configured(Rpc::client_version)) {
        SILK_LOG << "Unary stats ClientVersion: " << AsyncClientVersionCall::stats();
    }
    if (batch_options.is_configured(Rpc::node_info)) {
        SILK_LOG << "Unary stats NodeInfo: " << AsyncNodeInfoCall::stats();
    }
    if (batch_options.is_configured(Rpc::kv_version)) {
        SILK_LOG << "Unary stats KV Version: " << AsyncKvVersionCall::stats();
    }
    if (batch_options.is_configured(Rpc::subscribe)) {
        SILK_LOG << "Server streaming stats Subscribe: " << AsyncSubscribeCall::stats();
    }
    if (batch_options.is_configured(Rpc::state_changes)) {
        SILK_LOG << "Server streaming stats StateChanges: " << AsyncStateChangesCall::stats();
    }
    if (batch_options.is_configured(Rpc::tx)) {
        SILK_LOG << "Bidirectional streaming stats Tx: " << AsyncTxCall::stats();
    }
}

int main(int argc, char* argv[]) {
    const auto pid = boost::this_process::get_id();
    const auto tid = std::this_thread::get_id();

    CLI::App app{"ETHBACKEND & KV interface test"};

    std::string target_uri{"localhost:9090"};
    int num_channels{1};
    BatchOptions batch_options;
    silkworm::log::Level log_level{silkworm::log::Level::kCritical};
    app.add_option("--target", target_uri, "The address to connect to the ETHBACKEND & KV services")
        ->capture_default_str();
    app.add_option("--channels", num_channels,
                   "The number of gRPC channels to use as integer")
        ->required()
        ->check(CLI::PositiveNumber)
        ->capture_default_str();
    app.add_option("--interval", batch_options.interval_between_calls,
                   "The interval to wait between successive call batches as milliseconds")
        ->capture_default_str();
    app.add_option("--batch", batch_options.batch_size, "The number of async calls for each RPC in each batch as integer")
        ->capture_default_str();
    app.add_option("--calls", batch_options.configured_calls, "The list of RPC call types to use as integers")
        ->capture_default_str();
    app.add_option("--logLevel", log_level, "The log level identifier as string")
        ->capture_default_str()
        ->check(CLI::Range(static_cast<uint32_t>(silkworm::log::Level::kCritical),
                           static_cast<uint32_t>(silkworm::log::Level::kTrace)))
        ->default_val(std::to_string(static_cast<uint32_t>(log_level)));

    CLI11_PARSE(app, argc, argv)

    silkworm::log::Settings log_settings{};
    log_settings.log_threads = true;
    log_settings.log_verbosity = log_level;
    silkworm::log::init(log_settings);

    // TODO(canepat): this could be an option in Silkworm logging facility
    silkworm::rpc::Grpc2SilkwormLogGuard log_guard;

    try {
        boost::asio::io_context scheduler;
        boost::asio::signal_set signals{scheduler, SIGINT, SIGTERM};

        std::vector<std::shared_ptr<grpc::Channel>> channels;
        for (int i{0}; i < num_channels; ++i) {
            grpc::ChannelArguments channel_args;
            channel_args.SetInt(GRPC_ARG_USE_LOCAL_SUBCHANNEL_POOL, 1);
            channels.push_back(grpc::CreateCustomChannel(target_uri, grpc::InsecureChannelCredentials(), channel_args));
        }
        grpc::CompletionQueue queue;

        std::mutex mutex;
        std::condition_variable shutdown_requested;

        std::atomic_bool pump_stop{false};
        std::thread pump_thread{[&]() {
            SILK_TRACE << "Pump thread: " << pump_thread.get_id() << " start";
            std::size_t channel_index{0};
            while (!pump_stop) {
                AsyncCallFactory call_factory{channels[channel_index], &queue};
                call_factory.start_batch(pump_stop, batch_options);
                SILK_DEBUG << "Pump thread going to wait for " << batch_options.interval_between_calls << "ms...";
                std::unique_lock<std::mutex> lock{mutex};
                const auto now = std::chrono::system_clock::now();
                shutdown_requested.wait_until(lock, now + std::chrono::milliseconds{batch_options.interval_between_calls});
                channel_index = (channel_index + 1) % channels.size();
            }
            AsyncStateChangesCall::cancel_pending_calls();
            SILK_TRACE << "Pump thread: " << pump_thread.get_id() << " end";
        }};

        std::atomic_bool completion_stop{false};
        std::thread completion_thread{[&]() {
            SILK_TRACE << "Completion thread: " << completion_thread.get_id() << " start";
            while (!completion_stop) {
                SILK_DEBUG << "Reading next tag from queue...";
                void* tag{nullptr};
                bool ok{false};
                const auto got_event = queue.Next(&tag, &ok);
                if (got_event && !completion_stop) {
                    auto* processor = reinterpret_cast<TagProcessor*>(tag);
                    SILK_DEBUG << "Completion thread post operation: " << processor;
                    (*processor)(ok);
                } else {
                    SILK_DEBUG << "Got shutdown";
                    SILKWORM_ASSERT(completion_stop);
                }
            }
            SILK_TRACE << "Completion thread: " << completion_thread.get_id() << " end";
        }};

        SILK_DEBUG << "Signals registered on scheduler " << &scheduler;
        signals.async_wait([&](const boost::system::error_code& error, int signal_number) {
            std::cout << "\n";
            SILK_INFO << "Signal caught, error: " << error << " number: " << signal_number;
            pump_stop = true;
            completion_stop = true;
            shutdown_requested.notify_one();
            scheduler.stop();
        });

        SILK_LOG << "ETHBACKEND & KV interface test running [pid=" << pid << ", main thread=" << tid << "]";
        scheduler.run();

        // Order matters here: 1) wait for pump thread exit 2) shutdown gRPC CQ 3) wait for completion thread exit
        if (pump_thread.joinable()) {
            const auto pump_thread_id = pump_thread.get_id();
            SILK_DEBUG << "Joining pump thread: " << pump_thread_id;
            pump_thread.join();
            SILK_DEBUG << "Pump thread: " << pump_thread_id << " terminated";
        }
        queue.Shutdown();
        if (completion_thread.joinable()) {
            const auto completion_thread_id = completion_thread.get_id();
            SILK_DEBUG << "Joining completion thread: " << completion_thread_id;
            completion_thread.join();
            SILK_DEBUG << "Completion thread: " << completion_thread_id << " terminated";
        }

        print_stats(batch_options);
        SILK_LOG << "ETHBACKEND & KV interface test exiting [pid=" << pid << ", main thread=" << tid << "]";
        return 0;
    } catch (const std::exception& e) {
        SILK_CRIT << "ETHBACKEND & KV interface test exiting due to exception: " << e.what();
        return -1;
    } catch (...) {
        SILK_CRIT << "ETHBACKEND & KV interface test exiting due to unexpected exception";
        return -2;
    }
}
