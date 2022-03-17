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
#include <limits>
#include <memory>
#include <mutex>
#include <thread>

#include <boost/asio/io_context.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/process/environment.hpp>
#include <CLI/CLI.hpp>
#include <grpcpp/grpcpp.h>
#include <magic_enum.hpp>

#include <silkworm/common/assert.hpp>
#include <silkworm/common/endian.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/common/util.hpp>
#include <silkworm/rpc/util.hpp>
#include <remote/ethbackend.grpc.pb.h>
#include <remote/kv.grpc.pb.h>

using namespace std::literals;

struct UnaryStats {
    uint64_t started_count{0};
    uint64_t completed_count{0};
    uint64_t ok_count{0};
    uint64_t ko_count{0};
};

std::ostream& operator<<(std::ostream& out, const UnaryStats& stats) {
    out << "started=" << stats.started_count << " completed=" << stats.completed_count
        << " [OK=" << stats.ok_count << " KO=" << stats.ko_count << "]";
    return out;
}

UnaryStats unary_stats;

struct ServerStreamingStats {
    uint64_t started_count{0};
    uint64_t received_count{0};
    uint64_t completed_count{0};
    uint64_t ok_count{0};
    uint64_t ko_count{0};
};

std::ostream& operator<<(std::ostream& out, const ServerStreamingStats& stats) {
    out << "started=" << stats.started_count << " received=" << stats.received_count << " completed=" << stats.completed_count
        << " [OK=" << stats.ok_count << " KO=" << stats.ko_count << "]";
    return out;
}

ServerStreamingStats server_streaming_stats;

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

BidirectionalStreamingStats bidi_streaming_stats;

class AsyncCall {
  public:
    explicit AsyncCall(grpc::CompletionQueue* queue) : queue_(queue) {}
    virtual ~AsyncCall() = default;

    virtual bool handle_completion(bool ok) = 0;

    void cancel() { client_context_.TryCancel(); }

    std::string peer() const { return client_context_.peer(); }

    std::chrono::steady_clock::time_point start_time() const { return start_time_; }

  protected:
    grpc::ClientContext client_context_;
    grpc::CompletionQueue* queue_;
    std::chrono::steady_clock::time_point start_time_;
};

template <class Stub>
using StubFactory = std::function<std::unique_ptr<Stub>(std::shared_ptr<grpc::Channel>, const grpc::StubOptions&)>;

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
    explicit AsyncUnaryCall(std::shared_ptr<grpc::Channel> channel, grpc::CompletionQueue* queue, StubFactory<Stub> newStub)
    : AsyncCall(queue), stub_(newStub(channel, grpc::StubOptions{})) {}

    void start_async(const Request& request) {
        SILK_TRACE << "AsyncUnaryCall::start_async START";
        auto response_reader = (stub_.get()->*PrepareAsyncUnary)(&client_context_, request, queue_);
        response_reader->StartCall();
        response_reader->Finish(&reply_, &status_, this);
        start_time_ = std::chrono::steady_clock::now();
        ++unary_stats.started_count;
        SILK_TRACE << "AsyncUnaryCall::start_async END";
    }

  protected:
    std::unique_ptr<Stub> stub_;
    grpc::Status status_;
    Reply reply_;
};

template <typename Reply>
using AsyncReaderPtr = std::unique_ptr<grpc::ClientAsyncReaderInterface<Reply>>;

template<
    typename Request,
    typename Reply,
    typename StubInterface,
    typename Stub,
    AsyncReaderPtr<Reply>(StubInterface::*PrepareAsyncServerStreaming)(grpc::ClientContext*, const Request&, grpc::CompletionQueue*)
>
class AsyncServerStreamingCall : public AsyncCall {
  public:
    explicit AsyncServerStreamingCall(std::shared_ptr<grpc::Channel> channel, grpc::CompletionQueue* queue, StubFactory<Stub> newStub)
    : AsyncCall(queue), stub_(newStub(channel, grpc::StubOptions{})) {}

    void start_async(const Request& request) {
        SILK_TRACE << "AsyncServerStreamingCall::start_async START";
        reader_ = (stub_.get()->*PrepareAsyncServerStreaming)(&client_context_, request, queue_);
        reader_->StartCall(this);
        start_time_ = std::chrono::steady_clock::now();
        ++server_streaming_stats.started_count;
        SILK_TRACE << "AsyncServerStreamingCall::start_async END";
    }

    void read() {
        SILK_TRACE << "AsyncServerStreamingCall::read START";
        reader_->Read(&reply_, this);
        SILK_TRACE << "AsyncServerStreamingCall::read END";
    }

    void finish() {
        SILK_TRACE << "AsyncServerStreamingCall::finish START";
        reader_->Finish(&status_, this);
        SILK_TRACE << "AsyncServerStreamingCall::finish END";
    }

    bool handle_completion(bool ok) override {
        SILK_DEBUG << "AsyncServerStreamingCall::handle_completion ok: " << ok;
        if (ok) {
            if (done_) {
                handle_finish();
                ++server_streaming_stats.completed_count;
                if (status_.ok()) {
                    ++server_streaming_stats.ok_count;
                } else {
                    ++server_streaming_stats.ko_count;
                }
                return true;
            } else {
                if (started_) {
                    handle_read();
                    ++server_streaming_stats.received_count;
                    SILK_DEBUG << "AsyncServerStreamingCall new message received: " << server_streaming_stats.received_count;
                } else {
                    started_ = true;
                    SILK_DEBUG << "AsyncServerStreamingCall call started";
                }
                // Schedule next async READ event.
                read();
                SILK_DEBUG << "AsyncServerStreamingCall read scheduled";
                return false;
            }
        } else {
            SILK_DEBUG << "AsyncServerStreamingCall interrupted started: " << started_;
            done_ = true;
            finish();
            return false;
        }
    }

  protected:
    virtual void handle_read() = 0;
    virtual void handle_finish() = 0;

    std::unique_ptr<Stub> stub_;
    AsyncReaderPtr<Reply> reader_;
    grpc::Status status_;
    Reply reply_;
    bool started_{false};
    bool done_{false};
};

template <typename Request, typename Reply>
using AsyncReaderWriterPtr = std::unique_ptr<grpc::ClientAsyncReaderWriterInterface<Request, Reply>>;

template<
    typename Request,
    typename Reply,
    typename StubInterface,
    typename Stub,
    AsyncReaderWriterPtr<Request, Reply>(StubInterface::*PrepareAsyncBidirectionalStreaming)(grpc::ClientContext*, grpc::CompletionQueue*)
>
class AsyncBidirectionalStreamingCall : public AsyncCall {
  public:
    explicit AsyncBidirectionalStreamingCall(std::shared_ptr<grpc::Channel> channel, grpc::CompletionQueue* queue, StubFactory<Stub> newStub)
    : AsyncCall(queue), stub_(newStub(channel, grpc::StubOptions{})) {}

    void start_async() {
        SILK_TRACE << "AsyncBidirectionalStreamingCall::start_async START";
        stream_ = (stub_.get()->*PrepareAsyncBidirectionalStreaming)(&client_context_, queue_);
        state_ = State::kStarted;
        stream_->StartCall(this);
        start_time_ = std::chrono::steady_clock::now();
        ++bidi_streaming_stats.started_count;
        SILK_TRACE << "AsyncBidirectionalStreamingCall::start_async END";
    }

    void read() {
        SILK_TRACE << "AsyncBidirectionalStreamingCall::read START";
        stream_->Read(&reply_, this);
        SILK_TRACE << "AsyncBidirectionalStreamingCall::read END";
    }

    void write() {
        SILK_TRACE << "AsyncBidirectionalStreamingCall::write START";
        stream_->Write(request_, this);
        SILK_TRACE << "AsyncBidirectionalStreamingCall::write END";
    }

    void writes_done() {
        SILK_TRACE << "AsyncBidirectionalStreamingCall::writes_done START";
        stream_->WritesDone(this);
        SILK_TRACE << "AsyncBidirectionalStreamingCall::writes_done END";
    }

    void finish() {
        SILK_TRACE << "AsyncBidirectionalStreamingCall::finish START";
        stream_->Finish(&status_, this);
        SILK_TRACE << "AsyncBidirectionalStreamingCall::finish END";
    }

    bool handle_completion(bool ok) override {
        SILK_DEBUG << "AsyncBidirectionalStreamingCall::handle_completion ok: " << ok;
        if (ok) {
            switch (state_) {
                case State::kStarted: {
                    handle_start();
                    // Schedule first async WRITE event.
                    state_ = State::kWriting;
                    write();
                    SILK_DEBUG << "AsyncBidirectionalStreamingCall schedule write state: " << magic_enum::enum_name(state_);
                    return false;
                }
                case State::kWriting: {
                    ++bidi_streaming_stats.sent_count;
                    SILK_DEBUG << "AsyncBidirectionalStreamingCall new request sent: " << bidi_streaming_stats.sent_count;
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
                    return false;
                }
                case State::kReading: {
                    ++bidi_streaming_stats.received_count;
                    SILK_DEBUG << "AsyncBidirectionalStreamingCall new response received: " << bidi_streaming_stats.received_count;
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
                    return false;
                }
                case State::kClosed: {
                    SILK_DEBUG << "AsyncBidirectionalStreamingCall closed state: " << magic_enum::enum_name(state_);
                    state_ = State::kDone;
                    SILK_DEBUG << "AsyncBidirectionalStreamingCall finishing state: " << magic_enum::enum_name(state_);
                    finish();
                    return false;
                }
                case State::kDone: {
                    SILK_DEBUG << "AsyncBidirectionalStreamingCall finished state: " << magic_enum::enum_name(state_);
                    handle_finish();
                    ++bidi_streaming_stats.completed_count;
                    if (status_.ok()) {
                        ++bidi_streaming_stats.ok_count;
                    } else {
                        ++bidi_streaming_stats.ko_count;
                    }
                    return true;
                }
                default:
                    SILKWORM_ASSERT(false);
                    return true;
            }
        } else {
            state_ = State::kDone;
            SILK_DEBUG << "AsyncBidirectionalStreamingCall closed by peer state: " << magic_enum::enum_name(state_);
            finish();
            return false;
        }
    }

  protected:
    virtual void handle_start() = 0;
    virtual bool handle_read() = 0;
    virtual bool handle_write() = 0;
    virtual void handle_finish() = 0;

    enum class State {
        kIdle,
        kStarted,
        kWriting,
        kReading,
        kClosed,
        kDone
    };

    std::unique_ptr<Stub> stub_;
    AsyncReaderWriterPtr<Request, Reply> stream_;
    grpc::Status status_;
    Request request_;
    Reply reply_;
    bool started_{false};
    State state_{State::kIdle};
    bool client_streaming_done_{false};
    bool server_streaming_done_{false};
};

class AsyncEtherbaseCall : public AsyncUnaryCall<
    remote::EtherbaseRequest,
    remote::EtherbaseReply,
    remote::ETHBACKEND::StubInterface,
    remote::ETHBACKEND::Stub,
    &remote::ETHBACKEND::StubInterface::PrepareAsyncEtherbase> {
  public:
    explicit AsyncEtherbaseCall(std::shared_ptr<grpc::Channel> channel, grpc::CompletionQueue* queue)
    : AsyncUnaryCall(channel, queue, &remote::ETHBACKEND::NewStub) {}

    bool handle_completion(bool ok) override {
        SILK_DEBUG << "AsyncEtherbaseCall::handle_completion ok: " << ok << " status: " << status_;
        ++unary_stats.completed_count;
        if (ok && status_.ok()) {
            if (reply_.has_address()) {
                const auto h160_address = reply_.address();
                SILK_INFO << "Etherbase reply: " << silkworm::to_hex(silkworm::rpc::address_from_H160(h160_address));
            } else {
                SILK_INFO << "Etherbase reply: no address";
            }
            ++unary_stats.ok_count;
        } else {
            ++unary_stats.ko_count;
        }
        return true;
    }
};

class AsyncNetVersionCall : public AsyncUnaryCall<
    remote::NetVersionRequest,
    remote::NetVersionReply,
    remote::ETHBACKEND::StubInterface,
    remote::ETHBACKEND::Stub,
    &remote::ETHBACKEND::StubInterface::PrepareAsyncNetVersion> {
  public:
    explicit AsyncNetVersionCall(std::shared_ptr<grpc::Channel> channel, grpc::CompletionQueue* queue)
    : AsyncUnaryCall(channel, queue, &remote::ETHBACKEND::NewStub) {}

    bool handle_completion(bool ok) override {
        SILK_DEBUG << "AsyncNetVersionCall::handle_completion ok: " << ok << " status: " << status_;
        ++unary_stats.completed_count;
        if (ok && status_.ok()) {
            SILK_INFO << "NetVersion reply: id=" << reply_.id();
            ++unary_stats.ok_count;
        } else {
            ++unary_stats.ko_count;
        }
        return true;
    }
};

class AsyncNetPeerCountCall : public AsyncUnaryCall<
    remote::NetPeerCountRequest,
    remote::NetPeerCountReply,
    remote::ETHBACKEND::StubInterface,
    remote::ETHBACKEND::Stub,
    &remote::ETHBACKEND::StubInterface::PrepareAsyncNetPeerCount> {
  public:
    explicit AsyncNetPeerCountCall(std::shared_ptr<grpc::Channel> channel, grpc::CompletionQueue* queue)
    : AsyncUnaryCall(channel, queue, &remote::ETHBACKEND::NewStub) {}

    bool handle_completion(bool ok) override {
        SILK_DEBUG << "AsyncNetPeerCountCall::handle_completion ok: " << ok << " status: " << status_;
        ++unary_stats.completed_count;
        if (ok && status_.ok()) {
            SILK_INFO << "NetPeerCount reply: count=" << reply_.count();
            ++unary_stats.ok_count;
        } else {
            ++unary_stats.ko_count;
        }
        return true;
    }
};

class AsyncBackEndVersionCall : public AsyncUnaryCall<
    google::protobuf::Empty,
    types::VersionReply,
    remote::ETHBACKEND::StubInterface,
    remote::ETHBACKEND::Stub,
    &remote::ETHBACKEND::StubInterface::PrepareAsyncVersion> {
  public:
    explicit AsyncBackEndVersionCall(std::shared_ptr<grpc::Channel> channel, grpc::CompletionQueue* queue)
    : AsyncUnaryCall(channel, queue, &remote::ETHBACKEND::NewStub) {}

    bool handle_completion(bool ok) override {
        SILK_DEBUG << "AsyncBackEndVersionCall::handle_completion ok: " << ok << " status: " << status_;
        ++unary_stats.completed_count;
        if (ok && status_.ok()) {
            const auto major = reply_.major();
            const auto minor = reply_.minor();
            const auto patch = reply_.patch();
            SILK_INFO << "BackEnd Version reply: major=" << major << " minor=" << minor << " patch=" << patch;
            ++unary_stats.ok_count;
        } else {
            ++unary_stats.ko_count;
        }
        return true;
    }
};

class AsyncProtocolVersionCall : public AsyncUnaryCall<
    remote::ProtocolVersionRequest,
    remote::ProtocolVersionReply,
    remote::ETHBACKEND::StubInterface,
    remote::ETHBACKEND::Stub,
    &remote::ETHBACKEND::StubInterface::PrepareAsyncProtocolVersion> {
  public:
    explicit AsyncProtocolVersionCall(std::shared_ptr<grpc::Channel> channel, grpc::CompletionQueue* queue)
    : AsyncUnaryCall(channel, queue, &remote::ETHBACKEND::NewStub) {}

    bool handle_completion(bool ok) override {
        SILK_DEBUG << "AsyncProtocolVersionCall::handle_completion ok: " << ok << " status: " << status_;
        ++unary_stats.completed_count;
        if (ok && status_.ok()) {
            SILK_INFO << "ProtocolVersion reply: id=" << reply_.id();
            ++unary_stats.ok_count;
        } else {
            ++unary_stats.ko_count;
        }
        return true;
    }
};

class AsyncClientVersionCall : public AsyncUnaryCall<
    remote::ClientVersionRequest,
    remote::ClientVersionReply,
    remote::ETHBACKEND::StubInterface,
    remote::ETHBACKEND::Stub,
    &remote::ETHBACKEND::StubInterface::PrepareAsyncClientVersion> {
  public:
    explicit AsyncClientVersionCall(std::shared_ptr<grpc::Channel> channel, grpc::CompletionQueue* queue)
    : AsyncUnaryCall(channel, queue, &remote::ETHBACKEND::NewStub) {}

    bool handle_completion(bool ok) override {
        SILK_DEBUG << "AsyncClientVersionCall::handle_completion ok: " << ok << " status: " << status_;
        ++unary_stats.completed_count;
        if (ok && status_.ok()) {
            SILK_INFO << "ClientVersion reply: nodename=" << reply_.nodename();
            ++unary_stats.ok_count;
        } else {
            ++unary_stats.ko_count;
        }
        return true;
    }
};

class AsyncSubscribeCall : public AsyncServerStreamingCall<
    remote::SubscribeRequest,
    remote::SubscribeReply,
    remote::ETHBACKEND::StubInterface,
    remote::ETHBACKEND::Stub,
    &remote::ETHBACKEND::StubInterface::PrepareAsyncSubscribe> {
  public:
    explicit AsyncSubscribeCall(std::shared_ptr<grpc::Channel> channel, grpc::CompletionQueue* queue)
    : AsyncServerStreamingCall(channel, queue, &remote::ETHBACKEND::NewStub) {}

    void handle_read() override {
        SILK_INFO << "Subscribe reply: type=" << reply_.type() << " data=" << reply_.data();
    }

    void handle_finish() override {
        SILK_INFO << "Subscribe completed status: " << status_;
    }
};

class AsyncNodeInfoCall : public AsyncUnaryCall<
    remote::NodesInfoRequest,
    remote::NodesInfoReply,
    remote::ETHBACKEND::StubInterface,
    remote::ETHBACKEND::Stub,
    &remote::ETHBACKEND::StubInterface::PrepareAsyncNodeInfo> {
  public:
    explicit AsyncNodeInfoCall(std::shared_ptr<grpc::Channel> channel, grpc::CompletionQueue* queue)
    : AsyncUnaryCall(channel, queue, &remote::ETHBACKEND::NewStub) {}

    bool handle_completion(bool ok) override {
        SILK_DEBUG << "AsyncNodeInfoCall::handle_completion ok: " << ok << " status: " << status_;
        ++unary_stats.completed_count;
        if (ok && status_.ok()) {
            SILK_INFO << "NodeInfo reply: nodesinfo_size=" << reply_.nodesinfo_size();
            ++unary_stats.ok_count;
        } else {
            ++unary_stats.ko_count;
        }
        return true;
    }
};

class AsyncKvVersionCall : public AsyncUnaryCall<
    google::protobuf::Empty,
    types::VersionReply,
    remote::KV::StubInterface,
    remote::KV::Stub,
    &remote::KV::StubInterface::PrepareAsyncVersion> {
  public:
    explicit AsyncKvVersionCall(std::shared_ptr<grpc::Channel> channel, grpc::CompletionQueue* queue)
    : AsyncUnaryCall(channel, queue, &remote::KV::NewStub) {}

    bool handle_completion(bool ok) override {
        SILK_DEBUG << "AsyncKvVersionCall::handle_completion ok: " << ok << " status: " << status_;
        ++unary_stats.completed_count;
        if (ok && status_.ok()) {
            const auto major = reply_.major();
            const auto minor = reply_.minor();
            const auto patch = reply_.patch();
            SILK_INFO << "KV Version reply: major=" << major << " minor=" << minor << " patch=" << patch;
            ++unary_stats.ok_count;
        } else {
            ++unary_stats.ko_count;
        }
        return true;
    }
};

class AsyncTxCall : public AsyncBidirectionalStreamingCall<
    remote::Cursor,
    remote::Pair,
    remote::KV::StubInterface,
    remote::KV::Stub,
    &remote::KV::StubInterface::PrepareAsyncTx> {
  public:
    explicit AsyncTxCall(std::shared_ptr<grpc::Channel> channel, grpc::CompletionQueue* queue)
    : AsyncBidirectionalStreamingCall(channel, queue, &remote::KV::NewStub) {}

    void handle_start() override {
        SILK_INFO << "Tx started: opening cursor";
        request_.set_op(remote::Op::OPEN);
        request_.set_bucketname(table_name_);
    }

    bool handle_read() override {
        if (query_count_ == 0) {
            if (cursor_id_ == kInvalidCursorId) {
                SILK_DEBUG << "Tx cursor closed, closing tx";
                return true; // reads done, close tx
            } else {
                SILK_INFO << "Tx queried: k=" << reply_.k() << " v= " << reply_.v() << ", queries done closing cursor";
                request_.set_op(remote::Op::CLOSE);
                request_.set_cursor(cursor_id_);
                cursor_id_ = kInvalidCursorId;
                return false;
            }
        } else {
            if (cursor_id_ == kInvalidCursorId) {
                SILK_INFO << "Tx opened: cursor=" << reply_.cursorid();
                cursor_id_ = reply_.cursorid();
            } else {
                SILK_INFO << "Tx queried: k=" << reply_.k() << " v: " << reply_.v();
            }
            --query_count_;
            SILK_DEBUG << "Tx: prepare request NEXT cursor=" << cursor_id_;
            // Prepare next Cursor query to send.
            request_.set_op(remote::Op::NEXT);
            request_.set_cursor(cursor_id_);
            return false;
        }
    }

    bool handle_write() override {
        SILK_DEBUG << "Tx request: cursor op=" << remote::Op_Name(request_.op());
        return false;
    }

    void handle_finish() override {
        SILK_INFO << "Tx completed: status: " << status_;
    }

  private:
    inline static const uint32_t kInvalidCursorId{std::numeric_limits<uint32_t>::max()};

    std::string table_name_{"TestTable"};
    uint32_t query_count_{5};
    uint32_t cursor_id_{kInvalidCursorId};
};

class AsyncStateChangesCall : public AsyncServerStreamingCall<
    remote::StateChangeRequest,
    remote::StateChangeBatch,
    remote::KV::StubInterface,
    remote::KV::Stub,
    &remote::KV::StubInterface::PrepareAsyncStateChanges> {
  public:
    explicit AsyncStateChangesCall(std::shared_ptr<grpc::Channel> channel, grpc::CompletionQueue* queue)
    : AsyncServerStreamingCall(channel, queue, &remote::KV::NewStub) {}

    void handle_read() override {
        SILK_INFO << "StateChanges batch: changebatch_size=" << reply_.changebatch_size()
            << " databaseviewid=" << reply_.databaseviewid() << " pendingblockbasefee=" << reply_.pendingblockbasefee()
            << " blockgaslimit=" << reply_.blockgaslimit();
    }

    void handle_finish() override {
        SILK_INFO << "StateChanges completed status: " << status_;
    }
};

class AsyncCallFactory {
  public:
    AsyncCallFactory(std::shared_ptr<grpc::Channel> channel, grpc::CompletionQueue* queue) : channel_(channel), queue_(queue) {}

    void start_batch(std::atomic_bool& stop, int batch_size) {
        for (auto i{0}; i<batch_size && !stop; i++) {
            auto* etherbase = new AsyncEtherbaseCall(channel_, queue_);
            etherbase->start_async(remote::EtherbaseRequest{});
            SILK_DEBUG << "New Etherbase async call started: " << etherbase;

            auto* net_version = new AsyncNetVersionCall(channel_, queue_);
            net_version->start_async(remote::NetVersionRequest{});
            SILK_DEBUG << "New NetVersion async call started: " << net_version;

            auto* net_peer_count = new AsyncNetPeerCountCall(channel_, queue_);
            net_peer_count->start_async(remote::NetPeerCountRequest{});
            SILK_DEBUG << "New NetPeerCount async call started: " << net_version;

            auto* backend_version = new AsyncBackEndVersionCall(channel_, queue_);
            backend_version->start_async(google::protobuf::Empty{});
            SILK_DEBUG << "New ETHBACKEND Version async call started: " << backend_version;

            auto* protocol_version = new AsyncProtocolVersionCall(channel_, queue_);
            protocol_version->start_async(remote::ProtocolVersionRequest{});
            SILK_DEBUG << "New ProtocolVersion async call started: " << protocol_version;

            auto* client_version = new AsyncClientVersionCall(channel_, queue_);
            client_version->start_async(remote::ClientVersionRequest{});
            SILK_DEBUG << "New ClientVersion async call started: " << client_version;

            auto* subscribe = new AsyncSubscribeCall(channel_, queue_);
            subscribe->start_async(remote::SubscribeRequest{});
            SILK_DEBUG << "New Subscribe async call started: " << subscribe;

            auto* node_info = new AsyncNodeInfoCall(channel_, queue_);
            node_info->start_async(remote::NodesInfoRequest{});
            SILK_DEBUG << "New NodeInfo async call started: " << node_info;

            auto* kv_version = new AsyncKvVersionCall(channel_, queue_);
            kv_version->start_async(google::protobuf::Empty{});
            SILK_DEBUG << "New KV Version async call started: " << kv_version;

            auto* tx = new AsyncTxCall(channel_, queue_);
            tx->start_async();
            SILK_DEBUG << "New Tx async call started: " << tx;

            auto* state_changes = new AsyncStateChangesCall(channel_, queue_);
            state_changes->start_async(remote::StateChangeRequest{});
            SILK_DEBUG << "New StateChanges async call started: " << state_changes;
        }
    }

  private:
    std::shared_ptr<grpc::Channel> channel_;
    grpc::CompletionQueue* queue_;
};

void print_stats() {
    SILK_LOG << "Unary stats: " << unary_stats;
    SILK_LOG << "Server streaming stats: " << server_streaming_stats;
    SILK_LOG << "Bidirectional streaming stats: " << bidi_streaming_stats;
}

int main(int argc, char* argv[]) {
    const auto pid = boost::this_process::get_id();
    const auto tid = std::this_thread::get_id();

    CLI::App app{"ETHBACKEND & KV interface test"};

    std::string target_uri{"localhost:9090"};
    int64_t interval_between_calls{100};
    int batch_size{1};
    silkworm::log::Level log_level{silkworm::log::Level::kCritical};
    app.add_option("--target", target_uri, "The address to connect to the ETHBACKEND & KV services", true);
    app.add_option("--interval", interval_between_calls, "The interval to wait between successive call batches as milliseconds", true);
    app.add_option("--batch", batch_size, "The number of async calls for each RPC in each batch as integer", true);
    app.add_option("--logLevel", log_level, "The log level identifier as string", true)
        ->check(CLI::Range(static_cast<uint32_t>(silkworm::log::Level::kCritical), static_cast<uint32_t>(silkworm::log::Level::kTrace)))
        ->default_val(std::to_string(static_cast<uint32_t>(log_level)));

    CLI11_PARSE(app, argc, argv);

    silkworm::log::Settings log_settings{};
    log_settings.log_nocolor = true;
    log_settings.log_threads = true;
    log_settings.log_verbosity = log_level;
    silkworm::log::init(log_settings);

    //TODO(canepat): this could be an option in Silkworm logging facility
    silkworm::rpc::Grpc2SilkwormLogGuard log_guard;

    try {
        boost::asio::io_context scheduler;
        boost::asio::signal_set signals{scheduler, SIGINT, SIGTERM};

        auto channel = grpc::CreateChannel(target_uri, grpc::InsecureChannelCredentials());
        //TODO(canepat): create list of channels for round-robin batch pump
        grpc::CompletionQueue queue;

        std::mutex mutex;
        std::condition_variable shutdown_requested;

        std::atomic_bool pump_stop{false};
        std::thread pump_thread{[&]() {
            SILK_TRACE << "Pump thread: " << pump_thread.get_id() << " start";
            AsyncCallFactory call_factory{channel, &queue};
            while (!pump_stop) {
                call_factory.start_batch(pump_stop, batch_size);
                SILK_DEBUG << "Pump thread going to wait for " << interval_between_calls << "ms...";
                std::unique_lock<std::mutex> lock{mutex};
                const auto now = std::chrono::system_clock::now();
                shutdown_requested.wait_until(lock, now + std::chrono::milliseconds{interval_between_calls});
            }
            SILK_TRACE << "Pump thread: " << pump_thread.get_id() << " end";
        }};

        std::atomic_bool completion_stop{false};
        std::thread completion_thread{[&]() {
            SILK_TRACE << "Completion thread: " << completion_thread.get_id() << " start";
            while (!completion_stop) {
                SILK_DEBUG << "Reading next tag from queue...";
                void* tag;
                bool ok;
                const auto got_event = queue.Next(&tag, &ok);
                if (got_event) {
                    std::unique_ptr<AsyncCall> call{static_cast<AsyncCall*>(tag)};
                    SILK_DEBUG << "Got tag for " << call.get() << " from peer " << call->peer();
                    const bool completed = call->handle_completion(ok);
                    const auto end_time = std::chrono::steady_clock::now();
                    const auto latency = end_time - call->start_time();
                    if (completed) {
                        SILK_INFO << "Call " << call.get() << " completed [latency=" << latency / 1ns << " ns]";
                    } else {
                        call.release();
                    }
                } else {
                    SILK_DEBUG << "Got shutdown, draining queue...";
                    while (queue.Next(&tag, &ok)) {
                        std::unique_ptr<AsyncCall> ignored_call{static_cast<AsyncCall*>(tag)};
                    }
                    SILK_DEBUG << "Queue fully drained";
                    SILKWORM_ASSERT(completion_stop);
                }
            }
            SILK_TRACE << "Completion thread: " << completion_thread.get_id() << " end";
        }};

        SILK_DEBUG << "Signals registered on scheduler " << &scheduler;
        signals.async_wait([&](const boost::system::error_code& error, int signal_number) {
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

        print_stats();
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
