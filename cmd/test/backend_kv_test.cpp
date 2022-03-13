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
#include <iostream>
#include <memory>
#include <mutex>
#include <thread>

#include <boost/asio/io_context.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/process/environment.hpp>
#include <CLI/CLI.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/common/endian.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/common/util.hpp>
#include <silkworm/rpc/util.hpp>
#include <remote/ethbackend.grpc.pb.h>

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

class AsyncCall {
  public:
    explicit AsyncCall(grpc::CompletionQueue* queue) : queue_(queue) {}
    virtual ~AsyncCall() = default;

    virtual bool handle_completion(bool ok) = 0;

    std::chrono::steady_clock::time_point start_time() const { return start_time_; }

  protected:
    grpc::ClientContext client_context_;
    grpc::CompletionQueue* queue_;
    std::chrono::steady_clock::time_point start_time_;
};

template <typename Reply>
using AsyncResponseReaderPtr = std::unique_ptr<grpc::ClientAsyncResponseReaderInterface<Reply>>;

template<
    typename Request,
    typename Reply,
    AsyncResponseReaderPtr<Reply>(remote::ETHBACKEND::StubInterface::*PrepareAsync)(grpc::ClientContext*, const Request&, grpc::CompletionQueue*)
>
class AsyncUnaryCall : public AsyncCall {
  public:
    explicit AsyncUnaryCall(std::shared_ptr<grpc::Channel> channel, grpc::CompletionQueue* queue)
    : AsyncCall(queue), stub_(remote::ETHBACKEND::NewStub(channel)) {}

    void start_async(const Request& request) {
        SILK_TRACE << "AsyncUnaryCall::start_async START";
        auto response_reader = (stub_.get()->*PrepareAsync)(&client_context_, request, queue_);
        response_reader->StartCall();
        response_reader->Finish(&reply_, &status_, this);
        start_time_ = std::chrono::steady_clock::now();
        ++unary_stats.started_count;
        SILK_TRACE << "AsyncUnaryCall::start_async END";
    }

  protected:
    std::unique_ptr<remote::ETHBACKEND::StubInterface> stub_;
    grpc::Status status_;
    Reply reply_;
};

template <typename Reply>
using AsyncReaderPtr = std::unique_ptr<grpc::ClientAsyncReaderInterface<Reply>>;

template<
    typename Request,
    typename Reply,
    AsyncReaderPtr<Reply>(remote::ETHBACKEND::StubInterface::*PrepareAsync)(grpc::ClientContext*, const Request&, grpc::CompletionQueue*)
>
class AsyncServerStreamingCall : public AsyncCall {
  public:
    explicit AsyncServerStreamingCall(std::shared_ptr<grpc::Channel> channel, grpc::CompletionQueue* queue)
    : AsyncCall(queue), stub_(remote::ETHBACKEND::NewStub(channel)) {}

    void start_async(const Request& request) {
        SILK_TRACE << "AsyncServerStreamingCall::start_async START";
        reader_ = (stub_.get()->*PrepareAsync)(&client_context_, request, queue_);
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

    std::unique_ptr<remote::ETHBACKEND::StubInterface> stub_;
    AsyncReaderPtr<Reply> reader_;
    grpc::Status status_;
    Reply reply_;
    bool started_{false};
    bool done_{false};
};

class AsyncEtherbaseCall : public AsyncUnaryCall<
    remote::EtherbaseRequest, remote::EtherbaseReply, &remote::ETHBACKEND::StubInterface::PrepareAsyncEtherbase> {
  public:
    explicit AsyncEtherbaseCall(std::shared_ptr<grpc::Channel> channel, grpc::CompletionQueue* queue)
    : AsyncUnaryCall(channel, queue) {}

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
    remote::NetVersionRequest, remote::NetVersionReply, &remote::ETHBACKEND::StubInterface::PrepareAsyncNetVersion> {
  public:
    explicit AsyncNetVersionCall(std::shared_ptr<grpc::Channel> channel, grpc::CompletionQueue* queue)
    : AsyncUnaryCall(channel, queue) {}

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
    remote::NetPeerCountRequest, remote::NetPeerCountReply, &remote::ETHBACKEND::StubInterface::PrepareAsyncNetPeerCount> {
  public:
    explicit AsyncNetPeerCountCall(std::shared_ptr<grpc::Channel> channel, grpc::CompletionQueue* queue)
    : AsyncUnaryCall(channel, queue) {}

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

class AsyncVersionCall : public AsyncUnaryCall<
    google::protobuf::Empty, types::VersionReply, &remote::ETHBACKEND::StubInterface::PrepareAsyncVersion> {
  public:
    explicit AsyncVersionCall(std::shared_ptr<grpc::Channel> channel, grpc::CompletionQueue* queue)
    : AsyncUnaryCall(channel, queue) {}

    bool handle_completion(bool ok) override {
        SILK_DEBUG << "AsyncVersionCall::handle_completion ok: " << ok << " status: " << status_;
        ++unary_stats.completed_count;
        if (ok && status_.ok()) {
            const auto major = reply_.major();
            const auto minor = reply_.minor();
            const auto patch = reply_.patch();
            SILK_INFO << "Version reply: major=" << major << " minor=" << minor << " patch=" << patch;
            ++unary_stats.ok_count;
        } else {
            ++unary_stats.ko_count;
        }
        return true;
    }
};

class AsyncProtocolVersionCall : public AsyncUnaryCall<
    remote::ProtocolVersionRequest, remote::ProtocolVersionReply, &remote::ETHBACKEND::StubInterface::PrepareAsyncProtocolVersion> {
  public:
    explicit AsyncProtocolVersionCall(std::shared_ptr<grpc::Channel> channel, grpc::CompletionQueue* queue)
    : AsyncUnaryCall(channel, queue) {}

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
    remote::ClientVersionRequest, remote::ClientVersionReply, &remote::ETHBACKEND::StubInterface::PrepareAsyncClientVersion> {
  public:
    explicit AsyncClientVersionCall(std::shared_ptr<grpc::Channel> channel, grpc::CompletionQueue* queue)
    : AsyncUnaryCall(channel, queue) {}

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
    remote::SubscribeRequest, remote::SubscribeReply, &remote::ETHBACKEND::StubInterface::PrepareAsyncSubscribe> {
  public:
    explicit AsyncSubscribeCall(std::shared_ptr<grpc::Channel> channel, grpc::CompletionQueue* queue)
    : AsyncServerStreamingCall(channel, queue) {}

    void handle_read() override {
        SILK_INFO << "Subscribe reply: type=" << reply_.type() << " data=" << reply_.data();
    }

    void handle_finish() override {
        SILK_INFO << "Subscribe completed status: " << status_;
    }
};

class AsyncNodeInfoCall : public AsyncUnaryCall<
    remote::NodesInfoRequest, remote::NodesInfoReply, &remote::ETHBACKEND::StubInterface::PrepareAsyncNodeInfo> {
  public:
    explicit AsyncNodeInfoCall(std::shared_ptr<grpc::Channel> channel, grpc::CompletionQueue* queue)
    : AsyncUnaryCall(channel, queue) {}

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

            auto* version = new AsyncVersionCall(channel_, queue_);
            version->start_async(google::protobuf::Empty{});
            SILK_DEBUG << "New Version async call started: " << version;

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
        }
    }

  private:
    std::shared_ptr<grpc::Channel> channel_;
    grpc::CompletionQueue* queue_;
};

void print_stats() {
    SILK_LOG << "Unary stats: " << unary_stats;
    SILK_LOG << "Server streaming stats: " << server_streaming_stats;
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
                    SILK_DEBUG << "Got tag for " << call.get();
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
