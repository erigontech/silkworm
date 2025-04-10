// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <exception>
#include <iomanip>
#include <iostream>
#include <string>

#include <silkworm/infra/concurrency/task.hpp>

#include <absl/flags/flag.h>
#include <absl/flags/parse.h>
#include <absl/flags/usage.h>
#include <absl/strings/match.h>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/signal_set.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/db/kv/api/state_cache.hpp>
#include <silkworm/db/kv/grpc/client/remote_client.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/grpc/client/client_context_pool.hpp>
#include <silkworm/infra/grpc/common/util.hpp>
#include <silkworm/interfaces/remote/ethbackend.grpc.pb.h>
#include <silkworm/interfaces/remote/kv.grpc.pb.h>
#include <silkworm/interfaces/types/types.pb.h>
#include <silkworm/rpc/common/constants.hpp>
#include <silkworm/rpc/ethbackend/remote_backend.hpp>
#include <silkworm/rpc/ethdb/kv/backend_providers.hpp>

using namespace silkworm;
using namespace silkworm::db::kv::api;
using namespace silkworm::rpc;

std::string h160_address_to_string(const types::H160& address) {
    std::stringstream out;
    out << "address=" << address.has_hi();
    if (address.has_hi()) {
        auto& hi_half = address.hi();
        out << std::hex << hi_half.hi() << hi_half.lo();
    } else {
        auto lo_half = address.lo();
        out << std::hex << lo_half;
    }
    out << std::dec;
    return out.str();
}

std::ostream& operator<<(std::ostream& out, const types::H160& address) {
    out << h160_address_to_string(address);
    return out;
}

int ethbackend_sync(const std::string& target) {
    // Create ETHBACKEND stub using insecure channel to target
    grpc::Status status;

    const auto channel = grpc::CreateChannel(target, grpc::InsecureChannelCredentials());
    const auto stub = remote::ETHBACKEND::NewStub(channel);

    grpc::ClientContext eb_context;
    remote::EtherbaseReply eb_reply;
    std::cout << "ETHBACKEND Etherbase ->\n";
    status = stub->Etherbase(&eb_context, remote::EtherbaseRequest{}, &eb_reply);
    if (status.ok()) {
        std::cout << "ETHBACKEND Etherbase <- " << status << " address: " << eb_reply.address() << "\n";
    } else {
        std::cout << "ETHBACKEND Etherbase <- " << status << "\n";
    }

    grpc::ClientContext nv_context;
    remote::NetVersionReply nv_reply;
    std::cout << "ETHBACKEND NetVersion ->\n";
    status = stub->NetVersion(&nv_context, remote::NetVersionRequest{}, &nv_reply);
    if (status.ok()) {
        std::cout << "ETHBACKEND NetVersion <- " << status << " id: " << nv_reply.id() << "\n";
    } else {
        std::cout << "ETHBACKEND NetVersion <- " << status << "\n";
    }

    grpc::ClientContext v_context;
    types::VersionReply v_reply;
    std::cout << "ETHBACKEND Version ->\n";
    status = stub->Version(&v_context, google::protobuf::Empty{}, &v_reply);
    if (status.ok()) {
        std::cout << "ETHBACKEND Version <- " << status << " major.minor.patch: " << v_reply.major() << "." << v_reply.minor() << "." << v_reply.patch() << "\n";
    } else {
        std::cout << "ETHBACKEND Version <- " << status << "\n";
    }

    grpc::ClientContext pv_context;
    remote::ProtocolVersionReply pv_reply;
    std::cout << "ETHBACKEND ProtocolVersion ->\n";
    status = stub->ProtocolVersion(&pv_context, remote::ProtocolVersionRequest{}, &pv_reply);
    if (status.ok()) {
        std::cout << "ETHBACKEND ProtocolVersion <- " << status << " id: " << pv_reply.id() << "\n";
    } else {
        std::cout << "ETHBACKEND ProtocolVersion <- " << status << "\n";
    }

    grpc::ClientContext cv_context;
    remote::ClientVersionReply cv_reply;
    std::cout << "ETHBACKEND ClientVersion ->\n";
    status = stub->ClientVersion(&cv_context, remote::ClientVersionRequest{}, &cv_reply);
    if (status.ok()) {
        std::cout << "ETHBACKEND ClientVersion <- " << status << " node name: " << cv_reply.node_name() << "\n";
    } else {
        std::cout << "ETHBACKEND ClientVersion <- " << status << "\n";
    }

    return 0;
}

int ethbackend_async(const std::string& target) {
    // Create ETHBACKEND stub using insecure channel to target
    grpc::CompletionQueue queue;
    grpc::Status status;
    void* got_tag{nullptr};
    bool ok{false};

    const auto channel = grpc::CreateChannel(target, grpc::InsecureChannelCredentials());
    const auto stub = remote::ETHBACKEND::NewStub(channel);

    // Etherbase
    grpc::ClientContext eb_context;
    const auto eb_reader = stub->PrepareAsyncEtherbase(&eb_context, remote::EtherbaseRequest{}, &queue);

    eb_reader->StartCall();
    std::cout << "ETHBACKEND Etherbase ->\n";
    remote::EtherbaseReply eb_reply;
    eb_reader->Finish(&eb_reply, &status, eb_reader.get());
    bool has_event = queue.Next(&got_tag, &ok);
    if (!has_event || got_tag != eb_reader.get()) {
        return -1;
    }
    if (status.ok()) {
        std::cout << "ETHBACKEND Etherbase <- " << status << " address: " << eb_reply.has_address() << "\n";
    } else {
        std::cout << "ETHBACKEND Etherbase <- " << status << "\n";
    }

    // NetVersion
    grpc::ClientContext nv_context;
    const auto nv_reader = stub->PrepareAsyncNetVersion(&nv_context, remote::NetVersionRequest{}, &queue);

    nv_reader->StartCall();
    std::cout << "ETHBACKEND NetVersion ->\n";
    remote::NetVersionReply nv_reply;
    nv_reader->Finish(&nv_reply, &status, nv_reader.get());
    has_event = queue.Next(&got_tag, &ok);
    if (!has_event || got_tag != nv_reader.get()) {
        return -1;
    }
    if (status.ok()) {
        std::cout << "ETHBACKEND NetVersion <- " << status << " id: " << nv_reply.id() << "\n";
    } else {
        std::cout << "ETHBACKEND NetVersion <- " << status << "\n";
    }

    // Version
    grpc::ClientContext v_context;
    const auto v_reader = stub->PrepareAsyncVersion(&v_context, google::protobuf::Empty{}, &queue);

    v_reader->StartCall();
    std::cout << "ETHBACKEND Version ->\n";
    types::VersionReply v_reply;
    v_reader->Finish(&v_reply, &status, v_reader.get());
    has_event = queue.Next(&got_tag, &ok);
    if (!has_event || got_tag != v_reader.get()) {
        return -1;
    }
    if (status.ok()) {
        std::cout << "ETHBACKEND Version <- " << status << " major.minor.patch: " << v_reply.major() << "." << v_reply.minor() << "." << v_reply.patch() << "\n";
    } else {
        std::cout << "ETHBACKEND Version <- " << status << "\n";
    }

    // ProtocolVersion
    grpc::ClientContext pv_context;
    const auto pv_reader = stub->PrepareAsyncProtocolVersion(&pv_context, remote::ProtocolVersionRequest{}, &queue);

    pv_reader->StartCall();
    std::cout << "ETHBACKEND ProtocolVersion ->\n";
    remote::ProtocolVersionReply pv_reply;
    pv_reader->Finish(&pv_reply, &status, pv_reader.get());
    has_event = queue.Next(&got_tag, &ok);
    if (!has_event || got_tag != pv_reader.get()) {
        return -1;
    }
    if (status.ok()) {
        std::cout << "ETHBACKEND ProtocolVersion <- " << status << " id: " << pv_reply.id() << "\n";
    } else {
        std::cout << "ETHBACKEND ProtocolVersion <- " << status << "\n";
    }

    // ClientVersion
    grpc::ClientContext cv_context;
    const auto cv_reader = stub->PrepareAsyncClientVersion(&cv_context, remote::ClientVersionRequest{}, &queue);

    cv_reader->StartCall();
    std::cout << "ETHBACKEND ClientVersion ->\n";
    remote::ClientVersionReply cv_reply;
    cv_reader->Finish(&cv_reply, &status, cv_reader.get());
    has_event = queue.Next(&got_tag, &ok);
    if (!has_event || got_tag != cv_reader.get()) {
        return -1;
    }
    if (status.ok()) {
        std::cout << "ETHBACKEND ClientVersion <- " << status << " node name: " << cv_reply.node_name() << "\n";
    } else {
        std::cout << "ETHBACKEND ClientVersion <- " << status << "\n";
    }

    return 0;
}

Task<void> ethbackend_etherbase(ethbackend::BackEnd& backend) {
    try {
        std::cout << "ETHBACKEND Etherbase ->\n";
        const auto address = co_await backend.etherbase();
        std::cout << "ETHBACKEND Etherbase <- address: " << address << "\n";
    } catch (const std::exception& e) {
        std::cout << "ETHBACKEND Etherbase <- error: " << e.what() << "\n";
    }
}

int ethbackend_coroutines(const std::string& target) {
    try {
        ClientContextPool context_pool{1};
        auto& context = context_pool.next_context();
        auto ioc = context.ioc();
        auto grpc_context = context.grpc_context();

        boost::asio::signal_set signals(*ioc, SIGINT, SIGTERM);
        signals.async_wait([&](const boost::system::error_code& error, int signal_number) {
            std::cout << "Signal caught, error: " << error.message() << " number: " << signal_number << std::endl
                      << std::flush;
            context_pool.stop();
        });

        const auto channel = grpc::CreateChannel(target, grpc::InsecureChannelCredentials());

        // Etherbase
        ethbackend::RemoteBackEnd eth_backend{channel, *grpc_context};
        boost::asio::co_spawn(*ioc, ethbackend_etherbase(eth_backend), [&](std::exception_ptr) {
            context_pool.stop();
        });

        context_pool.run();
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n"
                  << std::flush;
    } catch (...) {
        std::cerr << "Unexpected exception\n"
                  << std::flush;
    }
    return 0;
}

int kv_seek(const std::string& target, const std::string& table_name, silkworm::ByteView key) {
    // Create KV stub using insecure channel to target
    grpc::ClientContext context;

    const auto channel = grpc::CreateChannel(target, grpc::InsecureChannelCredentials());
    const auto stub = remote::KV::NewStub(channel);
    const auto reader_writer = stub->Tx(&context);
    std::cout << "KV Tx START\n";

    // Read TX identifier
    auto tx_id_pair = remote::Pair{};
    auto success = reader_writer->Read(&tx_id_pair);
    if (!success) {
        std::cerr << "KV stream closed receiving TXID\n";
        std::cout << "KV Tx STATUS: " << reader_writer->Finish() << "\n";
        return -1;
    }
    const auto tx_id = tx_id_pair.cursor_id();
    std::cout << "KV Tx START <- txid: " << tx_id << "\n";

    // Open cursor
    auto open_message = remote::Cursor{};
    open_message.set_op(remote::Op::OPEN);
    open_message.set_bucket_name(table_name);
    success = reader_writer->Write(open_message);
    if (!success) {
        std::cerr << "KV stream closed sending OPEN operation req\n";
        std::cout << "KV Tx STATUS: " << reader_writer->Finish() << "\n";
        return -1;
    }
    std::cout << "KV Tx OPEN -> table_name: " << table_name << "\n";
    auto open_pair = remote::Pair{};
    success = reader_writer->Read(&open_pair);
    if (!success) {
        std::cerr << "KV stream closed receiving OPEN operation rsp\n";
        std::cout << "KV Tx STATUS: " << reader_writer->Finish() << "\n";
        return -1;
    }
    auto cursor_id = open_pair.cursor_id();
    std::cout << "KV Tx OPEN <- cursor: " << cursor_id << "\n";

    // Seek given key in given table
    auto seek_message = remote::Cursor{};
    seek_message.set_op(remote::Op::SEEK);
    seek_message.set_cursor(cursor_id);
    seek_message.set_k(key.data(), key.size());
    success = reader_writer->Write(seek_message);
    if (!success) {
        std::cerr << "KV stream closed sending SEEK operation req\n";
        std::cout << "KV Tx STATUS: " << reader_writer->Finish() << "\n";
        return -1;
    }
    std::cout << "KV Tx SEEK -> cursor: " << cursor_id << " key: " << key << "\n";
    auto seek_pair = remote::Pair{};
    success = reader_writer->Read(&seek_pair);
    if (!success) {
        std::cerr << "KV stream closed receiving SEEK operation rsp\n";
        std::cout << "KV Tx STATUS: " << reader_writer->Finish() << "\n";
        return -1;
    }
    const auto& rsp_key = silkworm::string_view_to_byte_view(seek_pair.k());
    const auto& rsp_value = silkworm::string_view_to_byte_view(seek_pair.v());
    std::cout << "KV Tx SEEK <- key: " << rsp_key << " value: " << rsp_value << std::endl;

    // Close cursor
    auto close_message = remote::Cursor{};
    close_message.set_op(remote::Op::CLOSE);
    close_message.set_cursor(cursor_id);
    success = reader_writer->Write(close_message);
    if (!success) {
        std::cerr << "KV stream closed sending CLOSE operation req\n";
        std::cout << "KV Tx STATUS: " << reader_writer->Finish() << "\n";
        return -1;
    }
    std::cout << "KV Tx CLOSE -> cursor: " << cursor_id << "\n";
    auto close_pair = remote::Pair{};
    success = reader_writer->Read(&close_pair);
    if (!success) {
        std::cerr << "KV stream closed receiving CLOSE operation rsp\n";
        std::cout << "KV Tx STATUS: " << reader_writer->Finish() << "\n";
        return -1;
    }
    std::cout << "KV Tx CLOSE <- cursor: " << close_pair.cursor_id() << "\n";

    reader_writer->WritesDone();
    grpc::Status status = reader_writer->Finish();
    std::cout << "KV Tx STATUS: " << status << "\n";

    return 0;
}

int kv_seek_async(const std::string& target, const std::string& table_name, silkworm::ByteView key, uint32_t timeout) {
    // Create KV stub using insecure channel to target
    grpc::ClientContext context;
    grpc::CompletionQueue queue;
    grpc::Status status;
    void* got_tag{nullptr};
    bool ok{false};

    const auto channel = grpc::CreateChannel(target, grpc::InsecureChannelCredentials());
    const auto stub = remote::KV::NewStub(channel);

    // Prepare RPC call context and stream
    context.set_deadline(std::chrono::system_clock::system_clock::now() + std::chrono::milliseconds{timeout});
    const auto reader_writer = stub->PrepareAsyncTx(&context, &queue);

    void* start_tag = reinterpret_cast<void*>(0);
    void* open_tag = reinterpret_cast<void*>(1);
    void* seek_tag = reinterpret_cast<void*>(2);
    void* close_tag = reinterpret_cast<void*>(3);
    void* finish_tag = reinterpret_cast<void*>(4);

    // 1) StartCall
    std::cout << "KV Tx START\n";
    // 1.1) StartCall + Next
    reader_writer->StartCall(start_tag);
    bool has_event = queue.Next(&got_tag, &ok);
    if (!has_event || got_tag != start_tag) {
        return -1;
    }
    // 1.2) Read + Next
    auto tx_id_pair = remote::Pair{};
    reader_writer->Read(&tx_id_pair, start_tag);
    has_event = queue.Next(&got_tag, &ok);
    if (!has_event || got_tag != start_tag) {
        return -1;
    }
    const auto tx_id = tx_id_pair.cursor_id();
    std::cout << "KV Tx START <- txid: " << tx_id << "\n";

    // 2) Open cursor
    std::cout << "KV Tx OPEN -> table_name: " << table_name << "\n";
    // 2.1) Write + Next
    auto open_message = remote::Cursor{};
    open_message.set_op(remote::Op::OPEN);
    open_message.set_bucket_name(table_name);
    reader_writer->Write(open_message, open_tag);
    has_event = queue.Next(&got_tag, &ok);
    if (!has_event || got_tag != open_tag) {
        return -1;
    }
    // 2.2) Read + Next
    auto open_pair = remote::Pair{};
    reader_writer->Read(&open_pair, open_tag);
    has_event = queue.Next(&got_tag, &ok);
    if (!has_event || got_tag != open_tag) {
        return -1;
    }
    auto cursor_id = open_pair.cursor_id();
    std::cout << "KV Tx OPEN <- cursor: " << cursor_id << "\n";

    // 3) Seek given key in given table
    std::cout << "KV Tx SEEK -> cursor: " << cursor_id << " key: " << key << "\n";
    // 3.1) Write + Next
    auto seek_message = remote::Cursor{};
    seek_message.set_op(remote::Op::SEEK);
    seek_message.set_cursor(cursor_id);
    seek_message.set_k(key.data(), key.size());
    reader_writer->Write(seek_message, seek_tag);
    has_event = queue.Next(&got_tag, &ok);
    if (!has_event || got_tag != seek_tag) {
        return -1;
    }
    // 3.2) Read + Next
    auto seek_pair = remote::Pair{};
    reader_writer->Read(&seek_pair, seek_tag);
    has_event = queue.Next(&got_tag, &ok);
    if (!has_event || got_tag != seek_tag) {
        return -1;
    }
    const auto& key_bytes = silkworm::string_view_to_byte_view(seek_pair.k());
    const auto& value_bytes = silkworm::string_view_to_byte_view(seek_pair.v());
    std::cout << "KV Tx SEEK <- key: " << key_bytes << " value: " << value_bytes << std::endl;

    // 4) Close cursor
    std::cout << "KV Tx CLOSE -> cursor: " << cursor_id << "\n";
    // 4.1) Write + Next
    auto close_message = remote::Cursor{};
    close_message.set_op(remote::Op::CLOSE);
    close_message.set_cursor(cursor_id);
    reader_writer->Write(close_message, close_tag);
    has_event = queue.Next(&got_tag, &ok);
    if (!has_event || got_tag != close_tag) {
        return -1;
    }
    // 4.2) Read + Next
    auto close_pair = remote::Pair{};
    reader_writer->Read(&close_pair, close_tag);
    has_event = queue.Next(&got_tag, &ok);
    if (!has_event || got_tag != close_tag) {
        return -1;
    }
    std::cout << "KV Tx CLOSE <- cursor: " << close_pair.cursor_id() << "\n";

    // 5) Finish
    reader_writer->Finish(&status, finish_tag);
    if (!status.ok()) {
        std::cout << "KV Tx Status <- error_code: " << status.error_code() << "\n";
        std::cout << "KV Tx Status <- error_message: " << status.error_message() << "\n";
        std::cout << "KV Tx Status <- error_details: " << status.error_details() << "\n";
        return -1;
    }

    return 0;
}

class GrpcKvCallbackReactor final : public grpc::ClientBidiReactor<remote::Cursor, remote::Pair> {
  public:
    explicit GrpcKvCallbackReactor(remote::KV::Stub& stub, std::chrono::milliseconds timeout) : stub_(stub) {
        context_.set_deadline(std::chrono::system_clock::now() + timeout);
        stub_.experimental_async()->Tx(&context_, this);
        StartCall();
    }

    void read_start(std::function<void(bool, remote::Pair)> read_completed) {
        read_completed_ = std::move(read_completed);
        StartRead(&pair_);
    }

    void write_start(remote::Cursor* cursor, std::function<void(bool)> write_completed) {
        write_completed_ = std::move(write_completed);
        StartWrite(cursor);
    }

    void OnReadDone(bool ok) override {
        read_completed_(ok, pair_);
    }

    void OnWriteDone(bool ok) override {
        write_completed_(ok);
    }

  private:
    remote::KV::Stub& stub_;
    grpc::ClientContext context_;
    remote::Pair pair_;
    std::function<void(bool, remote::Pair)> read_completed_;
    std::function<void(bool)> write_completed_;
};

int kv_seek_async_callback(const std::string& target, const std::string& table_name, silkworm::ByteView key, uint32_t timeout) {
    boost::asio::io_context ioc;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{ioc.get_executor()};

    const auto channel = grpc::CreateChannel(target, grpc::InsecureChannelCredentials());
    auto stub = remote::KV::NewStub(channel);

    boost::asio::signal_set signals(ioc, SIGINT, SIGTERM);
    signals.async_wait([&](const boost::system::error_code& error, int signal_number) {
        std::cout << "Signal caught, error: " << error.message() << " number: " << signal_number << std::endl
                  << std::flush;
        ioc.stop();
    });

    GrpcKvCallbackReactor reactor{*stub, std::chrono::milliseconds{timeout}};

    std::cout << "KV Tx START\n";
    reactor.read_start([&](bool tx_id_read_ok, const remote::Pair& tx_id_pair) {
        if (!tx_id_read_ok) {
            std::cout << "KV Tx error reading tx ID" << std::flush;
            return;
        }
        const auto tx_id = tx_id_pair.cursor_id();
        std::cout << "KV Tx START <- tx_id: " << tx_id << "\n";
        auto open_message = remote::Cursor{};
        open_message.set_op(remote::Op::OPEN);
        open_message.set_bucket_name(table_name);
        reactor.write_start(&open_message, [&](bool open_write_ok) {
            if (!open_write_ok) {
                std::cout << "error writing OPEN gRPC" << std::flush;
                return;
            }
            std::cout << "KV Tx OPEN -> table_name: " << table_name << "\n";
            reactor.read_start([&](bool open_read_ok, const remote::Pair& open_pair) {
                if (!open_read_ok) {
                    std::cout << "error reading OPEN gRPC" << std::flush;
                    return;
                }
                const auto cursor_id = open_pair.cursor_id();
                std::cout << "KV Tx OPEN <- cursor: " << cursor_id << "\n";
                auto seek_message = remote::Cursor{};
                seek_message.set_op(remote::Op::SEEK);
                seek_message.set_cursor(cursor_id);
                seek_message.set_k(key.data(), key.size());
                reactor.write_start(&seek_message, [&, cursor_id](bool seek_write_ok) {
                    if (!seek_write_ok) {
                        std::cout << "error writing SEEK gRPC" << std::flush;
                        return;
                    }
                    std::cout << "KV Tx SEEK -> cursor: " << cursor_id << " key: " << key << "\n";
                    reactor.read_start([&, cursor_id](bool seek_read_ok, const remote::Pair& seek_pair) {
                        if (!seek_read_ok) {
                            std::cout << "error reading SEEK gRPC" << std::flush;
                            return;
                        }
                        const auto& key_bytes = silkworm::string_view_to_byte_view(seek_pair.k());
                        const auto& value_bytes = silkworm::string_view_to_byte_view(seek_pair.v());
                        std::cout << "KV Tx SEEK <- key: " << key_bytes << " value: " << value_bytes << std::endl;
                        auto close_message = remote::Cursor{};
                        close_message.set_op(remote::Op::CLOSE);
                        close_message.set_cursor(cursor_id);
                        reactor.write_start(&close_message, [&, cursor_id](bool close_write_ok) {
                            if (!close_write_ok) {
                                std::cout << "error writing CLOSE gRPC" << std::flush;
                                return;
                            }
                            std::cout << "KV Tx CLOSE -> cursor: " << cursor_id << "\n";
                            reactor.read_start([&](bool close_read_ok, const remote::Pair& close_pair) {
                                if (!close_read_ok) {
                                    std::cout << "error reading CLOSE gRPC" << std::flush;
                                    return;
                                }
                                std::cout << "KV Tx CLOSE <- cursor: " << close_pair.cursor_id() << "\n";
                                ioc.stop();
                            });
                        });
                    });
                });
            });
        });
    });

    ioc.run();

    return 0;
}

int kv_seek_both(const std::string& target, const std::string& table_name, silkworm::ByteView key, silkworm::ByteView subkey) {
    // Create KV stub using insecure channel to target
    grpc::ClientContext context;

    const auto channel = grpc::CreateChannel(target, grpc::InsecureChannelCredentials());
    const auto stub = remote::KV::NewStub(channel);
    const auto reader_writer = stub->Tx(&context);
    std::cout << "KV Tx START\n";

    // Read TX identifier
    auto tx_id_pair = remote::Pair{};
    auto success = reader_writer->Read(&tx_id_pair);
    if (!success) {
        std::cerr << "KV stream closed receiving TXID\n";
        std::cout << "KV Tx STATUS: " << reader_writer->Finish() << "\n";
        return -1;
    }
    const auto tx_id = tx_id_pair.cursor_id();
    std::cout << "KV Tx START <- txid: " << tx_id << "\n";

    // Open cursor
    auto open_message = remote::Cursor{};
    open_message.set_op(remote::Op::OPEN);
    open_message.set_bucket_name(table_name);
    success = reader_writer->Write(open_message);
    if (!success) {
        std::cerr << "KV stream closed sending OPEN operation req\n";
        std::cout << "KV Tx STATUS: " << reader_writer->Finish() << "\n";
        return -1;
    }
    std::cout << "KV Tx OPEN -> table_name: " << table_name << "\n";
    auto open_pair = remote::Pair{};
    success = reader_writer->Read(&open_pair);
    if (!success) {
        std::cerr << "KV stream closed receiving OPEN operation rsp\n";
        std::cout << "KV Tx STATUS: " << reader_writer->Finish() << "\n";
        return -1;
    }
    auto cursor_id = open_pair.cursor_id();
    std::cout << "KV Tx OPEN <- cursor: " << cursor_id << "\n";

    // Seek given key in given table
    auto seek_both_message = remote::Cursor{};
    seek_both_message.set_op(remote::Op::SEEK_BOTH);
    seek_both_message.set_cursor(cursor_id);
    seek_both_message.set_k(key.data(), key.size());
    seek_both_message.set_v(subkey.data(), subkey.size());
    success = reader_writer->Write(seek_both_message);
    if (!success) {
        std::cerr << "KV stream closed sending SEEK_BOTH operation req\n";
        std::cout << "KV Tx STATUS: " << reader_writer->Finish() << "\n";
        return -1;
    }
    std::cout << "KV Tx SEEK_BOTH -> cursor: " << cursor_id << " key: " << key << " subkey: " << subkey << "\n";
    auto seek_both_pair = remote::Pair{};
    success = reader_writer->Read(&seek_both_pair);
    if (!success) {
        std::cerr << "KV stream closed receiving SEEK_BOTH operation rsp\n";
        std::cout << "KV Tx STATUS: " << reader_writer->Finish() << "\n";
        return -1;
    }
    const auto& rsp_key = silkworm::string_view_to_byte_view(seek_both_pair.k());
    const auto& rsp_value = silkworm::string_view_to_byte_view(seek_both_pair.v());
    std::cout << "KV Tx SEEK_BOTH <- key: " << rsp_key << " value: " << rsp_value << std::endl;

    // Close cursor
    auto close_message = remote::Cursor{};
    close_message.set_op(remote::Op::CLOSE);
    close_message.set_cursor(cursor_id);
    success = reader_writer->Write(close_message);
    if (!success) {
        std::cerr << "KV stream closed sending CLOSE operation req\n";
        std::cout << "KV Tx STATUS: " << reader_writer->Finish() << "\n";
        return -1;
    }
    std::cout << "KV Tx CLOSE -> cursor: " << cursor_id << "\n";
    auto close_pair = remote::Pair{};
    success = reader_writer->Read(&close_pair);
    if (!success) {
        std::cerr << "KV stream closed receiving CLOSE operation rsp\n";
        std::cout << "KV Tx STATUS: " << reader_writer->Finish() << "\n";
        return -1;
    }
    std::cout << "KV Tx CLOSE <- cursor: " << close_pair.cursor_id() << "\n";

    reader_writer->WritesDone();
    grpc::Status status = reader_writer->Finish();
    std::cout << "KV Tx STATUS: " << status << "\n";

    return 0;
}

ABSL_FLAG(std::string, key, "", "key as hex string w/o leading 0x");
ABSL_FLAG(std::string, seekkey, "", "seek key as hex string w/o leading 0x");
ABSL_FLAG(std::string, subkey, "", "subkey as hex string w/o leading 0x");
ABSL_FLAG(std::string, tool, "", "gRPC remote interface tool name as string");
ABSL_FLAG(std::string, target, std::string{kDefaultPrivateApiAddr}, "Silkworm location as string <address>:<port>");
ABSL_FLAG(std::string, table, "", "database table name as string");
ABSL_FLAG(int, limit, -1, "max number of items returned by Temporal KV range queries");
ABSL_FLAG(std::string, from_key, "", "start lookup key as hex string w/o leading 0x");
ABSL_FLAG(std::string, to_key, "", "end lookup key as hex string w/o leading 0x");
ABSL_FLAG(int64_t, timestamp, -1, "history timestamp for Temporal KV domain_range query");
ABSL_FLAG(uint32_t, timeout, kDefaultTimeout.count(), "gRPC call timeout as integer");
ABSL_FLAG(bool, verbose, false, "verbose output");

int ethbackend_async() {
    auto target{absl::GetFlag(FLAGS_target)};
    if (target.empty() || !absl::StrContains(target, ":")) {
        std::cerr << "Parameter target is invalid: [" << target << "]\n";
        std::cerr << "Use --target flag to specify the location of Erigon running instance\n";
        return -1;
    }

    return ethbackend_async(target);
}

int ethbackend_coroutines() {
    auto target{absl::GetFlag(FLAGS_target)};
    if (target.empty() || !absl::StrContains(target, ":")) {
        std::cerr << "Parameter target is invalid: [" << target << "]\n";
        std::cerr << "Use --target flag to specify the location of Erigon running instance\n";
        return -1;
    }

    return ethbackend_coroutines(target);
}

int ethbackend_sync() {
    auto target{absl::GetFlag(FLAGS_target)};
    if (target.empty() || !absl::StrContains(target, ":")) {
        std::cerr << "Parameter target is invalid: [" << target << "]\n";
        std::cerr << "Use --target flag to specify the location of Erigon running instance\n";
        return -1;
    }

    return ethbackend_sync(target);
}

int kv_seek_async_callback() {
    auto target{absl::GetFlag(FLAGS_target)};
    if (target.empty() || !absl::StrContains(target, ":")) {
        std::cerr << "Parameter target is invalid: [" << target << "]\n";
        std::cerr << "Use --target flag to specify the location of Erigon running instance\n";
        return -1;
    }

    auto table_name{absl::GetFlag(FLAGS_table)};
    if (table_name.empty()) {
        std::cerr << "Parameter table is invalid: [" << table_name << "]\n";
        std::cerr << "Use --table flag to specify the name of Erigon database table\n";
        return -1;
    }

    auto key{absl::GetFlag(FLAGS_key)};
    const auto key_bytes = silkworm::from_hex(key);
    if (key.empty() || !key_bytes.has_value()) {
        std::cerr << "Parameter key is invalid: [" << key << "]\n";
        std::cerr << "Use --key flag to specify the key in key-value dupsort table\n";
        return -1;
    }

    auto timeout{absl::GetFlag(FLAGS_timeout)};

    return kv_seek_async_callback(target, table_name, key_bytes.value(), timeout);
}

int kv_seek_async() {
    auto target{absl::GetFlag(FLAGS_target)};
    if (target.empty() || !absl::StrContains(target, ":")) {
        std::cerr << "Parameter target is invalid: [" << target << "]\n";
        std::cerr << "Use --target flag to specify the location of Erigon running instance\n";
        return -1;
    }

    auto table_name{absl::GetFlag(FLAGS_table)};
    if (table_name.empty()) {
        std::cerr << "Parameter table is invalid: [" << table_name << "]\n";
        std::cerr << "Use --table flag to specify the name of Erigon database table\n";
        return -1;
    }

    auto key{absl::GetFlag(FLAGS_key)};
    const auto key_bytes = silkworm::from_hex(key);
    if (key.empty() || !key_bytes.has_value()) {
        std::cerr << "Parameter key is invalid: [" << key << "]\n";
        std::cerr << "Use --key flag to specify the key in key-value dupsort table\n";
        return -1;
    }

    auto timeout{absl::GetFlag(FLAGS_timeout)};

    return kv_seek_async(target, table_name, key_bytes.value(), timeout);
}

int kv_seek_both() {
    auto target{absl::GetFlag(FLAGS_target)};
    if (target.empty() || !absl::StrContains(target, ":")) {
        std::cerr << "Parameter target is invalid: [" << target << "]\n";
        std::cerr << "Use --target flag to specify the location of Erigon running instance\n";
        return -1;
    }

    auto table_name{absl::GetFlag(FLAGS_table)};
    if (table_name.empty()) {
        std::cerr << "Parameter table is invalid: [" << table_name << "]\n";
        std::cerr << "Use --table flag to specify the name of Erigon database table\n";
        return -1;
    }

    auto key{absl::GetFlag(FLAGS_key)};
    const auto key_bytes = silkworm::from_hex(key);
    if (key.empty() || !key_bytes.has_value()) {
        std::cerr << "Parameter key is invalid: [" << key << "]\n";
        std::cerr << "Use --key flag to specify the key in key-value dupsort table\n";
        return -1;
    }

    auto subkey{absl::GetFlag(FLAGS_subkey)};
    const auto subkey_bytes = silkworm::from_hex(subkey);
    if (subkey.empty() || !subkey_bytes.has_value()) {
        std::cerr << "Parameter subkey is invalid: [" << subkey << "]\n";
        std::cerr << "Use --subkey flag to specify the subkey in key-value dupsort table\n";
        return -1;
    }

    return kv_seek_both(target, table_name, key_bytes.value(), subkey_bytes.value());
}

int kv_seek() {
    auto target{absl::GetFlag(FLAGS_target)};
    if (target.empty() || !absl::StrContains(target, ":")) {
        std::cerr << "Parameter target is invalid: [" << target << "]\n";
        std::cerr << "Use --target flag to specify the location of Erigon running instance\n";
        return -1;
    }

    auto table_name{absl::GetFlag(FLAGS_table)};
    if (table_name.empty()) {
        std::cerr << "Parameter table is invalid: [" << table_name << "]\n";
        std::cerr << "Use --table flag to specify the name of Erigon database table\n";
        return -1;
    }

    auto key{absl::GetFlag(FLAGS_key)};
    const auto key_bytes = silkworm::from_hex(key);
    if (key.empty() || !key_bytes.has_value()) {
        std::cerr << "Parameter key is invalid: [" << key << "]\n";
        std::cerr << "Use --key flag to specify the key in key-value dupsort table\n";
        return -1;
    }

    return kv_seek(target, table_name, key_bytes.value());
}

Task<void> kv_get_latest_query(const std::shared_ptr<Service>& kv_service,
                               GetLatestRequest request,
                               const bool /*verbose*/) {
    try {
        auto tx = co_await kv_service->begin_transaction();
        std::cout << "KV GetLatest -> " << request.table << " key=" << to_hex(request.key) << " latest=true\n";
        const auto result = co_await tx->get_latest(std::move(request));
        std::cout << "KV GetLatest <- success: " << result.success << " value=" << to_hex(result.value) << "\n";
        co_await tx->close();
    } catch (const std::exception& e) {
        std::cout << "KV GetLatest <- error: " << e.what() << "\n";
    }
}

Task<void> kv_get_as_of_query(const std::shared_ptr<Service>& kv_service,
                              GetAsOfRequest request,
                              const bool /*verbose*/) {
    try {
        auto tx = co_await kv_service->begin_transaction();
        std::cout << "KV GetLatest -> " << request.table << " key=" << to_hex(request.key)
                  << " ts=" << request.timestamp << " latest=false\n";
        const auto result = co_await tx->get_as_of(std::move(request));
        std::cout << "KV GetLatest <- success: " << result.success << " value=" << to_hex(result.value) << "\n";
        co_await tx->close();
    } catch (const std::exception& e) {
        std::cout << "KV GetLatest <- error: " << e.what() << "\n";
    }
}

Task<void> kv_history_seek_query(const std::shared_ptr<Service>& kv_service,
                                 HistoryPointRequest request,
                                 const bool /*verbose*/) {
    try {
        auto tx = co_await kv_service->begin_transaction();
        std::cout << "KV HistorySeek -> " << request.table << " key=" << to_hex(request.key) << " ts=" << request.timestamp << "\n";
        const auto result = co_await tx->history_seek(std::move(request));
        std::cout << "KV HistorySeek <- success: " << result.success << " value=" << to_hex(result.value) << "\n";
        co_await tx->close();
    } catch (const std::exception& e) {
        std::cout << "KV HistorySeek <- error: " << e.what() << "\n";
    }
}

Task<void> kv_index_range_query(const std::shared_ptr<Service>& kv_service,
                                IndexRangeRequest request,
                                const bool verbose) {
    try {
        auto tx = co_await kv_service->begin_transaction();
        std::cout << "KV IndexRange -> " << request.table << "\n";
        auto paginated_result = co_await tx->index_range(std::move(request));
        auto it = co_await paginated_result.begin();
        std::cout << "KV IndexRange <- #timestamps: ";
        int count{0};
        ListOfTimestamp timestamps;
        while (const auto value = co_await it->next()) {
            timestamps.emplace_back(*value);
            ++count;
        }
        std::cout << count << "\n";
        if (verbose) {
            for (const auto ts : timestamps) {
                std::cout << ts << "\n";
            }
        }
        co_await tx->close();
    } catch (const std::exception& e) {
        std::cout << "KV IndexRange <- error: " << e.what() << "\n";
    }
}

Task<void> kv_history_range_query(const std::shared_ptr<Service>& kv_service,
                                  HistoryRangeRequest request,
                                  const bool verbose) {
    try {
        auto tx = co_await kv_service->begin_transaction();
        std::cout << "KV HistoryRange -> " << request.table << " limit=" << request.limit << "\n";
        auto paginated_result = co_await tx->history_range(std::move(request));
        auto it = co_await paginated_result.begin();
        std::cout << "KV HistoryRange <- #keys and #values: ";
        int count{0};
        std::vector<KeyValue> keys_and_values;
        while (const auto key_value = co_await it->next()) {
            keys_and_values.emplace_back(*key_value);
            ++count;
        }
        std::cout << count << "\n";
        if (verbose) {
            for (const auto& key_value_pair : keys_and_values) {
                std::cout << "k=" << to_hex(key_value_pair.key) << " v=" << to_hex(key_value_pair.value) << "\n";
            }
        }
        co_await tx->close();
    } catch (const std::exception& e) {
        std::cout << "KV HistoryRange <- error: " << e.what() << "\n";
    }
}

Task<void> kv_range_as_of_query(const std::shared_ptr<Service>& kv_service,
                                DomainRangeRequest request,
                                const bool verbose) {
    try {
        auto tx = co_await kv_service->begin_transaction();
        std::cout << "KV RangeAsOf -> " << request.table << " limit=" << request.limit << "\n";
        auto paginated_result = co_await tx->range_as_of(std::move(request));
        auto it = co_await paginated_result.begin();
        std::cout << "KV RangeAsOf <- #keys and #values: ";
        int count{0};
        std::vector<KeyValue> keys_and_values;
        while (const auto key_value = co_await it->next()) {
            keys_and_values.emplace_back(*key_value);
            ++count;
        }
        std::cout << count << "\n";
        if (verbose) {
            for (const auto& key_value_pair : keys_and_values) {
                std::cout << "k=" << to_hex(key_value_pair.key) << " v=" << to_hex(key_value_pair.value) << "\n";
            }
        }
        co_await tx->close();
    } catch (const std::exception& e) {
        std::cout << "KV RangeAsOf <- error: " << e.what() << "\n";
    }
}

template <typename Q>
using KVQueryFunc = Task<void> (*)(const std::shared_ptr<Service>&, Q, bool);

template <typename Q>
int execute_temporal_kv_query(const std::string& target, KVQueryFunc<Q> query_func, Q&& query, const bool verbose) {
    try {
        ClientContextPool context_pool{1};
        auto& context = context_pool.next_context();
        auto ioc = context.ioc();
        auto grpc_context = context.grpc_context();

        boost::asio::signal_set signals(*ioc, SIGINT, SIGTERM);
        signals.async_wait([&](const boost::system::error_code& error, int signal_number) {
            std::cout << "Signal caught, error: " << error.message() << " number: " << signal_number << std::endl
                      << std::flush;
            context_pool.stop();
        });

        auto channel_factory = [target]() -> std::shared_ptr<::grpc::Channel> {
            return ::grpc::CreateChannel(target, grpc::InsecureChannelCredentials());
        };

        // ETHBACKEND
        ethbackend::RemoteBackEnd eth_backend{channel_factory(), *grpc_context};
        // DB KV API client
        CoherentStateCache state_cache;
        db::kv::grpc::client::RemoteClient client{channel_factory,
                                                  *grpc_context,
                                                  &state_cache,
                                                  ethdb::kv::make_backend_providers(&eth_backend)};
        auto kv_service = client.service();

        boost::asio::co_spawn(*ioc, query_func(kv_service, std::forward<Q>(query), verbose), [&](std::exception_ptr) {
            context_pool.stop();
        });

        context_pool.run();
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
    } catch (...) {
        std::cerr << "Unexpected exception\n";
    }
    return 0;
}

int kv_get_latest() {
    const auto target{absl::GetFlag(FLAGS_target)};
    if (target.empty() || !absl::StrContains(target, ":")) {
        std::cerr << "Parameter target is invalid: [" << target << "]\n";
        std::cerr << "Use --target flag to specify the location of Erigon running instance in <host>:<port> format\n";
        return -1;
    }

    const auto table_name{absl::GetFlag(FLAGS_table)};
    if (table_name.empty()) {
        std::cerr << "Parameter table is invalid: [" << table_name << "]\n";
        std::cerr << "Use --table flag to specify the name of Erigon database table\n";
        return -1;
    }

    const auto key{absl::GetFlag(FLAGS_key)};
    const auto key_bytes = silkworm::from_hex(key);
    if (key.empty() || !key_bytes.has_value()) {
        std::cerr << "Parameter key is invalid: [" << key << "]\n";
        std::cerr << "Use --key flag to specify the start key in key-value table as hex string\n";
        return -1;
    }

    const auto timestamp{absl::GetFlag(FLAGS_timestamp)};
    if (timestamp < -1) {
        std::cerr << "Parameter timestamp is invalid: [" << timestamp << "]\n";
        std::cerr << "Use --timestamp flag to specify the timestamp for TKV domain_get query\n";
        return -1;
    }

    const auto verbose{absl::GetFlag(FLAGS_verbose)};

    if (timestamp > -1) {
        GetAsOfRequest query{
            .table = table_name,
            .key = *key_bytes,
            .timestamp = timestamp,
        };
        return execute_temporal_kv_query(target, kv_get_as_of_query, std::move(query), verbose);
    }
    GetLatestRequest query{
        .table = table_name,
        .key = *key_bytes,
    };
    return execute_temporal_kv_query(target, kv_get_latest_query, std::move(query), verbose);
}

int kv_history_seek() {
    const auto target{absl::GetFlag(FLAGS_target)};
    if (target.empty() || !absl::StrContains(target, ":")) {
        std::cerr << "Parameter target is invalid: [" << target << "]\n";
        std::cerr << "Use --target flag to specify the location of Erigon running instance in <host>:<port> format\n";
        return -1;
    }

    const auto table_name{absl::GetFlag(FLAGS_table)};
    if (table_name.empty()) {
        std::cerr << "Parameter table is invalid: [" << table_name << "]\n";
        std::cerr << "Use --table flag to specify the name of Erigon database table\n";
        return -1;
    }

    const auto key{absl::GetFlag(FLAGS_key)};
    const auto key_bytes = silkworm::from_hex(key);
    if (key.empty() || !key_bytes.has_value()) {
        std::cerr << "Parameter key is invalid: [" << key << "]\n";
        std::cerr << "Use --key flag to specify the start key in key-value table as hex string\n";
        return -1;
    }

    const auto timestamp{absl::GetFlag(FLAGS_timestamp)};
    if (timestamp < -1) {
        std::cerr << "Parameter timestamp is invalid: [" << timestamp << "]\n";
        std::cerr << "Use --timestamp flag to specify the history timestamp for TKV history_seek query\n";
        return -1;
    }

    const auto verbose{absl::GetFlag(FLAGS_verbose)};

    HistoryPointRequest query{
        .table = table_name,
        .key = *key_bytes,
        .timestamp = timestamp,
    };
    return execute_temporal_kv_query(target, kv_history_seek_query, std::move(query), verbose);
}

int kv_index_range() {
    const auto target{absl::GetFlag(FLAGS_target)};
    if (target.empty() || !absl::StrContains(target, ":")) {
        std::cerr << "Parameter target is invalid: [" << target << "]\n";
        std::cerr << "Use --target flag to specify the location of Erigon running instance in <host>:<port> format\n";
        return -1;
    }

    const auto table_name{absl::GetFlag(FLAGS_table)};
    if (table_name.empty()) {
        std::cerr << "Parameter table is invalid: [" << table_name << "]\n";
        std::cerr << "Use --table flag to specify the name of Erigon database table\n";
        return -1;
    }

    const auto key{absl::GetFlag(FLAGS_key)};
    const auto key_bytes = silkworm::from_hex(key);
    if (key.empty() || !key_bytes.has_value()) {
        std::cerr << "Parameter key is invalid: [" << key << "]\n";
        std::cerr << "Use --key flag to specify the start key in key-value table as hex string\n";
        return -1;
    }

    const auto limit{absl::GetFlag(FLAGS_limit)};
    if (limit < -1) {
        std::cerr << "Parameter limit is invalid: [" << limit << "]\n";
        std::cerr << "Use --limit flag to specify the max number of items returned by TKV queries (-1 means no limit)\n";
        return -1;
    }

    const auto verbose{absl::GetFlag(FLAGS_verbose)};

    IndexRangeRequest query{
        .table = table_name,
        .key = *key_bytes,
        .from_timestamp = 0,
        .to_timestamp = -1,
        .ascending_order = true,
        .limit = limit,
    };
    return execute_temporal_kv_query(target, kv_index_range_query, std::move(query), verbose);
}

int kv_history_range() {
    const auto target{absl::GetFlag(FLAGS_target)};
    if (target.empty() || !absl::StrContains(target, ":")) {
        std::cerr << "Parameter target is invalid: [" << target << "]\n";
        std::cerr << "Use --target flag to specify the location of Erigon running instance in <host>:<port> format\n";
        return -1;
    }

    const auto table_name{absl::GetFlag(FLAGS_table)};
    if (table_name.empty()) {
        std::cerr << "Parameter table is invalid: [" << table_name << "]\n";
        std::cerr << "Use --table flag to specify the name of Erigon database table\n";
        return -1;
    }

    const auto limit{absl::GetFlag(FLAGS_limit)};
    if (limit < -1) {
        std::cerr << "Parameter limit is invalid: [" << limit << "]\n";
        std::cerr << "Use --limit flag to specify the max number of items returned by TKV queries (-1 means no limit)\n";
        return -1;
    }

    const auto verbose{absl::GetFlag(FLAGS_verbose)};

    HistoryRangeRequest query{
        .table = table_name,
        .from_timestamp = 0,
        .to_timestamp = -1,
        .ascending_order = true,
        .limit = limit,
    };
    return execute_temporal_kv_query(target, kv_history_range_query, std::move(query), verbose);
}

int kv_get_as_of() {
    const auto target{absl::GetFlag(FLAGS_target)};
    if (target.empty() || !absl::StrContains(target, ":")) {
        std::cerr << "Parameter target is invalid: [" << target << "]\n";
        std::cerr << "Use --target flag to specify the location of Erigon running instance in <host>:<port> format\n";
        return -1;
    }

    const auto table_name{absl::GetFlag(FLAGS_table)};
    if (table_name.empty()) {
        std::cerr << "Parameter table is invalid: [" << table_name << "]\n";
        std::cerr << "Use --table flag to specify the name of Erigon database table\n";
        return -1;
    }

    const auto from_key{absl::GetFlag(FLAGS_from_key)};
    const auto from_key_bytes = silkworm::from_hex(from_key);
    if (from_key.empty() || !from_key_bytes.has_value()) {
        std::cerr << "Parameter from_key is invalid: [" << from_key << "]\n";
        std::cerr << "Use --from_key flag to specify the start key in key-value table lookup as hex string\n";
        return -1;
    }

    const auto to_key{absl::GetFlag(FLAGS_to_key)};
    const auto to_key_bytes = silkworm::from_hex(to_key);
    if (to_key.empty() || !to_key_bytes.has_value()) {
        std::cerr << "Parameter to_key is invalid: [" << to_key << "]\n";
        std::cerr << "Use --to_key flag to specify the end key in key-value table lookup as hex string\n";
        return -1;
    }

    const auto timestamp{absl::GetFlag(FLAGS_timestamp)};
    if (timestamp < -1) {
        std::cerr << "Parameter timestamp is invalid: [" << timestamp << "]\n";
        std::cerr << "Use --timestamp flag to specify the history timestamp for TKV domain_range query (-1 means latest)\n";
        return -1;
    }

    const auto limit{absl::GetFlag(FLAGS_limit)};
    if (limit < -1) {
        std::cerr << "Parameter limit is invalid: [" << limit << "]\n";
        std::cerr << "Use --limit flag to specify the max number of items returned by TKV queries (-1 means no limit)\n";
        return -1;
    }

    const auto verbose{absl::GetFlag(FLAGS_verbose)};

    DomainRangeRequest query{
        .table = table_name,
        .from_key = *from_key_bytes,
        .to_key = *to_key_bytes,
        .timestamp = timestamp > -1 ? std::make_optional(timestamp) : std::nullopt,
        .ascending_order = true,
        .limit = limit,
    };
    return execute_temporal_kv_query(target, kv_range_as_of_query, std::move(query), verbose);
}

int main(int argc, char* argv[]) {
    absl::SetProgramUsageMessage(
        "Execute specified internal gRPC I/F tool:\n"
        "\tethbackend\t\t\tquery the Erigon/Silkworm ETHBACKEND remote interface\n"
        "\tethbackend_async\t\tquery the Erigon/Silkworm ETHBACKEND remote interface\n"
        "\tethbackend_coroutines\t\tquery the Erigon/Silkworm ETHBACKEND remote interface\n"
        "\tkv_seek\t\t\t\tquery using SEEK the Erigon/Silkworm Key-Value (KV) remote interface to database\n"
        "\tkv_seek_async\t\t\tquery using SEEK the Erigon/Silkworm Key-Value (KV) remote interface to database\n"
        "\tkv_seek_async_callback\t\tquery using SEEK the Erigon/Silkworm Key-Value (KV) remote interface to database\n"
        "\tkv_seek_both\t\t\tquery using SEEK_BOTH the Erigon/Silkworm Key-Value (KV) remote interface to database\n"
        "\tkv_get_latest\t\tquery the Erigon/Silkworm Key-Value (KV) remote interface to data storage using DOMAIN_GET\n"
        "\tkv_history_seek\t\tquery using HISTORY_SEEK the Erigon/Silkworm Key-Value (KV) remote interface to data storage\n"
        "\tkv_index_range\t\tquery using INDEX_RANGE the Erigon/Silkworm Key-Value (KV) remote interface to data storage\n"
        "\tkv_history_range\t\tquery using HISTORY_RANGE the Erigon/Silkworm Key-Value (KV) remote interface to data storage\n"
        "\tkv_get_as_of\t\tquery using DOMAIN_RANGE the Erigon/Silkworm Key-Value (KV) remote interface to data storage\n");
    const auto positional_args = absl::ParseCommandLine(argc, argv);
    if (positional_args.size() < 2) {
        std::cerr << "No gRPC tool specified as first positional argument\n\n";
        std::cerr << absl::ProgramUsageMessage();
        return -1;
    }

    log::set_verbosity(log::Level::kCritical);

    const std::string tool{positional_args[1]};
    if (tool == "ethbackend_async") {
        return ethbackend_async();
    }
    if (tool == "ethbackend_coroutines") {
        return ethbackend_coroutines();
    }
    if (tool == "ethbackend") {
        return ethbackend_sync();
    }
    if (tool == "kv_seek_async_callback") {
        return kv_seek_async_callback();
    }
    if (tool == "kv_seek_async") {
        return kv_seek_async();
    }
    if (tool == "kv_seek_both") {
        return kv_seek_both();
    }
    if (tool == "kv_seek") {
        return kv_seek();
    }
    if (tool == "kv_get_latest") {
        return kv_get_latest();
    }
    if (tool == "kv_history_seek") {
        return kv_history_seek();
    }
    if (tool == "kv_index_range") {
        return kv_index_range();
    }
    if (tool == "kv_history_range") {
        return kv_history_range();
    }
    if (tool == "kv_get_as_of") {
        return kv_get_as_of();
    }

    std::cerr << "Unknown tool " << tool << " specified as first argument\n\n";
    std::cerr << absl::ProgramUsageMessage();
    return -1;
}
