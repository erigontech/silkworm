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

#include "backend_kv_server.hpp"

#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <catch2/catch.hpp>
#include <grpc/grpc.h>

#include <silkworm/common/log.hpp>
#include <silkworm/rpc/util.hpp>
#include <types/types.pb.h>

namespace { // Trick suggested by gRPC team to avoid name clashes in multiple test modules
class BackEndClient {
  public:
    explicit BackEndClient(remote::ETHBACKEND::StubInterface* stub) : stub_(stub) {}

    grpc::Status etherbase(remote::EtherbaseReply* response) {
        grpc::ClientContext context;
        return stub_->Etherbase(&context, remote::EtherbaseRequest{}, response);
    }

    grpc::Status net_version(remote::NetVersionReply* response) {
        grpc::ClientContext context;
        return stub_->NetVersion(&context, remote::NetVersionRequest{}, response);
    }

    grpc::Status net_peer_count(remote::NetPeerCountReply* response) {
        grpc::ClientContext context;
        return stub_->NetPeerCount(&context, remote::NetPeerCountRequest{}, response);
    }

    grpc::Status version(types::VersionReply* response) {
        grpc::ClientContext context;
        return stub_->Version(&context, google::protobuf::Empty{}, response);
    }

    grpc::Status protocol_version(remote::ProtocolVersionReply* response) {
        grpc::ClientContext context;
        return stub_->ProtocolVersion(&context, remote::ProtocolVersionRequest{}, response);
    }

    grpc::Status client_version(remote::ClientVersionReply* response) {
        grpc::ClientContext context;
        return stub_->ClientVersion(&context, remote::ClientVersionRequest{}, response);
    }

    grpc::Status subscribe_and_consume(const remote::SubscribeRequest& request, std::vector<remote::SubscribeReply>& responses) {
        grpc::ClientContext context;
        auto subscribe_reply_reader = stub_->Subscribe(&context, request);
        bool has_more{true};
        do {
            has_more = subscribe_reply_reader->Read(&responses.emplace_back());
        } while (has_more);
        responses.pop_back();
        return subscribe_reply_reader->Finish();
    }

    grpc::Status node_info(const remote::NodesInfoRequest& request, remote::NodesInfoReply* response) {
        grpc::ClientContext context;
        return stub_->NodeInfo(&context, request, response);
    }

  private:
    remote::ETHBACKEND::StubInterface* stub_;
};

class KvClient {
  public:
    explicit KvClient(remote::KV::StubInterface* stub) : stub_(stub) {}

    grpc::Status version(types::VersionReply* response) {
        grpc::ClientContext context;
        return stub_->Version(&context, google::protobuf::Empty{}, response);
    }

    grpc::Status tx(std::vector<remote::Cursor>& requests, std::vector<remote::Pair>& responses) {
        grpc::ClientContext context;
        auto tx_reader_writer = stub_->Tx(&context);
        uint32_t cursor_id{0};
        for (auto& req : requests) {
            req.set_cursor(cursor_id);
            tx_reader_writer->Write(req);
            tx_reader_writer->Read(&responses.emplace_back());
            cursor_id = responses.back().cursorid();
        }
        tx_reader_writer->WritesDone();
        return tx_reader_writer->Finish();
    }

    grpc::Status statechanges_and_consume(const remote::StateChangeRequest& request, std::vector<remote::StateChangeBatch>& responses) {
        grpc::ClientContext context;
        auto subscribe_reply_reader = stub_->StateChanges(&context, request);
        bool has_more{true};
        do {
            has_more = subscribe_reply_reader->Read(&responses.emplace_back());
        } while (has_more);
        responses.pop_back();
        return subscribe_reply_reader->Finish();
    }

  private:
    remote::KV::StubInterface* stub_;
};
} // namespace anonymous

namespace silkworm::rpc {

// TODO(canepat): better copy grpc_pick_unused_port_or_die to generate unused port
constexpr const char* kTestAddressUri = "localhost:12345";

TEST_CASE("BackEndKvServer::BackEndKvServer", "[silkworm][node][rpc]") {
    silkworm::log::set_verbosity(silkworm::log::Level::kNone);
    Grpc2SilkwormLogGuard log_guard;
    ServerConfig srv_config;
    srv_config.set_address_uri(kTestAddressUri);
    EthereumBackEnd backend;

    SECTION("OK: create/destroy server", "[silkworm][node][rpc]") {
        BackEndKvServer server{srv_config, backend};
    }

    SECTION("OK: create/shutdown/destroy server", "[silkworm][node][rpc]") {
        BackEndKvServer server{srv_config, backend};
        server.shutdown();
    }
}

TEST_CASE("BackEndKvServer::build_and_start", "[silkworm][node][rpc]") {
    silkworm::log::set_verbosity(silkworm::log::Level::kNone);
    Grpc2SilkwormLogGuard log_guard;
    ServerConfig srv_config;
    srv_config.set_address_uri(kTestAddressUri);
    EthereumBackEnd backend;

    SECTION("OK: run server in separate thread", "[silkworm][node][rpc]") {
        BackEndKvServer server{srv_config, backend};
        server.build_and_start();
        std::thread server_thread{[&server]() {
            server.join();
        }};
        server.shutdown();
        server_thread.join();
    }

    SECTION("OK: create/shutdown/run/destroy server", "[silkworm][node][rpc]") {
        BackEndKvServer server{srv_config, backend};
        server.shutdown();
        server.build_and_start();
    }
}

TEST_CASE("BackEndKvServer::shutdown", "[silkworm][node][rpc]") {
    silkworm::log::set_verbosity(silkworm::log::Level::kNone);
    Grpc2SilkwormLogGuard log_guard;
    ServerConfig srv_config;
    srv_config.set_address_uri(kTestAddressUri);
    EthereumBackEnd backend;

    SECTION("OK: shutdown server not running", "[silkworm][node][rpc]") {
        BackEndKvServer server{srv_config, backend};
        server.shutdown();
    }

    SECTION("OK: shutdown twice server not running", "[silkworm][node][rpc]") {
        BackEndKvServer server{srv_config, backend};
        server.shutdown();
        server.shutdown();
    }

    SECTION("OK: shutdown running server", "[silkworm][node][rpc]") {
        BackEndKvServer server{srv_config, backend};
        server.build_and_start();
        server.shutdown();
    }

    SECTION("OK: shutdown twice running server", "[silkworm][node][rpc]") {
        BackEndKvServer server{srv_config, backend};
        server.build_and_start();
        server.shutdown();
        server.shutdown();
    }
}

TEST_CASE("BackEndKvServer::join", "[silkworm][node][rpc]") {
    silkworm::log::set_verbosity(silkworm::log::Level::kNone);
    Grpc2SilkwormLogGuard log_guard;
    ServerConfig srv_config;
    srv_config.set_address_uri(kTestAddressUri);
    EthereumBackEnd backend;

    SECTION("OK: shutdown joined server", "[silkworm][node][rpc]") {
        BackEndKvServer server{srv_config, backend};
        server.build_and_start();
        std::thread server_thread{[&server]() {
            server.join();
        }};
        server.shutdown();
        server_thread.join();
    }
}

TEST_CASE("BackEndKvServer: RPC basic config", "[silkworm][node][rpc]") {
    silkworm::log::set_verbosity(silkworm::log::Level::kNone);
    Grpc2SilkwormLogGuard log_guard;
    std::shared_ptr<grpc::Channel> channel = grpc::CreateChannel(kTestAddressUri, grpc::InsecureChannelCredentials());
    auto ethbackend_stub_ptr = remote::ETHBACKEND::NewStub(channel);
    BackEndClient backend_client{ethbackend_stub_ptr.get()};
    auto kv_stub_ptr = remote::KV::NewStub(channel);
    KvClient kv_client{kv_stub_ptr.get()};
    ServerConfig srv_config;
    srv_config.set_num_contexts(1);
    srv_config.set_address_uri(kTestAddressUri);
    EthereumBackEnd backend;
    BackEndKvServer server{srv_config, backend};
    server.build_and_start();

    SECTION("Etherbase: return missing coinbase error", "[silkworm][node][rpc]") {
        remote::EtherbaseReply response;
        const auto status = backend_client.etherbase(&response);
        CHECK(!status.ok());
        CHECK(status.error_code() == grpc::StatusCode::INTERNAL);
        CHECK(status.error_message() == "etherbase must be explicitly specified");
        CHECK(!response.has_address());
    }

    SECTION("NetVersion: return network ID", "[silkworm][node][rpc]") {
        remote::NetVersionReply response;
        const auto status = backend_client.net_version(&response);
        CHECK(status.ok());
        CHECK(response.id() == kMainnetConfig.chain_id);
    }

    SECTION("NetPeerCount: return zero peer count", "[silkworm][node][rpc]") {
        remote::NetPeerCountReply response;
        const auto status = backend_client.net_peer_count(&response);
        CHECK(status.ok());
        CHECK(response.count() == 0);
    }

    SECTION("Version: return ETHBACKEND version", "[silkworm][node][rpc]") {
        types::VersionReply response;
        const auto status = backend_client.version(&response);
        CHECK(status.ok());
        CHECK(response.major() == 2);
        CHECK(response.minor() == 2);
        CHECK(response.patch() == 0);
    }

    SECTION("ProtocolVersion: return ETH protocol version", "[silkworm][node][rpc]") {
        remote::ProtocolVersionReply response;
        const auto status = backend_client.protocol_version(&response);
        CHECK(status.ok());
        CHECK(response.id() == kEthDevp2pProtocolVersion);
    }

    SECTION("ClientVersion: return Silkworm client version", "[silkworm][node][rpc]") {
        remote::ClientVersionReply response;
        const auto status = backend_client.client_version(&response);
        CHECK(status.ok());
        CHECK(response.nodename().find("silkworm") != std::string::npos);
    }

    // TODO(canepat): change using something meaningful when really implemented
    SECTION("Subscribe: return streamed subscriptions", "[silkworm][node][rpc]") {
        remote::SubscribeRequest request;
        std::vector<remote::SubscribeReply> responses;
        const auto status = backend_client.subscribe_and_consume(request, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 2);
    }

    SECTION("NodeInfo: return information about zero nodes", "[silkworm][node][rpc]") {
        remote::NodesInfoRequest request;
        request.set_limit(0);
        remote::NodesInfoReply response;
        const auto status = backend_client.node_info(request, &response);
        CHECK(status.ok());
        CHECK(response.nodesinfo_size() == 0);
    }

    SECTION("Version: return KV version", "[silkworm][node][rpc]") {
        types::VersionReply response;
        const auto status = kv_client.version(&response);
        CHECK(status.ok());
        CHECK(response.major() == 5);
        CHECK(response.minor() == 1);
        CHECK(response.patch() == 0);
    }

    // TODO(canepat): change using something meaningful when really implemented
    SECTION("Tx: return streamed pairs", "[silkworm][node][rpc]") {
        remote::SubscribeRequest request;
        remote::Cursor open;
        open.set_op(remote::Op::OPEN);
        open.set_bucketname("TestTable");
        remote::Cursor next;
        next.set_op(remote::Op::NEXT);
        remote::Cursor close;
        close.set_op(remote::Op::CLOSE);
        std::vector<remote::Cursor> requests{open, next, close};
        std::vector<remote::Pair> responses;
        const auto status = kv_client.tx(requests, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 3);
    }

    // TODO(canepat): change using something meaningful when really implemented
    SECTION("StateChanges: return streamed state changes", "[silkworm][node][rpc]") {
        remote::StateChangeRequest request;
        std::vector<remote::StateChangeBatch> responses;
        const auto status = kv_client.statechanges_and_consume(request, responses);
        CHECK(status.ok());
        CHECK(responses.size() == 2);
    }

    server.shutdown();
    server.join();
}

namespace {
const uint64_t kTestSentryPeerCount{10};
constexpr const char* kTestSentryPeerId{"peer_id"};
constexpr const char* kTestSentryPeerName{"peer_name"};

class SentryService : public sentry::Sentry::Service {
  public:
    explicit SentryService(grpc::Status status) : status_(status) {}

    std::unique_ptr<grpc::Server> build_and_start(const std::string& server_address) {
        grpc::ServerBuilder builder;
        builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
        builder.RegisterService(this);
        return builder.BuildAndStart();
    }

    grpc::Status PeerCount(::grpc::ServerContext* /*context*/, const ::sentry::PeerCountRequest* /*request*/, ::sentry::PeerCountReply* response) override {
        if (status_.ok()) {
            response->set_count(kTestSentryPeerCount);
        }
        return status_;
    }

    grpc::Status NodeInfo(::grpc::ServerContext* /*context*/, const ::google::protobuf::Empty* /*request*/, ::types::NodeInfoReply* response) override {
        response->set_id(kTestSentryPeerId);
        response->set_name(kTestSentryPeerName);
        return status_;
    }

  private:
    grpc::Status status_;
};
} // namespace anonymous

TEST_CASE("BackEndKvServer: RPC custom config", "[silkworm][node][rpc]") {
    silkworm::log::set_verbosity(silkworm::log::Level::kNone);
    Grpc2SilkwormLogGuard log_guard;
    std::shared_ptr<grpc::Channel> channel = grpc::CreateChannel(kTestAddressUri, grpc::InsecureChannelCredentials());
    auto ethbackend_stub_ptr = remote::ETHBACKEND::NewStub(channel);
    BackEndClient backend_client{ethbackend_stub_ptr.get()};
    auto kv_stub_ptr = remote::KV::NewStub(channel);
    KvClient kv_client{kv_stub_ptr.get()};
    ServerConfig srv_config;
    srv_config.set_num_contexts(1);
    srv_config.set_address_uri(kTestAddressUri);
    constexpr const char* kTestSentry1AddressUri = "localhost:54321";
    constexpr const char* kTestSentry2AddressUri = "localhost:54322";
    SentryService sentry_service1{grpc::Status::OK};
    auto sentry_server1 = sentry_service1.build_and_start(kTestSentry1AddressUri);
    SentryService sentry_service2{grpc::Status::OK};
    auto sentry_server2 = sentry_service2.build_and_start(kTestSentry2AddressUri);
    EthereumBackEnd backend;
    backend.set_etherbase(evmc::address{});
    backend.add_sentry_address(kTestSentry1AddressUri);
    backend.add_sentry_address(kTestSentry2AddressUri);
    BackEndKvServer server{srv_config, backend};
    server.build_and_start();

    SECTION("Etherbase: return coinbase address", "[silkworm][node][rpc]") {
        remote::EtherbaseReply response;
        const auto status = backend_client.etherbase(&response);
        CHECK(status.ok());
        CHECK(response.has_address());
        CHECK(response.address() == types::H160());
    }

    /*SECTION("NetPeerCount: return peer count", "[silkworm][node][rpc]") {
        remote::NetPeerCountReply response;
        const auto status = backend_client.net_peer_count(&response);
        CHECK(status.ok());
        CHECK(response.count() == 2 * kTestSentryPeerCount);
    }

    SECTION("NodeInfo: return information about nodes", "[silkworm][node][rpc]") {
        remote::NodesInfoRequest request;
        request.set_limit(0);
        remote::NodesInfoReply response;
        const auto status = backend_client.node_info(request, &response);
        CHECK(status.ok());
        CHECK(response.nodesinfo_size() == 2);
        for (int i{0}; i<response.nodesinfo_size(); i++) {
            const types::NodeInfoReply& nodes_info = response.nodesinfo(i);
            CHECK(nodes_info.id() == kTestSentryPeerId);
            CHECK(nodes_info.name() == kTestSentryPeerName);
        }
    }*/

    sentry_server1->Shutdown();
    sentry_server1->Wait();
    sentry_server2->Shutdown();
    sentry_server2->Wait();
    server.shutdown();
    server.join();
}

} // namespace silkworm::rpc
