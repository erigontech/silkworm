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

#include "backend_server.hpp"

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
};

namespace silkworm::rpc {

// TODO(canepat): better copy grpc_pick_unused_port_or_die to generate unused port
constexpr const char* kTestAddressUri = "localhost:12345";

TEST_CASE("BackEndServer::BackEndServer", "[silkworm][node][rpc]") {
    silkworm::log::set_verbosity(silkworm::log::Level::kNone);
    Grpc2SilkwormLogGuard log_guard;

    SECTION("OK: create/destroy server", "[silkworm][node][rpc]") {
        ServerConfig srv_config;
        srv_config.set_address_uri(kTestAddressUri);
        BackEndServer server{srv_config, kGoerliConfig};
    }

    SECTION("OK: create/shutdown/destroy server", "[silkworm][node][rpc]") {
        ServerConfig srv_config;
        srv_config.set_address_uri(kTestAddressUri);
        BackEndServer server{srv_config, kGoerliConfig};
        server.shutdown();
    }
}

TEST_CASE("BackEndServer::run", "[silkworm][node][rpc]") {
    silkworm::log::set_verbosity(silkworm::log::Level::kNone);
    Grpc2SilkwormLogGuard log_guard;

    SECTION("OK: run server in separate thread", "[silkworm][node][rpc]") {
        ServerConfig srv_config;
        srv_config.set_address_uri(kTestAddressUri);
        BackEndServer server{srv_config, kGoerliConfig};
        std::thread server_thread{[&server]() {
            server.run();
        }};
        server.shutdown();
        server_thread.join();
    }

    SECTION("OK: create/shutdown/run/destroy server", "[silkworm][node][rpc]") {
        ServerConfig srv_config;
        srv_config.set_address_uri(kTestAddressUri);
        BackEndServer server{srv_config, kGoerliConfig};
        server.shutdown();
        server.run();
    }
}

TEST_CASE("BackEndServer::shutdown", "[silkworm][node][rpc]") {
    silkworm::log::set_verbosity(silkworm::log::Level::kNone);
    Grpc2SilkwormLogGuard log_guard;

    SECTION("OK: shutdown server not running", "[silkworm][node][rpc]") {
        ServerConfig srv_config;
        srv_config.set_address_uri(kTestAddressUri);
        BackEndServer server{srv_config, kGoerliConfig};
        server.shutdown();
    }

    SECTION("OK: shutdown twice server not running", "[silkworm][node][rpc]") {
        ServerConfig srv_config;
        srv_config.set_address_uri(kTestAddressUri);
        BackEndServer server{srv_config, kGoerliConfig};
        server.shutdown();
        server.shutdown();
    }

    SECTION("OK: shutdown running server", "[silkworm][node][rpc]") {
        ServerConfig srv_config;
        srv_config.set_address_uri(kTestAddressUri);
        BackEndServer server{srv_config, kGoerliConfig};
        std::thread shutdown_thread{[&server]() {
            std::this_thread::yield();
            server.shutdown();
        }};
        server.run();
        shutdown_thread.join();
    }

    SECTION("OK: shutdown twice running server", "[silkworm][node][rpc]") {
        ServerConfig srv_config;
        srv_config.set_address_uri(kTestAddressUri);
        BackEndServer server{srv_config, kGoerliConfig};
        std::thread shutdown_thread1{[&server]() {
            std::this_thread::yield();
            server.shutdown();
        }};
        std::thread shutdown_thread2{[&server]() {
            std::this_thread::yield();
            server.shutdown();
        }};
        server.run();
        shutdown_thread1.join();
        shutdown_thread2.join();
    }
}

TEST_CASE("BackEndServer RPC calls", "[silkworm][node][rpc]") {
    silkworm::log::set_verbosity(silkworm::log::Level::kNone);
    Grpc2SilkwormLogGuard log_guard;
    std::shared_ptr<grpc::Channel> channel = grpc::CreateChannel(kTestAddressUri, grpc::InsecureChannelCredentials());
    auto stub_ptr = remote::ETHBACKEND::NewStub(channel);
    BackEndClient backend_client{stub_ptr.get()};
    ServerConfig srv_config;
    srv_config.set_num_contexts(1);
    srv_config.set_address_uri(kTestAddressUri);
    BackEndServer server{srv_config, kGoerliConfig};
    std::thread server_thread{[&server]() {
        server.run();
    }};

    SECTION("Etherbase: return coinbase address", "[silkworm][node][rpc]") {
        remote::EtherbaseReply response;
        const auto status = backend_client.etherbase(&response);
        CHECK(status == grpc::Status::OK);
        CHECK(response.has_address());
        CHECK(response.address() == types::H160());
    }

    SECTION("NetVersion: return network ID", "[silkworm][node][rpc]") {
        remote::NetVersionReply response;
        const auto status = backend_client.net_version(&response);
        CHECK(status == grpc::Status::OK);
        CHECK(response.id() == kGoerliConfig.chain_id);
    }

    SECTION("NetPeerCount: return peer count", "[silkworm][node][rpc]") {
        remote::NetPeerCountReply response;
        const auto status = backend_client.net_peer_count(&response);
        CHECK(status == grpc::Status::OK);
        CHECK(response.count() == 0);
    }

    SECTION("Version: return ETHBACKEND version", "[silkworm][node][rpc]") {
        types::VersionReply response;
        const auto status = backend_client.version(&response);
        CHECK(status == grpc::Status::OK);
        CHECK(response.major() == 2);
        CHECK(response.minor() == 2);
        CHECK(response.patch() == 0);
    }

    SECTION("ProtocolVersion: return ETH protocol version", "[silkworm][node][rpc]") {
        remote::ProtocolVersionReply response;
        const auto status = backend_client.protocol_version(&response);
        CHECK(status == grpc::Status::OK);
        CHECK(response.id() == kEthDevp2pProtocolVersion);
    }

    SECTION("ClientVersion: return Silkworm client version", "[silkworm][node][rpc]") {
        remote::ClientVersionReply response;
        const auto status = backend_client.client_version(&response);
        CHECK(status == grpc::Status::OK);
        CHECK(response.nodename().find("silkworm") != std::string::npos);
    }

    // TODO(canepat): change using something meaningful when really implemented
    SECTION("Subscribe: return streamed subscriptions", "[silkworm][node][rpc]") {
        remote::SubscribeRequest request;
        std::vector<remote::SubscribeReply> responses;
        const auto status = backend_client.subscribe_and_consume(request, responses);
        CHECK(status == grpc::Status::OK);
        CHECK(responses.size() == 2);
    }

    SECTION("NodeInfo: return information about nodes", "[silkworm][node][rpc]") {
        remote::NodesInfoRequest request;
        request.set_limit(0);
        remote::NodesInfoReply response;
        const auto status = backend_client.node_info(request, &response);
        CHECK(status == grpc::Status::OK);
        CHECK(response.nodesinfo_size() == 0);
    }

    server.shutdown();
    server_thread.join();
}

} // namespace silkworm::rpc
