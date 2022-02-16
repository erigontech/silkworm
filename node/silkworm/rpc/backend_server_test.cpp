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

#include <catch2/catch.hpp>
#include <grpc/grpc.h>

#include <silkworm/common/log.hpp>
#include <silkworm/rpc/util.hpp>
#include <types/types.pb.h>

// operator== overloading for grpc::Status is *NOT* present in gRPC library
namespace grpc {
inline bool operator==(const Status& lhs, const Status& rhs) {
    return lhs.error_code() == rhs.error_code() &&
        lhs.error_message() == rhs.error_message() &&
        lhs.error_details() == rhs.error_details();
}
} // namespace grpc

// operator== overloading is *NOT* present in gRPC generated sources
namespace types {
inline bool operator==(const H160& lhs, const H160& rhs) {
    return lhs.hi().hi() == rhs.hi().hi() &&
        lhs.hi().lo() == rhs.hi().lo() &&
        lhs.lo() == rhs.lo();
}
} // namespace types

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
            server.shutdown();
        }};
        server.run();
        shutdown_thread.join();
    }
}

TEST_CASE("BackEndServer RPC calls", "[silkworm][node][rpc]") {
    silkworm::log::set_verbosity(silkworm::log::Level::kNone);
    Grpc2SilkwormLogGuard log_guard;
    std::shared_ptr<grpc::Channel> channel = grpc::CreateChannel(kTestAddressUri, grpc::InsecureChannelCredentials());
    auto stub_ptr = remote::ETHBACKEND::NewStub(channel);
    BackEndClient client{stub_ptr.get()};
    ServerConfig srv_config;
    srv_config.set_num_contexts(1);
    srv_config.set_address_uri(kTestAddressUri);
    BackEndServer server{srv_config, kGoerliConfig};
    std::thread server_thread{[&server]() {
        server.run();
    }};

    SECTION("Etherbase: return coinbase address", "[silkworm][node][rpc]") {
        remote::EtherbaseReply response;
        const auto status = client.etherbase(&response);
        CHECK(status == grpc::Status::OK);
        CHECK(response.has_address());
        CHECK(response.address() == types::H160());
    }

    SECTION("NetVersion: return network ID", "[silkworm][node][rpc]") {
        remote::NetVersionReply response;
        const auto status = client.net_version(&response);
        CHECK(status == grpc::Status::OK);
        CHECK(response.id() == kGoerliConfig.chain_id);
    }

    server.shutdown();
    server_thread.join();
}

} // namespace silkworm::rpc
