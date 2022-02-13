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

#include "server.hpp"

#include <thread>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <catch2/catch.hpp>
#include <grpc/grpc.h>
#include <grpcpp/impl/codegen/service_type.h>

#include <silkworm/common/log.hpp>
#include <silkworm/rpc/util.hpp>

namespace silkworm::rpc {

class MockService : public grpc::Service {
};

class EmptyServer : public Server<MockService> {
  public:
    EmptyServer(const ServerConfig& config) : Server(config) {}

  protected:
    void request_calls() override {}
};

constexpr const char* kTestAddressUri = "localhost:12345";

TEST_CASE("Server::Server", "[silkworm][node][rpc]") {
    silkworm::log::set_verbosity(silkworm::log::Level::kNone);

    SECTION("KO: Address already in use", "[silkworm][node][rpc]") {
        GrpcNoLogGuard guard;

        boost::asio::io_context io_context;
        boost::asio::ip::tcp::endpoint endpoint{boost::asio::ip::tcp::v4(), 12345};
        boost::asio::ip::tcp::acceptor acceptor{io_context, endpoint};
        ServerConfig config;
        config.set_address_uri(kTestAddressUri);
        CHECK_THROWS_AS(EmptyServer(config), std::runtime_error);
    }

    SECTION("KO: Name or service not known", "[silkworm][node][rpc]") {
        GrpcNoLogGuard guard;

        ServerConfig config;
        config.set_address_uri("localhost@12345");
        CHECK_THROWS_AS(EmptyServer(config), std::runtime_error);
    }

    SECTION("OK: create and start Server", "[silkworm][node][rpc]") {
        ServerConfig config;
        config.set_address_uri(kTestAddressUri);
        EmptyServer server{config};
    }
}

TEST_CASE("Server::run", "[silkworm][node][rpc]") {
    silkworm::log::set_verbosity(silkworm::log::Level::kTrace);

    // TODO(canepat): use GMock
    class TestServer : public Server<MockService> {
      public:
        TestServer(const ServerConfig& config) : Server(config) {}
        bool accept_requests_called() const { return accept_requests_called_; }

      protected:
        void request_calls() override { accept_requests_called_ = true; }

      private:
        bool accept_requests_called_{false};
    };

    SECTION("OK: accept requests called", "[silkworm][node][rpc]") {
        ServerConfig config;
        config.set_address_uri(kTestAddressUri);
        TestServer server{config};
        std::thread shutdown_thread{[&server]() {
            std::this_thread::yield();
            server.shutdown();
            //server.join();
        }};
        server.run();
        CHECK(server.accept_requests_called());
        shutdown_thread.join();
    }
}

TEST_CASE("Server::shutdown", "[silkworm][node][rpc]") {
    silkworm::log::set_verbosity(silkworm::log::Level::kNone);

    SECTION("OK: single call", "[silkworm][node][rpc]") {
        ServerConfig config;
        config.set_address_uri(kTestAddressUri);
        EmptyServer server{config};
        CHECK_NOTHROW(server.shutdown());
    }

    SECTION("OK: double call", "[silkworm][node][rpc]") {
        ServerConfig config;
        config.set_address_uri(kTestAddressUri);
        EmptyServer server{config};
        server.shutdown();
        CHECK_NOTHROW(server.shutdown());
    }
}

} // namespace silkworm::rpc
