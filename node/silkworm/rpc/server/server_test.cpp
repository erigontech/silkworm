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

#include <catch2/catch.hpp>
#include <grpc/grpc.h>
#include <grpcpp/alarm.h>
#include <grpcpp/impl/codegen/service_type.h>

#include <silkworm/common/log.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/test/log.hpp>

namespace silkworm::rpc {

namespace {  // Trick suggested by gRPC team to avoid name clashes in multiple test modules
    class MockService : public grpc::Service {};

    class EmptyServer : public Server {
      public:
        explicit EmptyServer(const ServerConfig& config) : Server(config) {}

      protected:
        void register_async_services(grpc::ServerBuilder& builder) override {
            builder.RegisterService(&mock_async_service_);
        }
        void register_request_calls() override {}

      private:
        MockService mock_async_service_;
    };
}  // namespace

// TODO(canepat): better copy grpc_pick_unused_port_or_die to generate unused port
static const std::string kTestAddressUri{"localhost:12345"};

// Exclude gRPC tests from sanitizer builds due to data race warnings inside gRPC library
#ifndef SILKWORM_SANITIZE
TEST_CASE("Barebone gRPC Server", "[silkworm][node][rpc]") {
    grpc::ServerBuilder builder;
    // Add *at least one non-empty* ServerCompletionQueue (otherwise: ASAN SEGV error in Shutdown)
    std::unique_ptr<grpc::ServerCompletionQueue> cq = builder.AddCompletionQueue();
    auto alarm = std::make_unique<grpc::Alarm>();
    alarm->Set(cq.get(), gpr_now(GPR_CLOCK_MONOTONIC), reinterpret_cast<void*>(0));
    // Build and start the gRPC server
    std::unique_ptr<grpc::Server> server = builder.BuildAndStart();

    // First, shutdown the gRPC server
    server->Shutdown();
    // Then, shutdown and drain the ServerCompletionQueue
    cq->Shutdown();
    void* tag;
    bool ok;
    CHECK(cq->Next(&tag, &ok) == true);
    CHECK(tag == reinterpret_cast<void*>(0));
    CHECK(cq->Next(&tag, &ok) == false);
}

TEST_CASE("Server::Server", "[silkworm][node][rpc]") {
    test::SetLogVerbosityGuard guard{log::Level::kNone};

    SECTION("OK: create an empty Server", "[silkworm][node][rpc]") {
        ServerConfig config;
        config.set_address_uri(kTestAddressUri);
        EmptyServer server{config};
    }
}

TEST_CASE("Server::build_and_start", "[silkworm][node][rpc]") {
    test::SetLogVerbosityGuard set_log_verbosity_guard{log::Level::kNone};

    // TODO(canepat): use GMock
    class TestServer : public EmptyServer {
      public:
        TestServer(const ServerConfig& config) : EmptyServer(config) {}

        bool register_async_services_called() const { return register_async_services_called_; }

        bool register_request_calls_called() const { return register_request_calls_called_; }

      protected:
        void register_async_services(grpc::ServerBuilder& /*builder*/) override {
            register_async_services_called_ = true;
        }

        void register_request_calls() override { register_request_calls_called_ = true; }

      private:
        bool register_async_services_called_{false};
        bool register_request_calls_called_{false};
    };

    SECTION("KO: Address already in use", "[silkworm][node][rpc]") {
        GrpcNoLogGuard guard;

        ServerConfig config;
        config.set_address_uri(kTestAddressUri);
        TestServer server1{config};
        server1.build_and_start();
        TestServer server2{config};
        CHECK_THROWS_AS(server2.build_and_start(), std::runtime_error);
        server1.shutdown();
    }

    SECTION("KO: Name or service not known", "[silkworm][node][rpc]") {
        GrpcNoLogGuard guard;

        ServerConfig config;
        config.set_address_uri("local:12345");  // "localhost@12345" core dumped in gRPC 1.44.0-p0 (SIGSEGV)
        EmptyServer server{config};
        CHECK_THROWS_AS(server.build_and_start(), std::runtime_error);
    }

    SECTION("OK: accept requests called", "[silkworm][node][rpc]") {
        ServerConfig config;
        config.set_address_uri(kTestAddressUri);
        TestServer server{config};
        CHECK_NOTHROW(server.build_and_start());
        CHECK(server.register_async_services_called());
        CHECK(server.register_request_calls_called());
    }
}

TEST_CASE("Server::shutdown", "[silkworm][node][rpc]") {
    test::SetLogVerbosityGuard guard{log::Level::kNone};

    SECTION("OK: build_and_start/shutdown", "[silkworm][node][rpc]") {
        ServerConfig config;
        config.set_address_uri(kTestAddressUri);
        EmptyServer server{config};
        server.build_and_start();
        CHECK_NOTHROW(server.shutdown());
    }

    SECTION("OK: build_and_start/shutdown/shutdown", "[silkworm][node][rpc]") {
        ServerConfig config;
        config.set_address_uri(kTestAddressUri);
        EmptyServer server{config};
        server.build_and_start();
        CHECK_NOTHROW(server.shutdown());
        CHECK_NOTHROW(server.shutdown());
    }
}

TEST_CASE("Server::join", "[silkworm][node][rpc]") {
    test::SetLogVerbosityGuard guard{log::Level::kNone};

    SECTION("OK: build_and_start/join/shutdown", "[silkworm][node][rpc]") {
        ServerConfig config;
        config.set_address_uri(kTestAddressUri);
        EmptyServer server{config};
        server.build_and_start();
        std::thread server_thread{[&server]() { server.join(); }};
        CHECK_NOTHROW(server.shutdown());
        server_thread.join();
    }

    SECTION("OK: build_and_start/join/shutdown/shutdown", "[silkworm][node][rpc]") {
        ServerConfig config;
        config.set_address_uri(kTestAddressUri);
        EmptyServer server{config};
        server.build_and_start();
        std::thread server_thread{[&server]() { server.join(); }};
        CHECK_NOTHROW(server.shutdown());
        CHECK_NOTHROW(server.shutdown());
        server_thread.join();
    }
}
#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::rpc
