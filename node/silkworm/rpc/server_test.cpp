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

#include <atomic>
#include <chrono>
//#include <mutex>
#include <thread>

#include <catch2/catch.hpp>
#include <grpc/grpc.h>
#include <grpcpp/alarm.h>
#include <grpcpp/impl/codegen/service_type.h>

#include <silkworm/common/log.hpp>
#include <silkworm/rpc/util.hpp>

namespace silkworm::rpc {

namespace { // Trick suggested by gRPC team to avoid name clashes in multiple test modules
class MockService : public grpc::Service {
};

class EmptyServer : public Server<MockService> {
  public:
    EmptyServer(const ServerConfig& config) : Server(config) {}

  protected:
    void request_calls() override {}
};
};

// TODO(canepat): better copy grpc_pick_unused_port_or_die to generate unused port
constexpr const char* kTestAddressUri = "localhost:12345";

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
    silkworm::log::set_verbosity(silkworm::log::Level::kNone);

    SECTION("KO: Address already in use", "[silkworm][node][rpc]") {
        GrpcNoLogGuard guard;

        ServerConfig config;
        config.set_address_uri(kTestAddressUri);
        EmptyServer server(config);
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
    silkworm::log::set_verbosity(silkworm::log::Level::kNone);

    class TestServer : public Server<MockService> {
      public:
        TestServer(const ServerConfig& config) : Server(config) {}

        bool wait_initialization_for(uint32_t timeout=1000, uint32_t check_interval=10) {
            if (!notified_) {
                auto sleep_count = timeout / check_interval;
                for (uint64_t i=0; i<sleep_count; i++) {
                    if (notified_) {
                        break;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(check_interval));
                }
            }
            return notified_;
        }

      protected:
        void request_calls() override {
            notified_ = true;
        }

      private:
        std::atomic_bool notified_{false};
    };

    SECTION("OK: accept requests called", "[silkworm][node][rpc]") {
        ServerConfig config;
        config.set_address_uri(kTestAddressUri);
        TestServer server{config};
        std::thread shutdown_thread{[&server]() {
            const bool notified = server.wait_initialization_for();
            CHECK(notified);
            server.shutdown();
        }};
        server.run();
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
