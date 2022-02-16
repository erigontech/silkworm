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

#include "service.hpp"

#include <catch2/catch.hpp>

#include <silkworm/rpc/service.hpp>

namespace silkworm::rpc {

namespace { // Trick suggested by gRPC team to avoid name clashes in multiple test modules
class MockRpc {
  public:
    static int instance_count() { return instance_count_; }

    explicit MockRpc() { instance_count_++; }
    ~MockRpc() { instance_count_--; }

  private:
    inline static int instance_count_{0};
};

class EmptyService : public RpcService<MockRpc> {
  public:
    EmptyService() {}
    EmptyService(std::size_t capacity) : RpcService<MockRpc>(capacity) {}

    auto insert_request(MockRpc* rpc) { return add_request(rpc); }
    auto erase_request(MockRpc* rpc) { return remove_request(rpc); }
    auto requests_capacity() const { return requests_bucket_count(); }
    auto requests_count() const { return requests_size(); }
};
};

TEST_CASE("RpcService::RpcService", "[silkworm][node][rpc]") {
    SECTION("OK: has default capacity for requests", "[silkworm][node][rpc]") {
        EmptyService svc;
        CHECK(svc.requests_capacity() >= kRequestsInitialCapacity);
    }

    SECTION("OK: has specified capacity for requests", "[silkworm][node][rpc]") {
        const std::size_t capacity{100};
        EmptyService svc{capacity};
        CHECK(svc.requests_capacity() >= capacity);
    }
}

TEST_CASE("RpcService::add_request", "[silkworm][node][rpc]") {
    SECTION("OK: insert new rpc", "[silkworm][node][rpc]") {
        EmptyService svc;
        auto rpc = new MockRpc();
        auto [it, inserted] = svc.insert_request(rpc);
        CHECK(it->get() == rpc);
        CHECK(inserted);
        CHECK(svc.requests_count() == 1);
    }
}

TEST_CASE("RpcService::remove_request", "[silkworm][node][rpc]") {
    SECTION("KO: remove unexisting rpc", "[silkworm][node][rpc]") {
        EmptyService svc;
        auto rpc1 = new MockRpc();
        svc.insert_request(rpc1);
        auto rpc2 = new MockRpc();
        CHECK(svc.erase_request(rpc2) == 0);
        CHECK(svc.requests_count() == 1);
        delete rpc2;
    }

    SECTION("OK: remove existing rpc", "[silkworm][node][rpc]") {
        EmptyService svc;
        auto rpc = new MockRpc();
        svc.insert_request(rpc);
        CHECK(svc.erase_request(rpc) == 1);
        CHECK(svc.requests_count() == 0);
    }
}

} // namespace silkworm::rpc
