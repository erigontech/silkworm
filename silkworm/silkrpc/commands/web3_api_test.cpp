/*
   Copyright 2021 The Silkrpc Authors

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

#include "web3_api.hpp"

#include <catch2/catch.hpp>
#include <grpcpp/grpcpp.h>

namespace silkrpc::commands {

using Catch::Matchers::Message;

TEST_CASE("Web3RpcApi::Web3RpcApi", "[silkrpc][erigon_api]") {
    ContextPool context_pool{1, []() {
        return grpc::CreateChannel("localhost", grpc::InsecureChannelCredentials());
    }};
    CHECK_NOTHROW(Web3RpcApi{context_pool.next_context()});
}

} // namespace silkrpc::commands
