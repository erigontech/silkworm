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

#include "connection.hpp"

#include <boost/asio/thread_pool.hpp>
#include <catch2/catch.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/silkrpc/commands/rpc_api_table.hpp>

namespace silkrpc::http {

using Catch::Matchers::Message;

TEST_CASE("connection creation", "[silkrpc][http][connection]") {
    SILKRPC_LOG_VERBOSITY(LogLevel::None);

    ChannelFactory create_channel = []() { return grpc::CreateChannel("localhost", grpc::InsecureChannelCredentials()); };

    SECTION("field initialization") {
        ContextPool context_pool{1, create_channel};
        context_pool.start();
        boost::asio::thread_pool workers;
        // Uncommenting the following lines you got stuck into llvm-cov problem:
        // error: cmd/unit_test: Failed to load coverage: Malformed coverage data
        /*
        commands::RpcApiTable handler_table{""};
        Connection conn{context_pool.next_context(), workers, handler_table};
        */
        context_pool.stop();
        context_pool.join();
    }
}

} // namespace silkrpc::http
