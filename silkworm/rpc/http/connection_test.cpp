/*
   Copyright 2023 The Silkworm Authors

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

#include <silkworm/infra/grpc/client/client_context_pool.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/rpc/commands/rpc_api_table.hpp>

namespace silkworm::rpc::http {

using Catch::Matchers::Message;

// Exclude gRPC tests from sanitizer builds due to data race warnings inside gRPC library
// SUMMARY: ThreadSanitizer: data race /usr/include/c++/11/bits/stl_algobase.h:431
// - write of size 1 thread T8 'grpc_global_tim' created by main thread
// - previous write of size 1 by main thread
#ifndef SILKWORM_SANITIZE
TEST_CASE("connection creation", "[rpc][http][connection]") {
    test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};

    SECTION("field initialization") {
        ClientContextPool context_pool{1};
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
#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::rpc::http
