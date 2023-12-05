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

#include "server.hpp"

#include <catch2/catch.hpp>

#include <silkworm/infra/grpc/server/server_context_pool.hpp>
#include <silkworm/infra/test_util/log.hpp>

namespace silkworm::rpc::http {

// Exclude from sanitizer builds due to errors in Catch2 signal handling
// WARNING: ThreadSanitizer: signal-unsafe call inside a signal
#ifndef SILKWORM_SANITIZE
TEST_CASE("server creation", "[rpc][http][server]") {
    test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};

    SECTION("localhost successful") {
        ServerContextPool context_pool{1};
        context_pool.start();
        // Uncommenting the following lines you got stuck into llvm-cov problem:
        // error: cmd/unit_test: Failed to load coverage: Malformed coverage data
        /*Server server{"localhost:12345", "eth", context_pool, 1};
        server.stop();*/
        context_pool.stop();
        context_pool.join();
    }
}
#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::rpc::http
