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

#include "trace_api.hpp"

#include <catch2/catch.hpp>

#include <silkworm/silkrpc/common/log.hpp>

namespace silkworm::rpc::commands {

using Catch::Matchers::Message;

#ifndef SILKWORM_SANITIZE
TEST_CASE("TraceRpcApi") {
    SILKRPC_LOG_VERBOSITY(LogLevel::None);

    boost::asio::io_context ioc;
    boost::asio::thread_pool workers{1};

    SECTION("CTOR") {
        CHECK_NOTHROW(TraceRpcApi{ioc, workers});
    }
}
#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::rpc::commands
