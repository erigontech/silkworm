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

#include "server_settings.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/infra/concurrency/context_pool_settings.hpp>
#include <silkworm/infra/test_util/log.hpp>

namespace silkworm::rpc {

// Exclude gRPC tests from sanitizer builds due to data race warnings inside gRPC library
#ifndef SILKWORM_SANITIZE
TEST_CASE("ServerConfig::ServerConfig", "[silkworm][rpc][server_settings]") {
    ServerSettings config;
    CHECK(config.address_uri == kDefaultAddressUri);
    CHECK(config.context_pool_settings.num_contexts > 0);
}
#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::rpc
