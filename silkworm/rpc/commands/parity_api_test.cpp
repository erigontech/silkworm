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

#include "parity_api.hpp"

#include <catch2/catch.hpp>
#include <grpcpp/grpcpp.h>

namespace silkworm::rpc::commands {

#ifndef SILKWORM_SANITIZE
TEST_CASE("ParityRpcApi::ParityRpcApi", "[rpc][erigon_api]") {
    boost::asio::io_context ioc;
    CHECK_THROWS_AS(ParityRpcApi(ioc), std::logic_error);
}
#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::rpc::commands
