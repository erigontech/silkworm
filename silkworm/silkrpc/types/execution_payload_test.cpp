/*
   Copyright 2022 The Silkrpc Authors

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

#include "execution_payload.hpp" // NOLINT(build/include)

#include <evmc/evmc.hpp>
#include <catch2/catch.hpp>
#include <silkworm/silkrpc/common/log.hpp>

namespace silkrpc {

TEST_CASE("print empty execution payload", "[silkrpc][types][execution_payload]") {
    ExecutionPayload p{};
    CHECK_NOTHROW(null_stream() << p);
}

TEST_CASE("print empty payload status", "[silkrpc][types][execution_payload]") {
    PayloadStatus p{
        .latest_valid_hash = evmc::bytes32{},
        .validation_error = ""
    };
    CHECK_NOTHROW(null_stream() << p);
}

} // namespace silkrpc
