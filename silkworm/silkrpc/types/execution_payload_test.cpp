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

#include "execution_payload.hpp"  // NOLINT(build/include)

#include <catch2/catch.hpp>
#include <evmc/evmc.hpp>

#include <silkworm/infra/test/log.hpp>

namespace silkworm::rpc {

TEST_CASE("print empty ExecutionPayloadV1", "[silkworm][rpc][types]") {
    ExecutionPayload p{.version = 1};
    CHECK_NOTHROW(silkworm::test::null_stream() << p);
}

TEST_CASE("print empty PayloadStatusV1", "[silkworm][rpc][types]") {
    PayloadStatus p{
        .latest_valid_hash = evmc::bytes32{},
        .validation_error = ""};
    CHECK_NOTHROW(silkworm::test::null_stream() << p);
}

TEST_CASE("print empty ExecutionPayloadV2", "[silkworm][rpc][types]") {
    ExecutionPayload p{.version = 2};
    CHECK_NOTHROW(silkworm::test::null_stream() << p);
}

}  // namespace silkworm::rpc
