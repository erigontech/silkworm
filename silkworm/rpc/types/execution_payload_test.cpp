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

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/test_util/null_stream.hpp>
#include <silkworm/infra/test_util/log.hpp>

namespace silkworm::rpc {

TEST_CASE("print empty ExecutionPayloadV1", "[silkworm][rpc][types]") {
    CHECK_NOTHROW(silkworm::test_util::null_stream() << ExecutionPayload{.version = ExecutionPayload::V1});
}

TEST_CASE("print empty ExecutionPayloadV2", "[silkworm][rpc][types]") {
    CHECK_NOTHROW(silkworm::test_util::null_stream() << ExecutionPayload{.version = ExecutionPayload::V2});
}

TEST_CASE("print empty PayloadStatus", "[silkworm][rpc][types]") {
    CHECK_NOTHROW(silkworm::test_util::null_stream() << PayloadStatus{});
}

TEST_CASE("print empty ForkChoiceState", "[silkworm][rpc][types]") {
    CHECK_NOTHROW(silkworm::test_util::null_stream() << ForkChoiceState{});
}

TEST_CASE("print empty PayloadAttributesV1", "[silkworm][rpc][types]") {
    CHECK_NOTHROW(silkworm::test_util::null_stream() << PayloadAttributes{.version = PayloadAttributes::V1});
}

TEST_CASE("print empty PayloadAttributesV2", "[silkworm][rpc][types]") {
    CHECK_NOTHROW(silkworm::test_util::null_stream() << PayloadAttributes{.version = PayloadAttributes::V2});
}

TEST_CASE("print empty ForkChoiceUpdatedRequest", "[silkworm][rpc][types]") {
    CHECK_NOTHROW(silkworm::test_util::null_stream() << ForkChoiceUpdatedRequest{});
}

TEST_CASE("print empty ForkChoiceUpdatedReply", "[silkworm][rpc][types]") {
    CHECK_NOTHROW(silkworm::test_util::null_stream() << ForkChoiceUpdatedReply{});
}

TEST_CASE("print empty TransitionConfiguration", "[silkworm][rpc][types]") {
    CHECK_NOTHROW(silkworm::test_util::null_stream() << TransitionConfiguration{});
}

TEST_CASE("print empty ExecutionPayloadAndValue", "[silkworm][rpc][types]") {
    ExecutionPayloadAndValue pv{.payload = {.version = ExecutionPayload::V2}, .block_value = 0};
    CHECK_NOTHROW(silkworm::test_util::null_stream() << pv);
}

TEST_CASE("print empty ExecutionPayloadBody", "[silkworm][rpc][types]") {
    CHECK_NOTHROW(silkworm::test_util::null_stream() << ExecutionPayloadBody{});
}

}  // namespace silkworm::rpc
