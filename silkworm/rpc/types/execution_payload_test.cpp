// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "execution_payload.hpp"  // NOLINT(build/include)

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/test_util/null_stream.hpp>

namespace silkworm::rpc {

TEST_CASE("print empty ExecutionPayloadV1", "[silkworm][rpc][types]") {
    CHECK_NOTHROW(silkworm::test_util::null_stream() << ExecutionPayload{.version = ExecutionPayload::kV1});
}

TEST_CASE("print empty ExecutionPayloadV2", "[silkworm][rpc][types]") {
    CHECK_NOTHROW(silkworm::test_util::null_stream() << ExecutionPayload{.version = ExecutionPayload::kV2});
}

TEST_CASE("print empty PayloadStatus", "[silkworm][rpc][types]") {
    CHECK_NOTHROW(silkworm::test_util::null_stream() << PayloadStatus{});
}

TEST_CASE("print empty ForkChoiceState", "[silkworm][rpc][types]") {
    CHECK_NOTHROW(silkworm::test_util::null_stream() << ForkChoiceState{});
}

TEST_CASE("print empty PayloadAttributesV1", "[silkworm][rpc][types]") {
    CHECK_NOTHROW(silkworm::test_util::null_stream() << PayloadAttributes{.version = PayloadAttributes::kV1});
}

TEST_CASE("print empty PayloadAttributesV2", "[silkworm][rpc][types]") {
    CHECK_NOTHROW(silkworm::test_util::null_stream() << PayloadAttributes{.version = PayloadAttributes::kV2});
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
    ExecutionPayloadAndValue pv{.payload = {.version = ExecutionPayload::kV2}, .block_value = 0};
    CHECK_NOTHROW(silkworm::test_util::null_stream() << pv);
}

TEST_CASE("print empty ExecutionPayloadBody", "[silkworm][rpc][types]") {
    CHECK_NOTHROW(silkworm::test_util::null_stream() << ExecutionPayloadBody{});
}

}  // namespace silkworm::rpc
