// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "assembly.hpp"

namespace silkworm::execution::grpc::server {

api::BlockUnderConstruction block_from_assemble_request(const ::execution::AssembleBlockRequest&) {
    // TODO(canepat) implement
    return {};
}

::execution::AssembleBlockResponse response_from_assemble_result(const api::AssembleBlockResult&) {
    // TODO(canepat) implement
    return {};
}

api::PayloadId get_assembled_request_from_payload_id(const ::execution::GetAssembledBlockRequest&) {
    // TODO(canepat) implement
    return {};
}

::execution::GetAssembledBlockResponse response_from_get_assembled_result(const api::AssembledBlockResult&) {
    // TODO(canepat) implement
    return {};
}

}  // namespace silkworm::execution::grpc::server
