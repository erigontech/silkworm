// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>

#include <silkworm/interfaces/execution/execution.pb.h>

#include "../../../api/endpoint/assembly.hpp"

namespace silkworm::execution::grpc::server {

api::BlockUnderConstruction block_from_assemble_request(const ::execution::AssembleBlockRequest&);
::execution::AssembleBlockResponse response_from_assemble_result(const api::AssembleBlockResult&);

api::PayloadId get_assembled_request_from_payload_id(const ::execution::GetAssembledBlockRequest&);
::execution::GetAssembledBlockResponse response_from_get_assembled_result(const api::AssembledBlockResult&);

}  // namespace silkworm::execution::grpc::server
