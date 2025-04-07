// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>

#include <silkworm/interfaces/execution/execution.pb.h>

#include "../../../api/endpoint/assembly.hpp"

namespace silkworm::execution::grpc::client {

api::ExecutionPayload execution_payload_from_proto(const ::types::ExecutionPayload&);
api::BlobsBundleV1 blobs_bundle_from_proto(const ::types::BlobsBundleV1&);

api::AssembledBlock assembled_from_data(const ::execution::AssembledBlockData&);

::execution::AssembleBlockRequest assemble_request_from_block(const api::BlockUnderConstruction&);
api::AssembleBlockResult assemble_result_from_response(const ::execution::AssembleBlockResponse&);

::execution::GetAssembledBlockRequest get_assembled_request_from_payload_id(api::PayloadId);
api::AssembledBlockResult get_assembled_result_from_response(const ::execution::GetAssembledBlockResponse&);

}  // namespace silkworm::execution::grpc::client
