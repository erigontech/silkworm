// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/core/types/block.hpp>
#include <silkworm/interfaces/execution/execution.pb.h>

#include "../../../api/endpoint/insertion.hpp"

namespace silkworm::execution::grpc::client {

::execution::InsertBlocksRequest insertion_request_from_blocks(const api::Blocks&);
api::InsertionResult insertion_result_from_response(const ::execution::InsertionResult&);

}  // namespace silkworm::execution::grpc::client
