// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/interfaces/execution/execution.pb.h>

#include "../../../api/endpoint/range.hpp"

namespace silkworm::execution::grpc::client {

::execution::GetBodiesByRangeRequest bodies_request_from_block_num_range(BlockNumRange);
::execution::GetBodiesByHashesRequest bodies_request_from_block_hashes(const api::BlockHashes&);
api::BlockBodies block_bodies_from_response(const ::execution::GetBodiesBatchResponse&);

}  // namespace silkworm::execution::grpc::client
