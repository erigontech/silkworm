// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/interfaces/execution/execution.pb.h>

#include "../../../api/endpoint/range.hpp"

namespace silkworm::execution::grpc::server {

BlockNumRange block_num_range_from_request(const ::execution::GetBodiesByRangeRequest&);
api::BlockHashes block_hashes_from_request(const ::execution::GetBodiesByHashesRequest&);
::execution::GetBodiesBatchResponse response_from_bodies(const api::BlockBodies&);

}  // namespace silkworm::execution::grpc::server
