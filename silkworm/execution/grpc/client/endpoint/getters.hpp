// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>

#include <silkworm/core/types/block.hpp>
#include <silkworm/interfaces/execution/execution.pb.h>

#include "../../../api/endpoint/getters.hpp"

namespace silkworm::execution::grpc::client {

::execution::GetSegmentRequest request_from_block_num_or_hash(const api::BlockNumOrHash&);

std::optional<TotalDifficulty> total_difficulty_from_response(const ::execution::GetTDResponse&);

std::optional<BlockHeader> header_from_response(const ::execution::GetHeaderResponse&);

std::optional<BlockBody> body_from_response(const ::execution::GetBodyResponse&);

}  // namespace silkworm::execution::grpc::client
