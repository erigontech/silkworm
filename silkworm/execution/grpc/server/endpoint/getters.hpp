// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>

#include <silkworm/core/types/block.hpp>
#include <silkworm/interfaces/execution/execution.pb.h>

#include "../../../api/endpoint/getters.hpp"

namespace silkworm::execution::grpc::server {

api::BlockNumOrHash block_num_or_hash_from_request(const ::execution::GetSegmentRequest&);
::execution::GetTDResponse response_from_total_difficulty(const std::optional<TotalDifficulty>&);
::execution::GetHeaderResponse response_from_header(const std::optional<BlockHeader>&);
::execution::GetBodyResponse response_from_body(const std::optional<BlockBody>&, const Hash&, BlockNum);

}  // namespace silkworm::execution::grpc::server
