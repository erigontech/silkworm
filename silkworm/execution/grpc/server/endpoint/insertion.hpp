// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>

#include <silkworm/interfaces/execution/execution.pb.h>

#include "../../../api/endpoint/insertion.hpp"

namespace silkworm::execution::grpc::server {

std::optional<api::Blocks> blocks_from_insertion_request(const ::execution::InsertBlocksRequest&);
::execution::InsertionResult response_from_insertion_result(const api::InsertionResult& result);

}  // namespace silkworm::execution::grpc::server
