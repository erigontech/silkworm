// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/types/hash.hpp>
#include <silkworm/interfaces/execution/execution.pb.h>

#include "../../../api/endpoint/checkers.hpp"

namespace silkworm::execution::grpc::client {

::types::H256 h256_from_block_hash(const Hash& block_hash);

std::optional<BlockNum> block_num_from_response(const ::execution::GetHeaderHashNumberResponse&);

api::ForkChoice fork_choice_from_response(const ::execution::ForkChoice&);

}  // namespace silkworm::execution::grpc::client
