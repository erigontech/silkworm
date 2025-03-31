// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/types/hash.hpp>
#include <silkworm/infra/grpc/common/conversion.hpp>
#include <silkworm/interfaces/execution/execution.pb.h>

#include "../../../api/endpoint/checkers.hpp"

namespace silkworm::execution::grpc::server {

::execution::GetHeaderHashNumberResponse response_from_block_num(std::optional<BlockNum>);

::execution::ForkChoice response_from_fork_choice(const api::ForkChoice&);

}  // namespace silkworm::execution::grpc::server
