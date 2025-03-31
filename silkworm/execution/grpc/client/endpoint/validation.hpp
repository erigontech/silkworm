// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/interfaces/execution/execution.pb.h>

#include "../../../api/endpoint/checkers.hpp"
#include "../../../api/endpoint/validation.hpp"

namespace silkworm::execution::grpc::client {

::execution::ValidationRequest request_from_block_id(const BlockId&);
api::ValidationResult validation_result_from_response(const ::execution::ValidationReceipt&);

::execution::ForkChoice request_from_fork_choice(const api::ForkChoice&);
api::ForkChoiceResult fork_choice_result_from_response(const ::execution::ForkChoiceReceipt&);

}  // namespace silkworm::execution::grpc::client
