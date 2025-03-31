// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/interfaces/execution/execution.pb.h>

#include "../../../api/endpoint/checkers.hpp"
#include "../../../api/endpoint/status.hpp"
#include "../../../api/endpoint/validation.hpp"

namespace silkworm::execution::grpc::server {

api::ExecutionStatus execution_status_from_proto(const ::execution::ExecutionStatus&);

BlockId block_id_from_request(const ::execution::ValidationRequest&);
::execution::ValidationReceipt response_from_validation_result(const api::ValidationResult&);

api::ForkChoice fork_choice_from_request(const ::execution::ForkChoice&);
::execution::ForkChoiceReceipt response_from_fork_choice_result(const api::ForkChoiceResult&);

}  // namespace silkworm::execution::grpc::server
