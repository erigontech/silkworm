// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/interfaces/execution/execution.pb.h>

#include "../../../api/endpoint/status.hpp"

namespace silkworm::execution::grpc::server {

::execution::ExecutionStatus proto_from_execution_status(const api::ExecutionStatus&);

}  // namespace silkworm::execution::grpc::server
