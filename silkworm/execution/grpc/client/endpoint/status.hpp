// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/interfaces/execution/execution.pb.h>

#include "../../../api/endpoint/status.hpp"

namespace silkworm::execution::grpc::client {

api::ExecutionStatus execution_status_from_proto(const ::execution::ExecutionStatus&);

}  // namespace silkworm::execution::grpc::client
