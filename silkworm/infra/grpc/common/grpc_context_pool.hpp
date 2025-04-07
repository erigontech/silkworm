// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <agrpc/detail/forward.hpp>

namespace silkworm::rpc {

struct GrpcContextPool {
    virtual ~GrpcContextPool() = default;
    virtual agrpc::GrpcContext& any_grpc_context() = 0;
};

}  // namespace silkworm::rpc
