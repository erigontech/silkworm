// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "status.hpp"

#include <stdexcept>

namespace silkworm::execution::grpc::server {

namespace proto = ::execution;

::execution::ExecutionStatus proto_from_execution_status(const api::ExecutionStatus& status) {
    switch (status) {
        case api::ExecutionStatus::kSuccess:
            return proto::ExecutionStatus::Success;
        case api::ExecutionStatus::kBadBlock:
            return proto::ExecutionStatus::BadBlock;
        case api::ExecutionStatus::kTooFarAway:
            return proto::ExecutionStatus::TooFarAway;
        case api::ExecutionStatus::kMissingSegment:
            return proto::ExecutionStatus::MissingSegment;
        case api::ExecutionStatus::kInvalidForkchoice:
            return proto::ExecutionStatus::InvalidForkchoice;
        case api::ExecutionStatus::kBusy:
            return proto::ExecutionStatus::Busy;
        default:
            throw std::logic_error{"unsupported api::ExecutionStatus value " + std::to_string(int{status})};
    }
}

}  // namespace silkworm::execution::grpc::server
