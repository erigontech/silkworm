// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "status.hpp"

#include <stdexcept>

namespace silkworm::execution::grpc::client {

namespace proto = ::execution;

api::ExecutionStatus execution_status_from_proto(const proto::ExecutionStatus& proto_status) {
    switch (proto_status) {
        case proto::ExecutionStatus::Success:
            return api::ExecutionStatus::kSuccess;
        case proto::ExecutionStatus::BadBlock:
            return api::ExecutionStatus::kBadBlock;
        case proto::ExecutionStatus::TooFarAway:
            return api::ExecutionStatus::kTooFarAway;
        case proto::ExecutionStatus::MissingSegment:
            return api::ExecutionStatus::kMissingSegment;
        case proto::ExecutionStatus::InvalidForkchoice:
            return api::ExecutionStatus::kInvalidForkchoice;
        case proto::ExecutionStatus::Busy:
            return api::ExecutionStatus::kBusy;
        default:
            throw std::logic_error{"unsupported ::execution::ExecutionStatus value " + std::to_string(int{proto_status})};
    }
}

}  // namespace silkworm::execution::grpc::client
