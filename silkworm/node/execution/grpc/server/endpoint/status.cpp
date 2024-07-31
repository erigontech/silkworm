/*
   Copyright 2024 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

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
