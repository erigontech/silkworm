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
