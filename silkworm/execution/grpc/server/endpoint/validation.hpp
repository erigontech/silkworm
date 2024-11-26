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
