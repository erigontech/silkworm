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

#include <optional>

#include <silkworm/interfaces/execution/execution.pb.h>

#include "../../../api/endpoint/insertion.hpp"

namespace silkworm::execution::grpc::server {

std::optional<api::Blocks> blocks_from_insertion_request(const ::execution::InsertBlocksRequest&);
::execution::InsertionResult response_from_insertion_result(const api::InsertionResult& result);

}  // namespace silkworm::execution::grpc::server
