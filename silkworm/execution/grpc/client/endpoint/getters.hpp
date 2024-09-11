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

#include <silkworm/core/types/block.hpp>
#include <silkworm/interfaces/execution/execution.pb.h>

#include "../../../api/endpoint/getters.hpp"

namespace silkworm::execution::grpc::client {

::execution::GetSegmentRequest request_from_block_number_or_hash(const api::BlockNumberOrHash&);

std::optional<TotalDifficulty> total_difficulty_from_response(const ::execution::GetTDResponse&);

std::optional<BlockHeader> header_from_response(const ::execution::GetHeaderResponse&);

std::optional<BlockBody> body_from_response(const ::execution::GetBodyResponse&);

}  // namespace silkworm::execution::grpc::client
