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

#include "../../../api/endpoint/range.hpp"

namespace silkworm::execution::grpc::server {

BlockNumRange block_num_range_from_request(const ::execution::GetBodiesByRangeRequest&);
api::BlockHashes block_hashes_from_request(const ::execution::GetBodiesByHashesRequest&);
::execution::GetBodiesBatchResponse response_from_bodies(const api::BlockBodies&);

}  // namespace silkworm::execution::grpc::server
