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

namespace silkworm::execution::grpc::client {

::execution::GetBodiesByRangeRequest bodies_request_from_block_num_range(BlockNumRange);
::execution::GetBodiesByHashesRequest bodies_request_from_block_hashes(const api::BlockHashes&);
api::BlockBodies block_bodies_from_response(const ::execution::GetBodiesBatchResponse&);

}  // namespace silkworm::execution::grpc::client
