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

#include <memory>

#include <silkworm/interfaces/execution/execution.pb.h>

#include "../../../api/endpoint/assembly.hpp"

namespace silkworm::execution::grpc::client {

api::ExecutionPayload execution_payload_from_proto(const ::types::ExecutionPayload&);
api::BlobsBundleV1 blobs_bundle_from_proto(const ::types::BlobsBundleV1&);

api::AssembledBlock assembled_from_data(const ::execution::AssembledBlockData&);

::execution::AssembleBlockRequest assemble_request_from_block(const api::BlockUnderConstruction&);
api::AssembleBlockResult assemble_result_from_response(const ::execution::AssembleBlockResponse&);

::execution::GetAssembledBlockRequest get_assembled_request_from_payload_id(api::PayloadId);
api::AssembledBlockResult get_assembled_result_from_response(const ::execution::GetAssembledBlockResponse&);

}  // namespace silkworm::execution::grpc::client
