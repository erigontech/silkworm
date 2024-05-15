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

#include "assembly.hpp"

namespace silkworm::execution::grpc::server {

api::BlockUnderConstruction block_from_assemble_request(const ::execution::AssembleBlockRequest&) {
    // TODO(canepat) implement
    return {};
}

::execution::AssembleBlockResponse response_from_assemble_result(const api::AssembleBlockResult&) {
    // TODO(canepat) implement
    return {};
}

api::PayloadId get_assembled_request_from_payload_id(const ::execution::GetAssembledBlockRequest&) {
    // TODO(canepat) implement
    return {};
}

::execution::GetAssembledBlockResponse response_from_get_assembled_result(const api::AssembledBlockResult&) {
    // TODO(canepat) implement
    return {};
}

}  // namespace silkworm::execution::grpc::server
