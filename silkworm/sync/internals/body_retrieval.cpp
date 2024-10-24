/*
   Copyright 2022 The Silkworm Authors

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

#include "body_retrieval.hpp"

#include <silkworm/core/types/block.hpp>

namespace silkworm {

std::vector<BlockBody> BodyRetrieval::recover(std::vector<Hash> request) {
    std::vector<BlockBody> response;
    size_t bytes = 0;
    for (size_t i = 0; i < request.size(); ++i) {
        Hash& hash = request[i];
        BlockBody body;
        if (!db::read_body(db_tx_, hash, body)) {
            continue;
        }
        response.push_back(body);
        bytes += rlp::length(body);
        if (bytes >= kSoftResponseLimit || response.size() >= kMaxBodiesServe || i >= 2 * kMaxBodiesServe) {
            break;
        }
    }
    return response;
}

}  // namespace silkworm
