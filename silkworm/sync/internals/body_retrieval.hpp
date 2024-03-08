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

#pragma once

#include <silkworm/db/access_layer.hpp>

#include "types.hpp"

namespace silkworm {

class BodyRetrieval {
  public:
    static const long soft_response_limit = 2 * 1024 * 1024;  // Target maximum size of returned blocks
    static const long max_bodies_serve = 1024;                // Amount of block bodies to be fetched per retrieval request

    explicit BodyRetrieval(db::ROAccess db_access);

    std::vector<BlockBody> recover(std::vector<Hash>);

  protected:
    db::ROTxnManaged db_tx_;
};

}  // namespace silkworm
