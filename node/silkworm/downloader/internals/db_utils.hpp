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

#include <functional>
#include <set>

#include <silkworm/db/access_layer.hpp>

#include "types.hpp"

namespace silkworm {

//! \brief Read all headers up to limit, in reverse order from last, processing each via a user defined callback
void read_headers_in_reverse_order(mdbx::txn& txn, size_t limit, std::function<void(BlockHeader&&)> callback);

//! \brief Return (block-num, hash) of the header with the biggest total difficulty skipping bad headers
std::tuple<BlockNum, Hash> header_with_biggest_td(mdbx::txn& txn, const std::set<Hash>* bad_headers = nullptr);

}  // namespace silkworm
