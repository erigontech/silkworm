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

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/hash.hpp>
#include <silkworm/node/db/mdbx.hpp>
#include <silkworm/node/store/access_layer.hpp>

namespace silkworm {

//! \brief Read the lasdt n headers, in forward order, processing each via a user defined callback
void for_last_n_headers(const db::DataModel&, size_t n, std::function<void(BlockHeader&&)> callback);

//! \brief Return (block-num, hash) of the header with the biggest total difficulty skipping bad headers
std::tuple<BlockNum, Hash> header_with_biggest_td(db::ROTxn& txn, const std::set<Hash>* bad_headers = nullptr);

}  // namespace silkworm
