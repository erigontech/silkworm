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

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include <silkworm/core/common/bytes.hpp>

namespace silkworm::db::kv::api {

//! Database meta-transaction ID (a transaction over mdbx and snapshots)
using TxId = uint64_t;

using Timestamp = int64_t;
using TimestampRange = std::pair<Timestamp, Timestamp>;

using ListOfBytes = std::vector<Bytes>;
using ListOfTimestamp = std::vector<Timestamp>;

using Domain = uint16_t;
using History = std::string_view;
using InvertedIndex = std::string_view;

}  // namespace silkworm::db::kv::api
