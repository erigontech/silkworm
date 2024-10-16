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
#include <string>

#include "common.hpp"

namespace silkworm::db::kv::api {

struct PointResult {
    bool success{false};
    Bytes value;
};

struct HistoryPointQuery {
    TxId tx_id{0};
    std::string table;
    Bytes key;
    Timestamp timestamp{0};
};

using HistoryPointResult = PointResult;

struct DomainPointQuery {
    TxId tx_id{0};
    std::string table;
    Bytes key;
    std::optional<Timestamp> timestamp;  // not present means 'latest state' (no history lookup)
    Bytes sub_key;

    auto operator<=>(const DomainPointQuery&) const = default;
};

using DomainPointResult = PointResult;

}  // namespace silkworm::db::kv::api
