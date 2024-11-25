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

struct GetLatestQuery {
    TxId tx_id{0};
    std::string table;
    Bytes key;
    Bytes sub_key;

    // TODO(canepat) we need clang >= 17 to use spaceship operator instead of hand-made operator== below
    // auto operator<=>(const GetLatestQuery&) const = default;
};

inline bool operator==(const GetLatestQuery& lhs, const GetLatestQuery& rhs) {
    return (lhs.tx_id == rhs.tx_id) &&
           (lhs.table == rhs.table) &&
           (lhs.key == rhs.key) &&
           (lhs.sub_key == rhs.sub_key);
}

using GetLatestResult = PointResult;

struct GetAsOfQuery {
    TxId tx_id{0};
    std::string table;
    Bytes key;
    Bytes sub_key;
    Timestamp timestamp;

    // TODO(canepat) we need clang >= 17 to use spaceship operator instead of hand-made operator== below
    // auto operator<=>(const GetAsOfQuery&) const = default;
};

inline bool operator==(const GetAsOfQuery& lhs, const GetAsOfQuery& rhs) {
    return (lhs.tx_id == rhs.tx_id) &&
           (lhs.table == rhs.table) &&
           (lhs.key == rhs.key) &&
           (lhs.sub_key == rhs.sub_key) &&
           (lhs.timestamp == rhs.timestamp);
}

using GetAsOfResult = PointResult;

}  // namespace silkworm::db::kv::api
