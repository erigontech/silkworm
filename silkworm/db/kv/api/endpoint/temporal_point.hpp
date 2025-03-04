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

struct HistoryPointRequest {
    TxId tx_id{0};
    std::string table;
    Bytes key;
    Timestamp timestamp{0};
};

using HistoryPointResult = PointResult;

struct GetLatestRequest {
    TxId tx_id{0};
    std::string table;
    Bytes key;
    Bytes sub_key;

    // TODO(canepat) we need clang >= 17 to use spaceship operator instead of hand-made operator== below
    // auto operator<=>(const GetLatestRequest&) const = default;
};

inline bool operator==(const GetLatestRequest& lhs, const GetLatestRequest& rhs) {
    return (lhs.tx_id == rhs.tx_id) &&
           (lhs.table == rhs.table) &&
           (lhs.key == rhs.key) &&
           (lhs.sub_key == rhs.sub_key);
}

using GetLatestResult = PointResult;

struct GetAsOfRequest {
    TxId tx_id{0};
    std::string table;
    Bytes key;
    Bytes sub_key;
    Timestamp timestamp;

    // TODO(canepat) we need clang >= 17 to use spaceship operator instead of hand-made operator== below
    // auto operator<=>(const GetAsOfRequest&) const = default;
};

inline bool operator==(const GetAsOfRequest& lhs, const GetAsOfRequest& rhs) {
    return (lhs.tx_id == rhs.tx_id) &&
           (lhs.table == rhs.table) &&
           (lhs.key == rhs.key) &&
           (lhs.sub_key == rhs.sub_key) &&
           (lhs.timestamp == rhs.timestamp);
}

using GetAsOfResult = PointResult;

}  // namespace silkworm::db::kv::api
