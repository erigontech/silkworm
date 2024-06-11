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

#include <string>
#include <vector>

#include <silkworm/core/common/bytes.hpp>

#include "common.hpp"

namespace silkworm::remote::kv::api {

struct IndexRangeQuery {
    TxId tx_id{0};
    std::string table;
    Bytes key;
    Timestamp from_timestamp;
    Timestamp to_timestamp;
    bool ascending_order{false};
    uint64_t limit{0};
    uint32_t page_size{0};
    std::string page_token;
};

struct IndexRangeResult {
    ListOfTimestamp timestamps;
    std::string next_page_token;
};

struct RangeResult {
    ListOfBytes keys;
    ListOfBytes values;
    std::string next_page_token;
};

struct HistoryRangeQuery {
    TxId tx_id{0};
    std::string table;
    Timestamp from_timestamp;
    Timestamp to_timestamp;
    bool ascending_order{false};
    uint64_t limit{0};
    uint32_t page_size{0};
    std::string page_token;
};

using HistoryRangeResult = RangeResult;

struct DomainRangeQuery {
    TxId tx_id{0};
    std::string table;
    Bytes from_key;
    Bytes to_key;
    bool ascending_order{false};
    uint64_t limit{0};
    uint32_t page_size{0};
    std::string page_token;
};

using DomainRangeResult = RangeResult;

}  // namespace silkworm::remote::kv::api
