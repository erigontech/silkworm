/*
   Copyright 2023 The Silkworm Authors

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

#include <iostream>
#include <vector>

#include <evmc/evmc.hpp>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wshadow"
#include <glaze/glaze.hpp>
#pragma GCC diagnostic pop
#include <silkworm/core/common/base.hpp>

namespace silkworm::rpc {

struct Log {
    /* raw fields */
    evmc::address address;
    std::vector<evmc::bytes32> topics;
    silkworm::Bytes data;

    /* derived fields */
    uint64_t block_number{0};
    evmc::bytes32 tx_hash;
    uint32_t tx_index{0};
    evmc::bytes32 block_hash;
    uint32_t index{0};
    bool removed{false};
};

typedef std::vector<Log> Logs;

static constexpr auto addressSize = 64;
static constexpr auto hashSize = 128;
static constexpr auto int64Size = 32;
static constexpr auto dataSize = 4096;

struct GlazeJsonLogItem {
    char address[addressSize];
    char tx_hash[hashSize];
    char block_hash[hashSize];
    char block_number[int64Size];
    char tx_index[int64Size];
    char index[int64Size];
    char data[4096];
    bool removed;
    std::vector<std::string> topics;

    struct glaze {
        using T = GlazeJsonLogItem;
        static constexpr auto value = glz::object(
            "address", &T::address,
            "transactionHash", &T::tx_hash,
            "blockHash", &T::block_hash,
            "blockNumber", &T::block_number,
            "transactionIndex", &T::tx_index,
            "logIndex", &T::index,
            "data", &T::data,
            "removed", &T::removed,
            "topics", &T::topics);
    };
};

static constexpr auto jsonVersionSize = 8;

struct GlazeJsonLog {
    char jsonrpc[jsonVersionSize] = "2.0";
    uint32_t id;
    std::vector<GlazeJsonLogItem> log_json_list;
    struct glaze {
        using T = GlazeJsonLog;
        static constexpr auto value = glz::object(
            "jsonrpc", &T::jsonrpc,
            "id", &T::id,
            "result", &T::log_json_list);
    };
};

std::ostream& operator<<(std::ostream& out, const Log& log);

}  // namespace silkworm::rpc
