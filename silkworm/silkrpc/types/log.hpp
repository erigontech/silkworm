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

#include <silkworm/core/common/base.hpp>
#include <glaze/glaze.hpp>
#include <glaze/core/meta.hpp>

template <>
struct glz::meta<evmc::bytes32> {
   using T = evmc::bytes32;
   static constexpr auto value = object(
      "bytes", &T::bytes, "bytes is a array"
   );
};

template <>
struct glz::meta<evmc::address> {
   using T = evmc::address;
   static constexpr auto value = object(
      "bytes", &T::bytes, "bytes is a array"
   );
};


namespace silkrpc {

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

#ifdef notdef
    struct glaze {
     using T = Log;
     static constexpr auto value = glz::object(
        "address", &T::address,
        "topics", &T::topics,
        "data", &T::data,
        "block_number", &T::block_number,
        "tx_hash", &T::tx_hash,
        "tx_index", &T::tx_index,
        "block_hash", &T::block_hash,
        "index", &T::index,
        "removed", &T::removed
     );
  };
#endif
};

typedef std::vector<Log> Logs;

// INPUT
struct eth_log_item {
    //char from_block[16];
    //char to_block[16];
    //char address[128];
    std::string from_block;
    std::string to_block;
    std::string address;
    std::vector<std::vector<std::string>> topics;
    //std::vector<std::string> topics1;
    std::string block_hash;

        //"topics", &T::topics1,
    struct glaze {
     using T = eth_log_item;
     static constexpr auto value = glz::object(
        "address", &T::address,
        "fromBlock", &T::from_block,
        "toBlock", &T::to_block,
        "topics", &T::topics,
        "blockHash", &T::block_hash
     );
   };
};

struct eth_getLogs_request_json {
    //char jsonrpc[8];
    //char method[32];
    std::string jsonrpc;
    std::string method;
    std::vector<eth_log_item> params;
    uint32_t id;
    struct glaze {
     using T = eth_getLogs_request_json;
     static constexpr auto value = glz::object(
        "jsonrpc", &T::jsonrpc,
        "id", &T::id,
        "method", &T::method,
        "params", &T::params
     );
   };
};

std::ostream& operator<<(std::ostream& out, const Log& log);

} // namespace silkrpc

