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

//#include <optional>
//#include <set>
//#include <string>
//#include <vector>

//#include <evmc/evmc.hpp>
//#include <intx/intx.hpp>
#include <nlohmann/json.hpp>

//#include <silkworm/core/types/block.hpp>
//#include <silkworm/core/types/transaction.hpp>
//#include <silkworm/silkrpc/types/block.hpp>
//#include <silkworm/silkrpc/types/call.hpp>
//#include <silkworm/silkrpc/types/chain_config.hpp>
//#include <silkworm/silkrpc/types/chain_traffic.hpp>
//#include <silkworm/silkrpc/types/error.hpp>
//#include <silkworm/silkrpc/types/execution_payload.hpp>
//#include <silkworm/silkrpc/types/filter.hpp>
//#include <silkworm/silkrpc/types/issuance.hpp>
#include <silkworm/silkrpc/types/log.hpp>
//#include <silkworm/silkrpc/types/node_info.hpp>
//#include <silkworm/silkrpc/types/receipt.hpp>
//#include <silkworm/silkrpc/types/syncing_data.hpp>
//#include <silkworm/silkrpc/types/transaction.hpp>

namespace silkworm::rpc {

void to_json(nlohmann::json& json, const Log& log);

void from_json(const nlohmann::json& json, Log& log);

void make_glaze_json_content(std::string& reply, uint32_t id, const Logs& logs);

}  // namespace silkworm::rpc
