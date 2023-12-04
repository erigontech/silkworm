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

#include <optional>
#include <set>
#include <string>
#include <vector>

#include <evmc/evmc.hpp>
#include <intx/intx.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/transaction.hpp>
#include <silkworm/rpc/json/access_list_entry.hpp>
#include <silkworm/rpc/json/block.hpp>
#include <silkworm/rpc/json/call.hpp>
#include <silkworm/rpc/json/call_bundle.hpp>
#include <silkworm/rpc/json/execution_payload.hpp>
#include <silkworm/rpc/json/filter.hpp>
#include <silkworm/rpc/json/fork_choice.hpp>
#include <silkworm/rpc/json/glaze.hpp>
#include <silkworm/rpc/json/log.hpp>
#include <silkworm/rpc/json/node_info.hpp>
#include <silkworm/rpc/json/payload_attributes.hpp>
#include <silkworm/rpc/json/receipt.hpp>
#include <silkworm/rpc/json/transaction.hpp>
#include <silkworm/rpc/json/transition_configuration.hpp>
#include <silkworm/rpc/json/withdrawal.hpp>
#include <silkworm/rpc/types/block.hpp>
#include <silkworm/rpc/types/call.hpp>
#include <silkworm/rpc/types/call_bundle.hpp>
#include <silkworm/rpc/types/chain_config.hpp>
#include <silkworm/rpc/types/chain_traffic.hpp>
#include <silkworm/rpc/types/error.hpp>
#include <silkworm/rpc/types/execution_payload.hpp>
#include <silkworm/rpc/types/filter.hpp>
#include <silkworm/rpc/types/issuance.hpp>
#include <silkworm/rpc/types/log.hpp>
#include <silkworm/rpc/types/node_info.hpp>
#include <silkworm/rpc/types/peer_info.hpp>
#include <silkworm/rpc/types/receipt.hpp>
#include <silkworm/rpc/types/syncing_data.hpp>
#include <silkworm/rpc/types/transaction.hpp>

namespace evmc {

void to_json(nlohmann::json& json, const address& addr);
void from_json(const nlohmann::json& json, address& addr);

void to_json(nlohmann::json& json, const bytes32& b32);
void from_json(const nlohmann::json& json, bytes32& b32);

}  // namespace evmc

namespace intx {

void from_json(const nlohmann::json& json, uint256& ui256);

}  // namespace intx

namespace silkworm {

void to_json(nlohmann::json& json, const BlockHeader& ommer);

}  // namespace silkworm

namespace silkworm::rpc {

void to_json(nlohmann::json& json, const PeerInfo& peer_info);

void to_json(nlohmann::json& json, const struct ChainTraffic& chain_traffic);

void to_json(nlohmann::json& json, const struct TxPoolStatusInfo& status_info);

void to_json(nlohmann::json& json, const AccessListResult& access_list_result);

void to_json(nlohmann::json& json, const SyncingData& syncing_data);

void to_json(nlohmann::json& json, const StageData& stage_data);

void to_json(nlohmann::json& json, const Rlp& rlp);

void to_json(nlohmann::json& json, const BlockDetailsResponse& b);

void to_json(nlohmann::json& json, const BlockTransactionsResponse& b);

void to_json(nlohmann::json& json, const TransactionsWithReceipts& b);

void to_json(nlohmann::json& json, const PayloadStatus& payload_status);

void to_json(nlohmann::json& json, const Forks& forks);

void to_json(nlohmann::json& json, const Issuance& issuance);

void to_json(nlohmann::json& json, const Error& error);
void to_json(nlohmann::json& json, const RevertError& error);

void to_json(nlohmann::json& json, const std::set<evmc::address>& addresses);

uint64_t from_quantity(const std::string& hex_quantity);

std::string to_hex(uint64_t number);
std::string to_hex_no_leading_zeros(uint64_t number);
std::string to_hex_no_leading_zeros(silkworm::ByteView bytes);
std::string to_quantity(uint64_t number);
std::string to_quantity(intx::uint256 number);
std::string to_quantity(silkworm::ByteView bytes);

void to_quantity(std::span<char> hex_bytes, uint64_t number);
void to_quantity(std::span<char> hex_bytes, intx::uint256 number);
void to_quantity(std::span<char> hex_bytes, silkworm::ByteView bytes);
void to_hex(std::span<char> hex_bytes, silkworm::ByteView bytes);

nlohmann::json make_json_content(const nlohmann::json& request_json);
nlohmann::json make_json_content(const nlohmann::json& request_json, const nlohmann::json& result);
nlohmann::json make_json_error(const nlohmann::json& request_json, int code, const std::string& message);
nlohmann::json make_json_error(const nlohmann::json& request_json, const RevertError& error);

using JsonRpcId = std::variant<uint32_t, std::string, std::nullptr_t>;
JsonRpcId make_jsonrpc_id(const nlohmann::json& request_json);

}  // namespace silkworm::rpc

namespace nlohmann {

template <>
struct adl_serializer<silkworm::rpc::BlockNumberOrHash> {
    static silkworm::rpc::BlockNumberOrHash from_json(const json& json) {
        if (json.is_string()) {
            return silkworm::rpc::BlockNumberOrHash{json.get<std::string>()};
        } else if (json.is_number()) {
            return silkworm::rpc::BlockNumberOrHash{json.get<silkworm::BlockNum>()};
        }
        return silkworm::rpc::BlockNumberOrHash{0};
    }
};

}  // namespace nlohmann
