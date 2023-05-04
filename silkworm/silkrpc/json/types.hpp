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
#include <silkworm/silkrpc/json/call.hpp>
#include <silkworm/silkrpc/json/execution_payload.hpp>
#include <silkworm/silkrpc/json/filter.hpp>
#include <silkworm/silkrpc/json/log.hpp>
#include <silkworm/silkrpc/json/payload_attributes.hpp>
#include <silkworm/silkrpc/json/receipt.hpp>
#include <silkworm/silkrpc/types/block.hpp>
#include <silkworm/silkrpc/types/call.hpp>
#include <silkworm/silkrpc/types/chain_config.hpp>
#include <silkworm/silkrpc/types/chain_traffic.hpp>
#include <silkworm/silkrpc/types/error.hpp>
#include <silkworm/silkrpc/types/execution_payload.hpp>
#include <silkworm/silkrpc/types/filter.hpp>
#include <silkworm/silkrpc/types/issuance.hpp>
#include <silkworm/silkrpc/types/log.hpp>
#include <silkworm/silkrpc/types/node_info.hpp>
#include <silkworm/silkrpc/types/peer_info.hpp>
#include <silkworm/silkrpc/types/receipt.hpp>
#include <silkworm/silkrpc/types/syncing_data.hpp>
#include <silkworm/silkrpc/types/transaction.hpp>

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

void to_json(nlohmann::json& json, const Transaction& transaction);

void from_json(const nlohmann::json& json, AccessListEntry& entry);

}  // namespace silkworm

namespace silkworm::rpc {

inline constexpr auto jsonVersionSize = 8;
inline constexpr auto addressSize = 64;
inline constexpr auto hashSize = 128;
inline constexpr auto int64Size = 32;
inline constexpr auto dataSize = 4096;
inline constexpr auto ethCallResultFixedSize = 2048;

void to_json(nlohmann::json& json, const struct NodeInfo& node_info);

void to_json(nlohmann::json& json, const struct NodeInfoPorts& node_info_ports);

void to_json(nlohmann::json& json, const PeerInfo& peer_info);

void to_json(nlohmann::json& json, const struct ChainTraffic& chain_traffic);

void to_json(nlohmann::json& json, const struct TxPoolStatusInfo& status_info);

void to_json(nlohmann::json& json, const AccessListResult& access_list_result);

void to_json(nlohmann::json& json, const struct CallBundleTxInfo& tx_info);

void to_json(nlohmann::json& json, const struct CallBundleInfo& bundle_info);

void to_json(nlohmann::json& json, const SyncingData& syncing_data);

void to_json(nlohmann::json& json, const StageData& stage_data);

void to_json(nlohmann::json& json, const Rlp& rlp);

void to_json(nlohmann::json& json, const Block& b);

void to_json(nlohmann::json& json, const BlockDetailsResponse& b);

void to_json(nlohmann::json& json, const BlockTransactionsResponse& b);

void to_json(nlohmann::json& json, const Transaction& transaction);

void to_json(nlohmann::json& json, const ForkChoiceState& forkchoice_state);
void from_json(const nlohmann::json& json, ForkChoiceState& forkchoice_state);

void to_json(nlohmann::json& json, const ForkChoiceUpdatedReply& forkchoice_updated_reply);

void to_json(nlohmann::json& json, const PayloadStatus& payload_status);

void to_json(nlohmann::json& json, const TransitionConfiguration& transition_configuration);
void from_json(const nlohmann::json& json, TransitionConfiguration& transition_configuration);

void to_json(nlohmann::json& json, const Forks& forks);

void to_json(nlohmann::json& json, const Issuance& issuance);

void to_json(nlohmann::json& json, const Error& error);
void to_json(nlohmann::json& json, const RevertError& error);

void to_json(nlohmann::json& json, const std::set<evmc::address>& addresses);

std::string to_hex_no_leading_zeros(uint64_t number);
std::string to_hex_no_leading_zeros(silkworm::ByteView bytes);
std::string to_quantity(uint64_t number);
std::string to_quantity(intx::uint256 number);
std::string to_quantity(silkworm::ByteView bytes);

void to_quantity(std::span<char> hex_bytes, uint64_t number);
void to_quantity(std::span<char> hex_bytes, intx::uint256 number);
void to_quantity(std::span<char> hex_bytes, silkworm::ByteView bytes);
void to_hex(std::span<char> hex_bytes, silkworm::ByteView bytes);

nlohmann::json make_json_content(uint32_t id);
nlohmann::json make_json_content(uint32_t id, const nlohmann::json& result);
nlohmann::json make_json_error(uint32_t id, int64_t code, const std::string& message);
nlohmann::json make_json_error(uint32_t id, const RevertError& error);

// GLAZE
void make_glaze_json_error(std::string& reply, uint32_t id, const int error_id, const std::string& message);
void make_glaze_json_error(std::string& reply, uint32_t id, const RevertError& error);

}  // namespace silkworm::rpc

namespace nlohmann {

template <>
struct adl_serializer<silkworm::rpc::BlockNumberOrHash> {
    static silkworm::rpc::BlockNumberOrHash from_json(const json& json) {
        if (json.is_string()) {
            return silkworm::rpc::BlockNumberOrHash{json.get<std::string>()};
        } else if (json.is_number()) {
            return silkworm::rpc::BlockNumberOrHash{json.get<std::uint64_t>()};
        }
        return silkworm::rpc::BlockNumberOrHash{0};
    }
};

}  // namespace nlohmann
