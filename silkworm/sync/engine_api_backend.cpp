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

#include "engine_api_backend.hpp"

namespace silkworm::chainsync {

awaitable<rpc::PayloadStatus> EngineApiBackend::engine_new_payload(const rpc::ExecutionPayload& payload) {
    co_return co_await pos_sync_.new_payload(payload);
}

awaitable<rpc::ExecutionPayloadAndValue> EngineApiBackend::engine_get_payload(uint64_t payload_id) {
    co_return co_await pos_sync_.get_payload(payload_id);
}

awaitable<rpc::ForkChoiceUpdatedReply> EngineApiBackend::engine_forkchoice_updated(const rpc::ForkChoiceUpdatedRequest& fcu_request) {
    co_return co_await pos_sync_.fork_choice_update(fcu_request.fork_choice_state, fcu_request.payload_attributes);
}

awaitable<rpc::ExecutionPayloadBodies> EngineApiBackend::engine_get_payload_bodies_by_hash(const std::vector<Hash>& block_hashes) {
    co_return co_await pos_sync_.get_payload_bodies_by_hash(block_hashes);
}

awaitable<evmc::address> EngineApiBackend::etherbase() {
    co_return evmc::address{};
}

awaitable<uint64_t> EngineApiBackend::protocol_version() {
    co_return 0;
}

awaitable<uint64_t> EngineApiBackend::net_version() {
    co_return 0;
}

awaitable<std::string> EngineApiBackend::client_version() {
    co_return "";
}

awaitable<uint64_t> EngineApiBackend::net_peer_count() {
    co_return 0;
}

awaitable<rpc::NodeInfos> EngineApiBackend::engine_node_info() {
    co_return 0;
}

awaitable<rpc::PeerInfos> EngineApiBackend::peers() {
    co_return rpc::PeerInfos{};
}

}  // namespace silkworm::chainsync
