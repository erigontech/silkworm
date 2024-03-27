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

#include <chrono>

using namespace std::chrono_literals;

namespace silkworm::chainsync {

Task<rpc::PayloadStatus> EngineApiBackend::engine_new_payload(const rpc::NewPayloadRequest& request) {
    co_return co_await pos_sync_.new_payload(request, 8s);
}

Task<rpc::ExecutionPayloadAndValue> EngineApiBackend::engine_get_payload(uint64_t payload_id) {
    co_return co_await pos_sync_.get_payload(payload_id, 1s);
}

Task<rpc::ForkChoiceUpdatedReply> EngineApiBackend::engine_forkchoice_updated(const rpc::ForkChoiceUpdatedRequest& request) {
    co_return co_await pos_sync_.fork_choice_update(request, 8s);
}

Task<rpc::ExecutionPayloadBodies> EngineApiBackend::engine_get_payload_bodies_by_hash(const std::vector<Hash>& block_hashes) {
    co_return co_await pos_sync_.get_payload_bodies_by_hash(block_hashes, 10s);
}

Task<rpc::ExecutionPayloadBodies> EngineApiBackend::engine_get_payload_bodies_by_range(BlockNum start, uint64_t count) {
    co_return co_await pos_sync_.get_payload_bodies_by_range(start, count, 10s);
}

Task<evmc::address> EngineApiBackend::etherbase() {
    throw std::logic_error{"EngineApiBackend::etherbase not implemented"};
}

Task<uint64_t> EngineApiBackend::protocol_version() {
    throw std::logic_error{"EngineApiBackend::protocol_version not implemented"};
}

Task<uint64_t> EngineApiBackend::net_version() {
    throw std::logic_error{"EngineApiBackend::net_version not implemented"};
}

Task<std::string> EngineApiBackend::client_version() {
    throw std::logic_error{"EngineApiBackend::client_version not implemented"};
}

Task<uint64_t> EngineApiBackend::net_peer_count() {
    throw std::logic_error{"EngineApiBackend::net_peer_count not implemented"};
}

Task<rpc::NodeInfos> EngineApiBackend::engine_node_info() {
    throw std::logic_error{"EngineApiBackend::engine_node_info not implemented"};
}

Task<rpc::PeerInfos> EngineApiBackend::peers() {
    throw std::logic_error{"EngineApiBackend::peers not implemented"};
}

Task<bool> EngineApiBackend::get_block(uint64_t /* block_number*/, const HashAsSpan& /* hash */, bool /*read_senders*/, silkworm::Block& /*block*/) {
    throw std::logic_error{"EngineApiBackend::get_block not implemented"};
}

Task<uint64_t> EngineApiBackend::get_block_number_from_txn_hash(const HashAsSpan& /* hashs */) {
    throw std::logic_error{"EngineApiBackend::get_block_number_from_txn_hash not implemented"};
}

}  // namespace silkworm::chainsync
