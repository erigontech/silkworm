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

#include <memory>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/rpc/ethbackend/backend.hpp>
#include <silkworm/sync/sync_pos.hpp>

namespace silkworm::chainsync {

class EngineApiBackend : public rpc::ethbackend::BackEnd {
  public:
    explicit EngineApiBackend(PoSSync& pos_sync) : pos_sync_{pos_sync} {}
    ~EngineApiBackend() override = default;

    EngineApiBackend(const EngineApiBackend&) = delete;
    EngineApiBackend& operator=(const EngineApiBackend&) = delete;

    Task<rpc::PayloadStatus> engine_new_payload(const rpc::ExecutionPayload& payload) override;
    Task<rpc::ExecutionPayloadAndValue> engine_get_payload(uint64_t payload_id) override;
    Task<rpc::ForkChoiceUpdatedReply> engine_forkchoice_updated(const rpc::ForkChoiceUpdatedRequest& fcu_request) override;
    Task<rpc::ExecutionPayloadBodies> engine_get_payload_bodies_by_hash(const std::vector<Hash>& block_hashes) override;
    Task<rpc::ExecutionPayloadBodies> engine_get_payload_bodies_by_range(BlockNum start, uint64_t count) override;
    Task<evmc::address> etherbase() override;
    Task<uint64_t> protocol_version() override;
    Task<uint64_t> net_version() override;
    Task<std::string> client_version() override;
    Task<uint64_t> net_peer_count() override;
    Task<rpc::NodeInfos> engine_node_info() override;
    Task<rpc::PeerInfos> peers() override;
    Task<bool> get_block(uint64_t block_number, const HashAsSpan& hash, bool read_senders, silkworm::Block& block) override;
    Task<uint64_t> get_block_number_from_txn_hash(const HashAsSpan& hash) override;

  private:
    //! The Execution Layer Engine API RPC server.
    PoSSync& pos_sync_;
};

}  // namespace silkworm::chainsync
