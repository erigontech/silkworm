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

#include <silkworm/silkrpc/ethbackend/backend.hpp>
#include <silkworm/sync/sync_pos.hpp>

namespace silkworm::chainsync {

using boost::asio::awaitable;

class EngineApiBackend : public rpc::ethbackend::BackEnd {
  public:
    explicit EngineApiBackend(PoSSync& pos_sync) : pos_sync_{pos_sync} {}
    ~EngineApiBackend() override = default;

    EngineApiBackend(const EngineApiBackend&) = delete;
    EngineApiBackend& operator=(const EngineApiBackend&) = delete;

    awaitable<rpc::PayloadStatus> engine_new_payload_v1(const rpc::ExecutionPayload& payload) override;
    awaitable<rpc::ExecutionPayload> engine_get_payload_v1(uint64_t payload_id) override;
    awaitable<rpc::ForkChoiceUpdatedReply> engine_forkchoice_updated_v1(const rpc::ForkChoiceUpdatedRequest& fcu_request) override;
    awaitable<evmc::address> etherbase() override;
    awaitable<uint64_t> protocol_version() override;
    awaitable<uint64_t> net_version() override;
    awaitable<std::string> client_version() override;
    awaitable<uint64_t> net_peer_count() override;
    awaitable<rpc::NodeInfos> engine_node_info() override;
    awaitable<rpc::PeerInfos> peers() override;

  private:
    //! The Execution Layer Engine API RPC server.
    PoSSync& pos_sync_;
};

}  // namespace silkworm::chainsync
