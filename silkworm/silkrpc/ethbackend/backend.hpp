/*
   Copyright 2022 The Silkrpc Authors

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

#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <evmc/evmc.hpp>
#include <silkworm/silkrpc/types/node_info.hpp>
#include <silkworm/silkrpc/types/execution_payload.hpp>

namespace silkrpc::ethbackend {

class BackEnd {
public:
    virtual ~BackEnd() = default;
    virtual boost::asio::awaitable<evmc::address> etherbase() = 0;
    virtual boost::asio::awaitable<uint64_t> protocol_version() = 0;
    virtual boost::asio::awaitable<uint64_t> net_version() = 0;
    virtual boost::asio::awaitable<std::string> client_version() = 0;
    virtual boost::asio::awaitable<uint64_t> net_peer_count() = 0;
    virtual boost::asio::awaitable<ExecutionPayload> engine_get_payload_v1(uint64_t payload_id) = 0;
    virtual boost::asio::awaitable<PayloadStatus> engine_new_payload_v1(ExecutionPayload payload) = 0;
    virtual boost::asio::awaitable<ForkChoiceUpdatedReply> engine_forkchoice_updated_v1(ForkChoiceUpdatedRequest forkchoice_updated_request) = 0;
    virtual boost::asio::awaitable<std::vector<NodeInfo>> engine_node_info() = 0;
};

} // namespace silkrpc::ethbackend

