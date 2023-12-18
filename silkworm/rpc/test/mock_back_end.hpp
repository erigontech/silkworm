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
#include <string>

#include <boost/asio/awaitable.hpp>
#include <catch2/catch.hpp>
#include <gmock/gmock.h>

#include <silkworm/core/common/base.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/rpc/common/util.hpp>

namespace silkworm::rpc::test {

class BackEndMock : public ethbackend::BackEnd {  // NOLINT
  public:
    MOCK_METHOD((Task<evmc::address>), etherbase, ());
    MOCK_METHOD((Task<uint64_t>), protocol_version, ());
    MOCK_METHOD((Task<uint64_t>), net_version, ());
    MOCK_METHOD((Task<std::string>), client_version, ());
    MOCK_METHOD((Task<uint64_t>), net_peer_count, ());
    MOCK_METHOD((Task<ExecutionPayloadAndValue>), engine_get_payload, (uint64_t));
    MOCK_METHOD((Task<PayloadStatus>), engine_new_payload, (const ExecutionPayload&));
    MOCK_METHOD((Task<ForkChoiceUpdatedReply>), engine_forkchoice_updated, (const ForkChoiceUpdatedRequest&));
    MOCK_METHOD((Task<ExecutionPayloadBodies>), engine_get_payload_bodies_by_hash, (const std::vector<Hash>&));
    MOCK_METHOD((Task<ExecutionPayloadBodies>), engine_get_payload_bodies_by_range, (BlockNum start, uint64_t count));
    MOCK_METHOD((Task<NodeInfos>), engine_node_info, ());
    MOCK_METHOD((Task<PeerInfos>), peers, ());
    MOCK_METHOD((Task<bool>), get_block, (BlockNum block_number, const HashAsSpan& hash, bool, silkworm::Block&));
    MOCK_METHOD((Task<BlockNum>), get_block_number_from_txn_hash, (const HashAsSpan& hash));
};

}  // namespace silkworm::rpc::test
