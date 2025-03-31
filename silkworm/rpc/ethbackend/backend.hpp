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

#include <string>
#include <vector>

#include <silkworm/infra/concurrency/task.hpp>

#include <evmc/evmc.hpp>

#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/hash.hpp>
#include <silkworm/rpc/types/execution_payload.hpp>
#include <silkworm/rpc/types/node_info.hpp>
#include <silkworm/rpc/types/peer_info.hpp>

namespace silkworm::rpc::ethbackend {

class BackEnd {
  public:
    virtual ~BackEnd() = default;
    virtual Task<evmc::address> etherbase() = 0;
    virtual Task<uint64_t> protocol_version() = 0;
    virtual Task<uint64_t> net_version() = 0;
    virtual Task<std::string> client_version() = 0;
    virtual Task<uint64_t> net_peer_count() = 0;
    virtual Task<NodeInfos> engine_node_info() = 0;
    virtual Task<PeerInfos> peers() = 0;
    virtual Task<bool> get_block(BlockNum block_num, const HashAsSpan& hash, bool read_senders, silkworm::Block& block) = 0;
    virtual Task<std::optional<std::pair<BlockNum, TxnId>>> get_block_num_from_txn_hash(const HashAsSpan& hash) = 0;
    virtual Task<std::optional<BlockNum>> get_block_num_from_hash(const HashAsSpan& hash) = 0;
    virtual Task<std::optional<evmc::bytes32>> get_block_hash_from_block_num(BlockNum block_num) = 0;
    virtual Task<std::optional<Bytes>> canonical_body_for_storage(BlockNum block_num) = 0;
};

}  // namespace silkworm::rpc::ethbackend
