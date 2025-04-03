// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
