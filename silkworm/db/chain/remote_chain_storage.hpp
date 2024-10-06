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

#include <functional>

#include <agrpc/grpc_context.hpp>

#include <silkworm/db/kv/api/transaction.hpp>

#include "chain_storage.hpp"

namespace silkworm::db::chain {

using BlockProvider = std::function<Task<bool>(BlockNum, HashAsSpan, bool, Block&)>;
using BlockNumberFromTxnHashProvider = std::function<Task<BlockNum>(HashAsSpan)>;
using BlockNumberFromBlockHashProvider = std::function<Task<BlockNum>(HashAsSpan)>;
using CanonicalBlockHashFromNumberProvider = std::function<Task<evmc::bytes32>(BlockNum)>;

struct Providers {
    BlockProvider block;
    BlockNumberFromTxnHashProvider block_number_from_txn_hash;
    BlockNumberFromBlockHashProvider block_number_from_hash;
    CanonicalBlockHashFromNumberProvider canonical_block_hash_from_number;
};

//! RemoteChainStorage must be used when blockchain data is remote with respect to the running component, i.e. it is
//! in remote database (accessed via gRPC KV I/F) or remote snapshot files (accessed via gRPC ETHBACKEND I/F)
class RemoteChainStorage : public ChainStorage {
  public:
    RemoteChainStorage(kv::api::Transaction& tx, Providers& providers);
    ~RemoteChainStorage() override = default;

    [[nodiscard]] Task<ChainConfig> read_chain_config() const override;

    [[nodiscard]] Task<BlockNum> highest_block_number() const override;

    [[nodiscard]] Task<std::optional<BlockNum>> read_block_number(const Hash& hash) const override;

    Task<bool> read_block(HashAsSpan hash, BlockNum number, bool read_senders, Block& block) const override;
    Task<bool> read_block(const Hash& hash, BlockNum number, Block& block) const override;
    Task<bool> read_block(const Hash& hash, Block& block) const override;
    Task<bool> read_block(BlockNum number, bool read_senders, Block& block) const override;

    [[nodiscard]] Task<std::optional<BlockHeader>> read_header(BlockNum number, HashAsArray hash) const override;
    [[nodiscard]] Task<std::optional<BlockHeader>> read_header(BlockNum number, const Hash& hash) const override;
    [[nodiscard]] Task<std::optional<BlockHeader>> read_header(const Hash& hash) const override;

    [[nodiscard]] Task<std::vector<BlockHeader>> read_sibling_headers(BlockNum number) const override;

    Task<bool> read_body(BlockNum number, HashAsArray hash, bool read_senders, BlockBody& body) const override;
    Task<bool> read_body(const Hash& hash, BlockNum number, BlockBody& body) const override;
    Task<bool> read_body(const Hash& hash, BlockBody& body) const override;

    [[nodiscard]] Task<std::optional<Hash>> read_canonical_header_hash(BlockNum number) const override;
    [[nodiscard]] Task<std::optional<BlockHeader>> read_canonical_header(BlockNum number) const override;

    Task<bool> read_canonical_body(BlockNum number, BlockBody& body) const override;

    Task<bool> read_canonical_block(BlockNum number, Block& block) const override;

    [[nodiscard]] Task<bool> has_body(BlockNum number, HashAsArray hash) const override;
    [[nodiscard]] Task<bool> has_body(BlockNum number, const Hash& hash) const override;

    Task<bool> read_rlp_transactions(BlockNum number, const evmc::bytes32& hash, std::vector<Bytes>& rlp_txs) const override;
    Task<bool> read_rlp_transaction(const evmc::bytes32& txn_hash, Bytes& rlp_tx) const override;

    [[nodiscard]] Task<std::optional<intx::uint256>> read_total_difficulty(const Hash& block_hash, BlockNum block_number) const override;

    Task<std::optional<BlockNum>> read_block_number_by_transaction_hash(const evmc::bytes32& transaction_hash) const override;

  private:
    kv::api::Transaction& tx_;
    Providers providers_;
};

}  // namespace silkworm::db::chain
