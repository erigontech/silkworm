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

#include <silkworm/db/chain/providers.hpp>
#include <silkworm/db/kv/api/transaction.hpp>

#include "chain_storage.hpp"

namespace silkworm::db::chain {

//! RemoteChainStorage must be used when blockchain data is remote with respect to the running component, i.e. it is
//! in remote database (accessed via gRPC KV I/F) or remote snapshot files (accessed via gRPC ETHBACKEND I/F)
class RemoteChainStorage : public ChainStorage {
  public:
    RemoteChainStorage(kv::api::Transaction& tx, Providers providers);
    ~RemoteChainStorage() override = default;

    Task<ChainConfig> read_chain_config() const override;

    Task<BlockNum> highest_block_number() const override;

    Task<std::optional<BlockNum>> read_block_number(const Hash& hash) const override;

    Task<bool> read_block(HashAsSpan hash, BlockNum number, bool read_senders, Block& block) const override;
    Task<bool> read_block(const Hash& hash, BlockNum number, Block& block) const override;
    Task<bool> read_block(const Hash& hash, Block& block) const override;
    Task<bool> read_block(BlockNum number, bool read_senders, Block& block) const override;

    Task<std::optional<BlockHeader>> read_header(BlockNum number, HashAsArray hash) const override;
    Task<std::optional<BlockHeader>> read_header(BlockNum number, const Hash& hash) const override;
    Task<std::optional<BlockHeader>> read_header(const Hash& hash) const override;

    Task<std::vector<BlockHeader>> read_sibling_headers(BlockNum number) const override;

    Task<bool> read_body(BlockNum number, HashAsArray hash, bool read_senders, BlockBody& body) const override;
    Task<bool> read_body(const Hash& hash, BlockNum number, BlockBody& body) const override;
    Task<bool> read_body(const Hash& hash, BlockBody& body) const override;

    Task<std::optional<Hash>> read_canonical_header_hash(BlockNum number) const override;
    Task<std::optional<BlockHeader>> read_canonical_header(BlockNum number) const override;

    Task<bool> read_canonical_body(BlockNum number, BlockBody& body) const override;

    Task<bool> read_canonical_block(BlockNum number, Block& block) const override;

    Task<bool> has_body(BlockNum number, HashAsArray hash) const override;
    Task<bool> has_body(BlockNum number, const Hash& hash) const override;

    Task<bool> read_rlp_transactions(BlockNum number, const evmc::bytes32& hash, std::vector<Bytes>& rlp_txs) const override;
    Task<bool> read_rlp_transaction(const evmc::bytes32& txn_hash, Bytes& rlp_tx) const override;

    Task<std::optional<intx::uint256>> read_total_difficulty(const Hash& block_hash, BlockNum block_number) const override;

    Task<std::optional<BlockNum>> read_block_number_by_transaction_hash(const evmc::bytes32& transaction_hash) const override;
    Task<std::optional<Transaction>> read_transaction_by_idx_in_block(BlockNum block_num, uint64_t txn_id) const override;

  protected:
    Providers& providers() { return providers_; }

  private:
    kv::api::Transaction& tx_;
    Providers providers_;
};

}  // namespace silkworm::db::chain
