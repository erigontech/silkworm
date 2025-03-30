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

#include <silkworm/db/access_layer.hpp>

#include "chain_storage.hpp"

namespace silkworm::db::chain {

//! LocalChainStorage must be used when blockchain data is local with respect to the running component, i.e. it is
//! in local database (accessed via MDBX API) or local snapshot files (accessed via custom snapshot API)
class LocalChainStorage : public ChainStorage {
  public:
    explicit LocalChainStorage(db::DataModel data_model)
        : data_model_{data_model} {}
    ~LocalChainStorage() override = default;

    Task<ChainConfig> read_chain_config() const override;

    Task<BlockNum> max_block_num() const override;

    Task<std::optional<BlockNum>> read_block_num(const Hash& hash) const override;

    Task<bool> read_block(HashAsSpan hash, BlockNum block_num, bool read_senders, Block& block) const override;
    Task<bool> read_block(const Hash& hash, BlockNum block_num, Block& block) const override;
    Task<bool> read_block(const Hash& hash, Block& block) const override;
    Task<bool> read_block(BlockNum block_num, bool read_senders, Block& block) const override;

    Task<std::optional<BlockHeader>> read_header(BlockNum block_num, HashAsArray hash) const override;
    Task<std::optional<BlockHeader>> read_header(BlockNum block_num, const Hash& hash) const override;
    Task<std::optional<BlockHeader>> read_header(const Hash& hash) const override;

    Task<std::vector<BlockHeader>> read_sibling_headers(BlockNum block_num) const override;

    Task<bool> read_body(BlockNum block_num, HashAsArray hash, bool read_senders, BlockBody& body) const override;
    Task<bool> read_body(const Hash& hash, BlockNum block_num, BlockBody& body) const override;
    Task<bool> read_body(const Hash& hash, BlockBody& body) const override;

    Task<std::optional<Hash>> read_canonical_header_hash(BlockNum block_num) const override;
    Task<std::optional<BlockHeader>> read_canonical_header(BlockNum block_num) const override;

    Task<bool> read_canonical_body(BlockNum block_num, BlockBody& body) const override;
    Task<std::optional<Bytes>> read_raw_canonical_body_for_storage(BlockNum block_num) const override;

    Task<bool> read_canonical_block(BlockNum block_num, Block& block) const override;

    Task<bool> has_body(BlockNum block_num, HashAsArray hash) const override;
    Task<bool> has_body(BlockNum block_num, const Hash& hash) const override;

    Task<bool> read_rlp_transactions(BlockNum block_num, const evmc::bytes32& hash, std::vector<Bytes>& rlp_txs) const override;
    Task<bool> read_rlp_transaction(const evmc::bytes32& txn_hash, Bytes& rlp_tx) const override;

    Task<std::optional<intx::uint256>> read_total_difficulty(const Hash& block_hash, BlockNum block_num) const override;

    Task<std::pair<std::optional<BlockNum>, std::optional<TxnId>>> read_block_num_by_transaction_hash(const evmc::bytes32& transaction_hash) const override;
    Task<std::optional<Transaction>> read_transaction_by_idx_in_block(BlockNum block_num, uint64_t txn_idx) const override;

    Task<std::pair<std::optional<BlockHeader>, std::optional<Hash>>> read_head_header_and_hash() const override;

  private:
    db::DataModel data_model_;
};

}  // namespace silkworm::db::chain
