// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>

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

    Task<std::optional<std::pair<BlockNum, TxnId>>> read_block_num_by_transaction_hash(const evmc::bytes32& transaction_hash) const override;
    Task<std::optional<Transaction>> read_transaction_by_idx_in_block(BlockNum block_num, uint64_t txn_idx) const override;

    Task<std::pair<std::optional<BlockHeader>, std::optional<Hash>>> read_head_header_and_hash() const override;

  protected:
    Providers& providers() { return providers_; }

  private:
    kv::api::Transaction& tx_;
    Providers providers_;
};

}  // namespace silkworm::db::chain
