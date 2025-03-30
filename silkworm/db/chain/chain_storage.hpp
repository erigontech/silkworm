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

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/types/block.hpp>

namespace silkworm::db::chain {

//! ChainStorage represents the storage for blockchain primary data, namely: chain configuration, block headers,
//! bodies and transactions.
class ChainStorage {
  public:
    virtual ~ChainStorage() = default;

    //! Read the current chain configuration parameters
    virtual Task<ChainConfig> read_chain_config() const = 0;

    //! Get the max block number
    virtual Task<BlockNum> max_block_num() const = 0;

    //! Read block number from hash
    virtual Task<std::optional<BlockNum>> read_block_num(const Hash& hash) const = 0;

    //! Read block returning true on success and false on missing block
    virtual Task<bool> read_block(HashAsSpan hash, BlockNum block_num, bool read_senders, Block& block) const = 0;
    virtual Task<bool> read_block(const Hash& hash, BlockNum block_num, Block& block) const = 0;
    virtual Task<bool> read_block(const Hash& hash, Block& block) const = 0;

    //! Read canonical block by number returning true on success and false on missing block
    virtual Task<bool> read_block(BlockNum block_num, bool read_senders, Block& block) const = 0;

    //! Read block header with the specified key (block_num, hash)
    virtual Task<std::optional<BlockHeader>> read_header(BlockNum block_num, HashAsArray hash) const = 0;

    //! Read block header with the specified key (block_num, hash)
    virtual Task<std::optional<BlockHeader>> read_header(BlockNum block_num, const Hash& hash) const = 0;

    //! Read block header with the specified hash
    virtual Task<std::optional<BlockHeader>> read_header(const Hash& hash) const = 0;

    //! Read all sibling block headers at specified block_num
    virtual Task<std::vector<BlockHeader>> read_sibling_headers(BlockNum block_num) const = 0;

    //! Read block body in output parameter returning true on success and false on missing block
    virtual Task<bool> read_body(BlockNum block_num, HashAsArray hash, bool read_senders, BlockBody& body) const = 0;
    virtual Task<bool> read_body(const Hash& hash, BlockNum block_num, BlockBody& body) const = 0;
    virtual Task<bool> read_body(const Hash& hash, BlockBody& body) const = 0;

    //! Read the canonical block hash at specified block_num
    virtual Task<std::optional<Hash>> read_canonical_header_hash(BlockNum block_num) const = 0;

    //! Read the canonical block header at specified block_num
    virtual Task<std::optional<BlockHeader>> read_canonical_header(BlockNum block_num) const = 0;

    //! Read the canonical block body at specified block_num
    virtual Task<bool> read_canonical_body(BlockNum block_num, BlockBody& body) const = 0;

    //! Read the raw storage serialization for the canonical block body at specified block_num
    virtual Task<std::optional<Bytes>> read_raw_canonical_body_for_storage(BlockNum block_num) const = 0;

    //! Read the canonical block at specified block_num
    virtual Task<bool> read_canonical_block(BlockNum block_num, Block& block) const = 0;

    //! Check the presence of a block body using block number and hash
    virtual Task<bool> has_body(BlockNum block_num, HashAsArray hash) const = 0;
    virtual Task<bool> has_body(BlockNum block_num, const Hash& hash) const = 0;

    //! Read the RLP encoded block transactions at specified block_num
    virtual Task<bool> read_rlp_transactions(BlockNum block_num, const evmc::bytes32& hash, std::vector<Bytes>& rlp_txs) const = 0;

    virtual Task<bool> read_rlp_transaction(const evmc::bytes32& txn_hash, Bytes& rlp_tx) const = 0;

    //! Read total difficulty for block specified by hash and number
    virtual Task<std::optional<intx::uint256>> read_total_difficulty(const Hash& block_hash, BlockNum block_num) const = 0;

    virtual Task<std::pair<std::optional<BlockNum>, std::optional<TxnId>>> read_block_num_by_transaction_hash(const evmc::bytes32& transaction_hash) const = 0;
    virtual Task<std::optional<Transaction>> read_transaction_by_idx_in_block(BlockNum block_num, uint64_t txn_idx) const = 0;

    virtual Task<std::pair<std::optional<BlockHeader>, std::optional<Hash>>> read_head_header_and_hash() const = 0;
};

}  // namespace silkworm::db::chain
