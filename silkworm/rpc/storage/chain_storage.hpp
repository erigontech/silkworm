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

#include <optional>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/types/block.hpp>

namespace silkworm::rpc {

//! ChainStorage represents the storage for blockchain primary data, namely: chain configuration, block headers,
//! bodies and transactions.
class ChainStorage {
  public:
    virtual ~ChainStorage() = default;

    //! Read the current chain configuration parameters
    [[nodiscard]] virtual Task<std::optional<ChainConfig>> read_chain_config() const = 0;

    //! Get the highest block number
    [[nodiscard]] virtual Task<BlockNum> highest_block_number() const = 0;

    //! Read block number from hash
    [[nodiscard]] virtual Task<std::optional<BlockNum>> read_block_number(const Hash& hash) const = 0;

    //! Read block returning true on success and false on missing block
    virtual Task<bool> read_block(HashAsSpan hash, BlockNum number, bool read_senders, silkworm::Block& block) const = 0;
    virtual Task<bool> read_block(const Hash& hash, BlockNum number, silkworm::Block& block) const = 0;
    virtual Task<bool> read_block(const Hash& hash, silkworm::Block& block) const = 0;

    //! Read canonical block by number returning true on success and false on missing block
    virtual Task<bool> read_block(BlockNum number, bool read_senders, silkworm::Block& block) const = 0;

    //! Read block header with the specified key (block number, hash)
    [[nodiscard]] virtual Task<std::optional<BlockHeader>> read_header(BlockNum number, HashAsArray hash) const = 0;

    //! Read block header with the specified key (block number, hash)
    [[nodiscard]] virtual Task<std::optional<BlockHeader>> read_header(BlockNum number, const Hash& hash) const = 0;

    //! Read block header with the specified hash
    [[nodiscard]] virtual Task<std::optional<BlockHeader>> read_header(const Hash& hash) const = 0;

    //! Read all sibling block headers at specified height
    [[nodiscard]] virtual Task<std::vector<BlockHeader>> read_sibling_headers(BlockNum number) const = 0;

    //! Read block body in output parameter returning true on success and false on missing block
    virtual Task<bool> read_body(BlockNum number, HashAsArray hash, bool read_senders, silkworm::BlockBody& body) const = 0;
    virtual Task<bool> read_body(const Hash& hash, BlockNum number, silkworm::BlockBody& body) const = 0;
    virtual Task<bool> read_body(const Hash& hash, silkworm::BlockBody& body) const = 0;

    //! Read the canonical block hash at specified height
    [[nodiscard]] virtual Task<std::optional<Hash>> read_canonical_hash(BlockNum number) const = 0;

    //! Read the canonical block header at specified height
    [[nodiscard]] virtual Task<std::optional<BlockHeader>> read_canonical_header(BlockNum number) const = 0;

    //! Read the canonical block body at specified height
    virtual Task<bool> read_canonical_body(BlockNum height, BlockBody& body) const = 0;

    //! Read the canonical block at specified height
    virtual Task<bool> read_canonical_block(BlockNum height, silkworm::Block& block) const = 0;

    //! Check the presence of a block body using block number and hash
    [[nodiscard]] virtual Task<bool> has_body(BlockNum number, HashAsArray hash) const = 0;
    [[nodiscard]] virtual Task<bool> has_body(BlockNum number, const Hash& hash) const = 0;

    //! Read the RLP encoded block transactions at specified height
    virtual Task<bool> read_rlp_transactions(BlockNum number, const evmc::bytes32& hash, std::vector<Bytes>& rlp_txs) const = 0;

    virtual Task<bool> read_rlp_transaction(const evmc::bytes32& txn_hash, Bytes& rlp_tx) const = 0;

    //! Read total difficulty for block specified by hash and number
    [[nodiscard]] virtual Task<std::optional<intx::uint256>> read_total_difficulty(const Hash& block_hash, BlockNum block_number) const = 0;

    virtual Task<std::optional<BlockNum>> read_block_number_by_transaction_hash(const evmc::bytes32& transaction_hash) const = 0;

    // Task<silkworm::BlockHeader> read_current_header();

    // Task<evmc::bytes32> read_head_header_hash();

    // Task<uint64_t> read_cumulative_transaction_count(BlockNum block_number);

    // Task<silkworm::Bytes> read_header_rlp(const evmc::bytes32& block_hash, BlockNum block_number);

    // Task<silkworm::Bytes> read_body_rlp(const evmc::bytes32& block_hash, BlockNum block_number);

    // Task<Addresses> read_senders(const evmc::bytes32& block_hash, BlockNum block_number);

    // Task<Receipts> read_raw_receipts(BlockNum block_number);

    // Task<Receipts> read_receipts(const silkworm::BlockWithHash& block_with_hash);

    // Task<Transactions> read_canonical_transactions(uint64_t base_txn_id, uint64_t txn_count);

    // Task<Transactions> read_noncanonical_transactions(uint64_t base_txn_id, uint64_t txn_count);

};

}  // namespace silkworm::rpc
