// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Database Access Layer
// See Erigon core/rawdb/accessors_chain.go

#include <functional>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include <absl/functional/function_ref.h>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/types/account.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/block_body_for_storage.hpp>
#include <silkworm/core/types/hash.hpp>
#include <silkworm/core/types/receipt.hpp>
#include <silkworm/db/data_store.hpp>
#include <silkworm/db/datastore/kvdb/mdbx.hpp>
#include <silkworm/db/util.hpp>

namespace silkworm::snapshots {
class SnapshotRepository;
}

namespace silkworm::db {

using datastore::kvdb::ROTxn;
using datastore::kvdb::RWTxn;

//! \brief Pulls database schema version
std::optional<VersionBase> read_schema_version(ROTxn& txn);

//! \brief Writes database schema version (throws on downgrade)
void write_schema_version(RWTxn& txn, const VersionBase& schema_version);

//! \brief Updates database info with build info at provided block_num
//! \details Is useful to track whether increasing block numbers have been affected by
//! upgrades or downgrades of Silkworm's build
void write_build_info_block_num(RWTxn& txn, const Bytes& key, BlockNum block_num);

//! \brief Reads a header with the specified key (block number, hash)
std::optional<BlockHeader> read_header(ROTxn& txn, BlockNum block_num, const uint8_t (&hash)[kHashLength]);
std::optional<BlockHeader> read_header(ROTxn& txn, BlockNum block_num, const evmc::bytes32&);
std::optional<BlockHeader> read_header(ROTxn& txn, ByteView key);
Bytes read_header_raw(ROTxn& txn, ByteView key);

//! \brief Reads a header with the specified hash
std::optional<BlockHeader> read_header(ROTxn& txn, const evmc::bytes32& hash);

//! \brief Reads all headers at the specified block_num
std::vector<BlockHeader> read_headers(ROTxn& txn, BlockNum block_num);

//! \brief Reads all headers at the specified block_num and pass them to process_func callback
size_t read_headers(ROTxn& txn, BlockNum block_num, std::function<void(BlockHeader)> process_func);

//! \brief Reads the canonical head
std::tuple<BlockNum, evmc::bytes32> read_canonical_head(ROTxn& txn);

//! \brief Reads the canonical header from a block number
std::optional<BlockHeader> read_canonical_header(ROTxn& txn, BlockNum block_num);

//! \brief Writes given header to table::kHeaders
void write_header(RWTxn& txn, const BlockHeader& header, bool with_header_numbers = false);

//! \brief Writes given header to table::kHeaders and returns its hash
evmc::bytes32 write_header_ex(RWTxn& txn, const BlockHeader& header, bool with_header_numbers);

//! \brief Deletes a header from table::kHeaders
void delete_header(RWTxn& txn, BlockNum block_num, const evmc::bytes32& hash);

//! \brief Finds the first header with a number >= min_block_num in table::kHeaders
std::optional<BlockNum> read_stored_header_number_after(ROTxn& txn, BlockNum min_block_num);

//! \brief Read block number from hash
std::optional<BlockNum> read_block_num(ROTxn& txn, const evmc::bytes32& hash);

//! \brief Writes header hash in table::kHeaderNumbers
void write_header_number(RWTxn& txn, const uint8_t (&hash)[kHashLength], BlockNum block_num);

//! \brief Deletes a header hash to number entry in table::kHeaderNumbers
void delete_header_number(RWTxn& txn, const evmc::bytes32& hash);

//! \brief Writes the header hash in table::kCanonicalHashes
void write_canonical_header(RWTxn& txn, const BlockHeader& header);

//! \brief Reads the header hash in table::kCanonicalHashes
std::optional<evmc::bytes32> read_canonical_header_hash(ROTxn& txn, BlockNum block_num);

//! \brief Writes the header hash in table::kCanonicalHashes
void write_canonical_header_hash(RWTxn& txn, const uint8_t (&hash)[kHashLength], BlockNum block_num);

//! \brief Read a block body (in an out parameter) returning true on success and false on missing block
[[nodiscard]] bool read_body(ROTxn& txn, const Bytes& key, bool read_senders, BlockBody& out);
[[nodiscard]] bool read_body(
    ROTxn& txn,
    BlockNum block_num,
    const uint8_t (&hash)[kHashLength],
    bool read_senders,
    BlockBody& out);
[[nodiscard]] bool read_body(ROTxn& txn, const evmc::bytes32& hash, BlockNum block_num, BlockBody& body);
[[nodiscard]] bool read_body(ROTxn& txn, const evmc::bytes32& hash, BlockBody& body);
[[nodiscard]] bool read_canonical_body(ROTxn& txn, BlockNum block_num, bool read_senders, BlockBody& body);

std::optional<BlockBodyForStorage> read_body_for_storage(ROTxn& txn, const Bytes& key);
std::optional<BlockBodyForStorage> read_canonical_body_for_storage(ROTxn& txn, BlockNum block_num);

//! \brief Read the canonical block at specified block_num
[[nodiscard]] bool read_canonical_block(ROTxn& txn, BlockNum block_num, Block& block);

//! \brief Apply a user defined func to the bodies at specified block_num
size_t read_blocks(
    ROTxn& txn,
    BlockNum block_num,
    std::function<void(Block&)> process_func,
    bool read_senders = false);

//! \brief Check the presence of a block body using block number and hash
bool has_body(ROTxn& txn, BlockNum block_num, const uint8_t (&hash)[kHashLength]);
bool has_body(ROTxn& txn, BlockNum block_num, const evmc::bytes32& hash);

//! \brief Writes block body in table::kBlockBodies
void write_body(RWTxn& txn, const BlockBody& body, const evmc::bytes32& hash, BlockNum block_num);
void write_body(RWTxn& txn, const BlockBody& body, const uint8_t (&hash)[kHashLength], BlockNum block_num);
void write_raw_body(RWTxn& txn, const BlockBody& body, const evmc::bytes32& hash, BlockNum block_num);

//! \brief Deletes a block body from table::kBlockBodies
void delete_body(RWTxn& txn, const evmc::bytes32& hash, BlockNum block_num);

// See Erigon ReadTd
std::optional<intx::uint256> read_total_difficulty(ROTxn& txn, BlockNum, const evmc::bytes32& hash);
std::optional<intx::uint256> read_total_difficulty(ROTxn& txn, BlockNum, const uint8_t (&hash)[kHashLength]);
std::optional<intx::uint256> read_total_difficulty(ROTxn& txn, ByteView key);

// See Erigon WriteTd
void write_total_difficulty(RWTxn& txn, BlockNum block_num, const evmc::bytes32& hash, const intx::uint256& total_difficulty);
void write_total_difficulty(
    RWTxn& txn,
    BlockNum block_num,
    const uint8_t (&hash)[kHashLength],
    const intx::uint256& total_difficulty);
void write_total_difficulty(RWTxn& txn, const Bytes& key, const intx::uint256& total_difficulty);

// Reads canonical block; see Erigon ReadBlockByNumber.
// Returns true on success and false on missing block.
[[nodiscard]] bool read_block_by_number(ROTxn& txn, BlockNum block_num, bool read_senders, Block& block);

// Reads a block; see Erigon ReadBlock.
// Returns true on success and false on missing block.
[[nodiscard]] bool read_block(
    ROTxn& txn,
    std::span<const uint8_t, kHashLength> hash,
    BlockNum block_num,
    bool read_senders,
    Block& block);
[[nodiscard]] bool read_block(ROTxn& txn, const evmc::bytes32& hash, BlockNum block_num, Block& block);

// See Erigon ReadSenders
std::vector<evmc::address> read_senders(ROTxn& txn, const Bytes& key);
std::vector<evmc::address> read_senders(ROTxn& txn, BlockNum block_num, const uint8_t (&hash)[kHashLength]);
//! \brief Fills transactions' senders addresses directly in place
void parse_senders(ROTxn& txn, const Bytes& key, std::vector<Transaction>& out);
void write_senders(RWTxn& txn, const evmc::bytes32& hash, const BlockNum& block_num, const Block& block);
void delete_senders(RWTxn& txn, const evmc::bytes32& hash, const BlockNum& block_num);

void write_tx_lookup(RWTxn& txn, const Block& block);
void write_receipts(RWTxn& txn, const std::vector<silkworm::Receipt>& receipts, const BlockNum& block_num);

// See Erigon ReadTransactions
void read_transactions(ROTxn& txn, uint64_t base_id, uint64_t count, std::vector<Transaction>& out);
void read_transactions(datastore::kvdb::ROCursor& txn_table, uint64_t base_id, uint64_t count, std::vector<Transaction>& out);

bool read_rlp_transactions(ROTxn& txn, BlockNum block_num, const evmc::bytes32& hash, std::vector<Bytes>& rlp_txs);

//! \brief Persist transactions into db's bucket table::kBlockTransactions.
//! The key starts from base_id and is incremented by 1 for each transaction.
//! \remarks Before calling this ensure you got a proper base_id by incrementing sequence for table::kBlockTransactions.
void write_transactions(RWTxn& txn, const std::vector<Transaction>& transactions, uint64_t base_id);

//! \brief Delete transactions from table::kBlockTransactions.
void delete_transactions(RWTxn& txn, uint64_t base_id, uint64_t count);

std::optional<ByteView> read_code(ROTxn& txn, const evmc::bytes32& code_hash);

// Reads current or historical (if block_num is specified) account.
std::optional<Account> read_account(
    ROTxn& txn,
    const evmc::address& address,
    std::optional<BlockNum> block_num = std::nullopt);

// Reads current or historical (if block_num is specified) storage.
evmc::bytes32 read_storage(
    ROTxn& txn,
    const evmc::address& address,
    uint64_t incarnation,
    const evmc::bytes32& location,
    std::optional<BlockNum> block_num = std::nullopt);

// Reads current or historical (if block_num is specified) previous incarnation.
std::optional<uint64_t> read_previous_incarnation(
    ROTxn& txn,
    const evmc::address& address,
    std::optional<BlockNum> block_num = std::nullopt);

AccountChanges read_account_changes(ROTxn& txn, BlockNum block_num);

StorageChanges read_storage_changes(ROTxn& txn, BlockNum block_num);

//! \brief Retrieves the chain_id for which database is populated
//! \see Erigon chainConfig / chainConfigWithGenesis
std::optional<ChainConfig> read_chain_config(ROTxn& txn);

//! \brief Writes / Updates chain config provided genesis has been initialized
void update_chain_config(RWTxn& txn, const ChainConfig& config);

//! \brief Updates the tip header hash in table::kHeadHeader
void write_head_header_hash(RWTxn& txn, const uint8_t (&hash)[kHashLength]);
void write_head_header_hash(RWTxn& txn, const evmc::bytes32& hash);

//! \brief Reads the tip header hash from table::kHeadHeader
std::optional<evmc::bytes32> read_head_header_hash(ROTxn& txn);

//! \brief Delete a canonical hash associated to a block number
void delete_canonical_hash(RWTxn& txn, BlockNum block_num);

//! \brief Write canonical hash
void write_canonical_hash(RWTxn& txn, BlockNum block_num, const evmc::bytes32& hash);

//! \brief Gets/Increments the sequence value for a given map (bucket)
//! \param [in] map_name : the name of the map to get a sequence for
//! \param [in] increment : the value of increments to add to the sequence.
//! \returns The current value of the sequence AND internally increments the value for next call
//! \throws std::std::length_error on badly recorded value
//! \remarks Initial sequence for any key (also unset) is 0. Changes to sequences are invisible until the transaction is
//! committed
uint64_t increment_map_sequence(RWTxn& txn, const char* map_name, uint64_t increment = 1u);

//! \brief Returns the current sequence for a map_name
//! \remarks If the key is not present in Sequence bucket the return value is 0
//! \throws std::std::length_error on badly recorded value
uint64_t read_map_sequence(ROTxn& txn, const char* map_name);

//! \brief Reset the sequence value for a given map (bucket)
//! \param [in] map_name : the name of the map to reset the sequence for
//! \param [in] new_sequence : the value to set the sequence to
//! \returns The old value of the sequence
//! \throws std::std::length_error on badly recorded value
//! \remarks Initial sequence for any key (also unset) is 0. Changes to sequences are invisible until the transaction is
//! committed
uint64_t reset_map_sequence(RWTxn& txn, const char* map_name, uint64_t new_sequence);

//! \brief Read the last head block as stated by the last FCU
std::optional<evmc::bytes32> read_last_head_block(ROTxn& txn);

//! \brief Read the last safe block as stated by the last FCU
std::optional<evmc::bytes32> read_last_safe_block(ROTxn& txn);

//! \brief Read the last finalized block as stated by the last FCU
std::optional<evmc::bytes32> read_last_finalized_block(ROTxn& txn);

//! \brief Write the last head block as stated by the last FCU
void write_last_head_block(RWTxn& txn, const evmc::bytes32& hash);

//! \brief Write the last safe block as stated by the last FCU
void write_last_safe_block(RWTxn& txn, const evmc::bytes32& hash);

//! \brief Write the last finalized block as stated by the last FCU
void write_last_finalized_block(RWTxn& txn, const evmc::bytes32& hash);

class DataModel {
  public:
    DataModel(
        ROTxn& txn,
        const snapshots::SnapshotRepositoryROAccess& repository)
        : txn_{txn},
          repository_{repository} {}

    //! Retrieve the chain configuration for which database is populated
    std::optional<ChainConfig> read_chain_config() const;

    //! Retrieve the chain unique identifier for which database is populated
    std::optional<ChainId> read_chain_id() const;

    //! Get the max block number
    BlockNum max_block_num() const;

    //! Get the max block number frozen into snapshots
    BlockNum max_frozen_block_num() const;

    //! Read block header with the specified key (block_num, hash)
    std::optional<BlockHeader> read_header(BlockNum block_num, HashAsArray hash) const;

    //! Read block header with the specified key (block_num, hash)
    std::optional<BlockHeader> read_header(BlockNum block_num, const Hash& hash) const;

    //! Read block header with the specified hash
    std::optional<BlockHeader> read_header(const Hash& hash) const;

    //! Read block header with the specified block number
    std::optional<BlockHeader> read_header(BlockNum block_num) const;

    //! Reads the tip header hash from table::kHeadHeader and a corresponding header
    std::pair<std::optional<BlockHeader>, std::optional<Hash>> read_head_header_and_hash() const;

    //! Read block number from hash
    std::optional<BlockNum> read_block_num(const Hash& hash) const;

    //! Read all sibling block headers at specified block_num
    std::vector<BlockHeader> read_sibling_headers(BlockNum block_num) const;

    //! Read block body in output parameter returning true on success and false on missing block
    [[nodiscard]] bool read_body(BlockNum block_num, HashAsArray hash, bool read_senders, BlockBody& body) const;
    [[nodiscard]] bool read_body(const Hash& hash, BlockNum block_num, BlockBody& body) const;
    [[nodiscard]] bool read_body(const Hash& hash, BlockBody& body) const;

    std::optional<BlockBodyForStorage> read_canonical_body_for_storage(BlockNum block_num) const;
    std::optional<Bytes> read_raw_canonical_body_for_storage(BlockNum block_num) const;

    //! Read block body for storage from the snapshot repository
    std::optional<BlockBodyForStorage> read_body_for_storage_from_snapshot(BlockNum block_num) const;
    std::optional<Bytes> read_raw_body_for_storage_from_snapshot(BlockNum block_num) const;

    //! Read the canonical block header at specified block_num
    std::optional<Hash> read_canonical_header_hash(BlockNum block_num) const;

    //! Read the canonical block header at specified block_num
    std::optional<BlockHeader> read_canonical_header(BlockNum block_num) const;

    //! Read the canonical block body at specified block_num
    [[nodiscard]] bool read_canonical_body(BlockNum block_num, BlockBody& body) const;

    //! Read the transaction at index txn_idx within the specified block
    [[nodiscard]] std::optional<Transaction> read_transaction_by_txn_idx(BlockNum block_num, uint64_t txn_idx) const;

    //! Read the canonical block at specified block_num
    [[nodiscard]] bool read_canonical_block(BlockNum block_num, Block& block) const;

    //! Check the presence of a block body using block number and hash
    bool has_body(BlockNum block_num, HashAsArray hash) const;
    bool has_body(BlockNum block_num, const Hash& hash) const;

    //! Read block returning true on success and false on missing block
    [[nodiscard]] bool read_block(HashAsSpan hash, BlockNum block_num, bool read_senders, Block& block) const;
    [[nodiscard]] bool read_block(const evmc::bytes32& hash, BlockNum block_num, Block& block) const;
    [[nodiscard]] bool read_block(BlockNum block_num, bool read_senders, Block& block) const;

    //! Read the RLP encoded block transactions at specified block_num
    [[nodiscard]] bool read_rlp_transactions(BlockNum block_num, const evmc::bytes32& hash, std::vector<Bytes>& rlp_txs) const;

    std::optional<std::pair<BlockNum, TxnId>> read_tx_lookup(const evmc::bytes32& tx_hash) const;

    //! Read total difficulty at specified block_num
    std::optional<intx::uint256> read_total_difficulty(BlockNum block_num, const evmc::bytes32& hash) const;
    std::optional<intx::uint256> read_total_difficulty(BlockNum, HashAsArray hash) const;
    std::optional<intx::uint256> read_total_difficulty(ByteView key) const;

    //! Read all block headers up to limit in reverse order from last, processing each one via a user defined callback
    void for_last_n_headers(size_t n, absl::FunctionRef<void(BlockHeader)> callback) const;

  private:
    bool read_block_from_snapshot(BlockNum block_num, Block& block) const;
    std::optional<BlockHeader> read_header_from_snapshot(BlockNum block_num) const;
    std::optional<BlockHeader> read_header_from_snapshot(const Hash& hash) const;
    bool read_body_from_snapshot(BlockNum block_num, BlockBody& body) const;
    bool is_body_in_snapshot(BlockNum block_num) const;
    bool read_rlp_transactions_from_snapshot(BlockNum block_num, std::vector<Bytes>& rlp_txs) const;
    bool read_transactions_from_snapshot(BlockNum block_num, uint64_t base_txn_id, uint64_t txn_count, std::vector<Transaction>& txs) const;
    std::optional<std::pair<BlockNum, TxnId>> read_tx_lookup_from_db(const evmc::bytes32& tx_hash) const;
    std::optional<std::pair<BlockNum, TxnId>> read_tx_lookup_from_snapshot(const evmc::bytes32& tx_hash) const;

    ROTxn& txn_;
    const snapshots::SnapshotRepositoryROAccess& repository_;
};

class DataModelFactory {
  public:
    explicit DataModelFactory(DataStoreRef data_store)
        : func_{[data_store = std::move(data_store)](db::ROTxn& tx) { return db::DataModel{tx, data_store.blocks_repository}; }} {}

    DataModel operator()(ROTxn& tx) const {
        return func_(tx);
    }

    //! Null factory only for mocks
    static DataModelFactory null() {
        return DataModelFactory{};
    }

  private:
    //! Null factory only for mocks
    DataModelFactory()
        : func_{
              [](ROTxn&) -> db::DataModel {
                  SILKWORM_ASSERT(false);
                  std::abort();
              },
          } {}

    std::function<DataModel(ROTxn& tx)> func_;
};

}  // namespace silkworm::db
