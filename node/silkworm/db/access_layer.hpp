/*
   Copyright 2022 The Silkworm Authors

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

// Database Access Layer
// See Erigon core/rawdb/accessors_chain.go

#include <optional>
#include <span>
#include <vector>

#include <silkworm/chain/config.hpp>
#include <silkworm/common/rlp_err.hpp>
#include <silkworm/db/mdbx.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/types/account.hpp>
#include <silkworm/types/block.hpp>

namespace silkworm::db {

//! \brief Pulls database schema version
std::optional<VersionBase> read_schema_version(mdbx::txn& txn);

//! \brief Writes database schema version (throws on downgrade)
void write_schema_version(mdbx::txn& txn, const VersionBase& schema_version);

//! \brief Updates database info with build info at provided height
//! \details Is useful to track whether increasing heights have been affected by
//! upgrades or downgrades of Silkworm's build
void write_build_info_height(mdbx::txn& txn, Bytes key, BlockNum height);

//! \brief Reads a header with the specified key (block number, hash)
std::optional<BlockHeader> read_header(mdbx::txn& txn, BlockNum block_number, const uint8_t (&hash)[kHashLength]);
std::optional<BlockHeader> read_header(mdbx::txn& txn, BlockNum block_number, const evmc::bytes32&);
std::optional<BlockHeader> read_header(mdbx::txn& txn, ByteView key);
Bytes read_header_raw(mdbx::txn& txn, ByteView key);

//! \brief Reads a header with the specified hash
std::optional<BlockHeader> read_header(mdbx::txn& txn, const evmc::bytes32& hash);

//! \brief Reads a header without rlp-decoding it
std::optional<ByteView> read_rlp_encoded_header(mdbx::txn& txn, BlockNum bn, const evmc::bytes32& hash);

//! \brief Reads the canonical header from a block number
std::optional<BlockHeader> read_canonical_header(mdbx::txn& txn, BlockNum b);

//! \brief Writes given header to table::kHeaders
void write_header(mdbx::txn& txn, const BlockHeader& header, bool with_header_numbers = false);

//! \brief Read block number from hash
std::optional<BlockNum> read_block_number(mdbx::txn& txn, const evmc::bytes32& hash);

//! \brief Writes header hash in table::kHeaderNumbers
void write_header_number(mdbx::txn& txn, const uint8_t (&hash)[kHashLength], BlockNum number);

//! \brief Writes the header hash in table::kCanonicalHashes
void write_canonical_header(mdbx::txn& txn, const BlockHeader& header);

//! \brief Reads the header hash in table::kCanonicalHashes
std::optional<evmc::bytes32> read_canonical_header_hash(mdbx::txn& txn, BlockNum number);

//! \brief Writes the header hash in table::kCanonicalHashes
void write_canonical_header_hash(mdbx::txn& txn, const uint8_t (&hash)[kHashLength], BlockNum number);

//! \brief Read a block body (in an out parameter) returning true on success and false on missing block
[[nodiscard]] bool read_body(mdbx::txn& txn, const Bytes& key, bool read_senders, BlockBody& out);
[[nodiscard]] bool read_body(mdbx::txn& txn, BlockNum block_number, const uint8_t (&hash)[kHashLength],
                             bool read_senders, BlockBody& out);
[[nodiscard]] bool read_body(mdbx::txn& txn, const evmc::bytes32& hash, BlockNum bn, BlockBody& body);
[[nodiscard]] bool read_body(mdbx::txn& txn, const evmc::bytes32& hash, BlockBody& body);

//! \brief Check the presence of a block body using block number and hash
[[nodiscard]] bool has_body(mdbx::txn& txn, BlockNum block_number, const uint8_t (&hash)[kHashLength]);
[[nodiscard]] bool has_body(mdbx::txn& txn, BlockNum block_number, const evmc::bytes32& hash);

//! \brief Writes block body in table::kBlockBodies
void write_body(mdbx::txn& txn, const BlockBody& body, const evmc::bytes32& hash, BlockNum bn);
void write_body(mdbx::txn& txn, const BlockBody& body, const uint8_t (&hash)[kHashLength], BlockNum number);

// See Erigon ReadTd
std::optional<intx::uint256> read_total_difficulty(mdbx::txn& txn, BlockNum, const evmc::bytes32& hash);
std::optional<intx::uint256> read_total_difficulty(mdbx::txn& txn, BlockNum, const uint8_t (&hash)[kHashLength]);
std::optional<intx::uint256> read_total_difficulty(mdbx::txn& txn, ByteView key);

// See Erigon WriteTd
void write_total_difficulty(mdbx::txn& txn, BlockNum, const evmc::bytes32& hash, const intx::uint256& total_difficulty);
void write_total_difficulty(mdbx::txn& txn, BlockNum, const uint8_t (&hash)[kHashLength], const intx::uint256& td);
void write_total_difficulty(mdbx::txn& txn, const Bytes& key, const intx::uint256& total_difficulty);

// Reads canonical block; see Erigon ReadBlockByNumber.
// Returns true on success and false on missing block.
[[nodiscard]] bool read_block_by_number(mdbx::txn& txn, BlockNum number, bool read_senders, Block& out);

// Reads a block; see Erigon ReadBlock.
// Returns true on success and false on missing block.
[[nodiscard]] bool read_block(mdbx::txn& txn, std::span<const uint8_t, kHashLength> hash, BlockNum number,
                              bool read_senders, Block& out);

// See Erigon ReadSenders
std::vector<evmc::address> read_senders(mdbx::txn& txn, const Bytes& key);
std::vector<evmc::address> read_senders(mdbx::txn& txn, BlockNum block_number, const uint8_t (&hash)[kHashLength]);
//! \brief Fills transactions' senders addresses directly in place
void parse_senders(mdbx::txn& txn, const Bytes& key, std::vector<Transaction>& out);

// See Erigon ReadTransactions
void read_transactions(mdbx::txn& txn, uint64_t base_id, uint64_t count, std::vector<Transaction>& out);
void read_transactions(mdbx::cursor& txn_table, uint64_t base_id, uint64_t count, std::vector<Transaction>& out);

//! \brief Persist transactions into db's bucket table::kBlockTransactions.
//! The key starts from base_id and is incremented by 1 for each transaction.
//! \remarks Before calling this ensure you got a proper base_id by incrementing sequence for table::kBlockTransactions.
void write_transactions(mdbx::txn& txn, const std::vector<Transaction>& transactions, uint64_t base_id);

std::optional<ByteView> read_code(mdbx::txn& txn, const evmc::bytes32& code_hash);

// Reads current or historical (if block_number is specified) account.
std::optional<Account> read_account(mdbx::txn& txn, const evmc::address& address,
                                    std::optional<BlockNum> block_number = std::nullopt);

// Reads current or historical (if block_number is specified) storage.
evmc::bytes32 read_storage(mdbx::txn& txn, const evmc::address& address, uint64_t incarnation,
                           const evmc::bytes32& location, std::optional<BlockNum> block_number = std::nullopt);

// Reads current or historical (if block_number is specified) previous incarnation.
std::optional<uint64_t> read_previous_incarnation(mdbx::txn& txn, const evmc::address& address,
                                                  std::optional<BlockNum> block_number = std::nullopt);

AccountChanges read_account_changes(mdbx::txn& txn, BlockNum block_number);

StorageChanges read_storage_changes(mdbx::txn& txn, BlockNum block_number);

//! \brief Retrieves the chain_id for which database is populated
//! \see Erigon chainConfig / chainConfigWithGenesis
std::optional<ChainConfig> read_chain_config(mdbx::txn& txn);

//! \brief Writes / Updates chain config provided genesis has been initialized
void update_chain_config(mdbx::txn& txn, const ChainConfig& config);

//! \brief Updates highest header hash in table::kHeadHeader
void write_head_header_hash(mdbx::txn& txn, const uint8_t (&hash)[kHashLength]);
void write_head_header_hash(mdbx::txn& txn, const evmc::bytes32& hash);

//! \brief Reads highest header hash from table::kHeadHeader
std::optional<evmc::bytes32> read_head_header_hash(mdbx::txn& txn);

//! \brief Reads canonical hash from block number
std::optional<evmc::bytes32> read_canonical_hash(mdbx::txn& txn, BlockNum b);

//! \brief Delete a canonical hash associated to a block number
void delete_canonical_hash(mdbx::txn& txn, BlockNum b);

//! \brief Write canonical hash
void write_canonical_hash(mdbx::txn& txn, BlockNum b, const evmc::bytes32& hash);

//! \brief Gets/Increments the sequence value for a given map (bucket)
//! \param [in] map_name : the name of the map to get a sequence for
//! \param [in] increment : the value of increments to add to the sequence.
//! \returns The current value of the sequence AND internally increments the value for next call
//! \throws std::std::length_error on badly recorded value
//! \remarks Initial sequence for any key (also unset) is 0. Changes to sequences are invisible until the transaction is
//! committed
uint64_t increment_map_sequence(mdbx::txn& txn, const char* map_name, uint64_t increment = 1u);

//! \brief Returns the current sequence for a map_name
//! \remarks If the key is not present in Sequence bucket the return value is 0
//! \throws std::std::length_error on badly recorded value
uint64_t read_map_sequence(mdbx::txn& txn, const char* map_name);

}  // namespace silkworm::db
