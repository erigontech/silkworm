/*
   Copyright 2020-2021 The Silkworm Authors

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

#ifndef SILKWORM_DB_ACCESS_LAYER_HPP_
#define SILKWORM_DB_ACCESS_LAYER_HPP_

// Database Access Layer
// See Erigon core/rawdb/accessors_chain.go

#include <optional>
#include <vector>

#include <silkworm/chain/config.hpp>
#include <silkworm/common/rlp_err.hpp>
#include <silkworm/db/mdbx.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/types/account.hpp>
#include <silkworm/types/block.hpp>

namespace silkworm::db {

class MissingSenders : public std::runtime_error {
  public:
    using std::runtime_error::runtime_error;
};

// Pulls database schema version
std::optional<VersionBase> read_schema_version(mdbx::txn& txn) noexcept;

// Writes database schema version (throws on downgrade)
void write_schema_version(mdbx::txn& txn, VersionBase& schema_version);

std::optional<BlockHeader> read_header(mdbx::txn& txn, BlockNum block_number, const uint8_t (&hash)[kHashLength]);

//! \brief Writes given header to table::kHeaders
void write_header(mdbx::txn& txn, const BlockHeader& header, bool with_header_numbers = false);

//! \brief Writes header hash in table::kHeaderNumbers
void write_header_number(mdbx::txn& txn, const uint8_t (&hash)[kHashLength], const BlockNum number);

//! \brief Writes the header hash in table::kCanonicalHashes
void write_canonical_header(mdbx::txn& txn, const BlockHeader& header);

//! \brief Writes the header hash in table::kCanonicalHashes
void write_canonical_header_hash(mdbx::txn& txn, const uint8_t (&hash)[kHashLength], BlockNum number);

std::optional<BlockBody> read_body(mdbx::txn& txn, BlockNum block_number, const uint8_t (&hash)[kHashLength],
                                   bool read_senders);

//! \brief Writes block body in table::kBlockBodies
void write_body(mdbx::txn& txn, const BlockBody& body, const uint8_t (&hash)[kHashLength], const BlockNum number);

// See Erigon ReadTd
std::optional<intx::uint256> read_total_difficulty(mdbx::txn& txn, BlockNum block_number,
                                                   const uint8_t (&hash)[kHashLength]);

// See Erigon WriteTd
void write_total_difficulty(mdbx::txn& txn, Bytes& key, const intx::uint256& total_difficulty);
void write_total_difficulty(mdbx::txn& txn, BlockNum block_number, const uint8_t (&hash)[kHashLength],
                            const intx::uint256& total_difficulty);

// See Erigon ReadBlockByNumber
// might throw MissingSenders
std::optional<BlockWithHash> read_block(mdbx::txn& txn, BlockNum block_number, bool read_senders);

// See Erigon ReadSenders
std::vector<evmc::address> read_senders(mdbx::txn& txn, BlockNum block_number, const uint8_t (&hash)[kHashLength]);

// Overload
std::vector<Transaction> read_transactions(mdbx::cursor& txn_table, BlockNum base_id, uint64_t count);

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

//! \brief Updates highest header in table::Config
void write_head_header_hash(mdbx::txn& txn, const uint8_t (&hash)[kHashLength]);

}  // namespace silkworm::db

#endif  // !SILKWORM_DB_ACCESS_LAYER_HPP_
