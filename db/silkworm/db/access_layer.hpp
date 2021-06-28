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
#include <silkworm/common/magic_enum.hpp>
#include <silkworm/db/chaindb.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/types/account.hpp>
#include <silkworm/types/block.hpp>

namespace silkworm::rlp {

class DecodingError : public std::exception {
  public:
    explicit DecodingError(DecodingResult err)
        : err_{magic_enum::enum_integer<DecodingResult>(err)},
          message_{"Decoding error : " + std::string(magic_enum::enum_name<DecodingResult>(err))} {};
    explicit DecodingError(DecodingResult err, const std::string& message)
        : err_{magic_enum::enum_integer<DecodingResult>(err)}, message_{message} {};
    virtual ~DecodingError() noexcept {};
    const char* what() const noexcept override { return message_.c_str(); }
    int err() const noexcept { return err_; }

  protected:
    int err_;
    std::string message_;
};

inline void err_handler(DecodingResult err) {
    if (err != DecodingResult::kOk) {
        throw DecodingError(err);
    }
}

}  // namespace silkworm::rlp

namespace silkworm::db {

class MissingSenders : public std::runtime_error {
  public:
    using std::runtime_error::runtime_error;
};

// See Erigon StorageModeReceipts
constexpr const char* kStorageModeReceipts{"smReceipts"};

// See Erigon GetStorageModeFromDB
bool read_storage_mode_receipts(mdbx::txn& txn);

std::optional<BlockHeader> read_header(mdbx::txn& txn, uint64_t block_number,
                                       const uint8_t (&hash)[kHashLength]);

std::optional<BlockBody> read_body(mdbx::txn& txn, uint64_t block_number, const uint8_t (&hash)[kHashLength],
                                   bool read_senders);

// See Erigon ReadTd
std::optional<intx::uint256> read_total_difficulty(mdbx::txn& txn, uint64_t block_number,
                                                   const uint8_t (&hash)[kHashLength]);

// See Erigon ReadBlockByNumber
// might throw MissingSenders
std::optional<BlockWithHash> read_block(mdbx::txn& txn, uint64_t block_number, bool read_senders);

// See Erigon ReadSenders
std::vector<evmc::address> read_senders(mdbx::txn& txn, int64_t block_number,
                                        const uint8_t (&hash)[kHashLength]);

// Overload
std::vector<Transaction> read_transactions(mdbx::cursor& txn_table, uint64_t base_id, uint64_t count);

std::optional<Bytes> read_code(mdbx::txn& txn, const evmc::bytes32& code_hash);

// Reads current or historical (if block_number is specified) account.
std::optional<Account> read_account(mdbx::txn& txn, const evmc::address& address,
                                    std::optional<uint64_t> block_number = std::nullopt);

// Reads current or historical (if block_number is specified) storage.
evmc::bytes32 read_storage(mdbx::txn& txn, const evmc::address& address, uint64_t incarnation,
                           const evmc::bytes32& location, std::optional<uint64_t> block_number = std::nullopt);

// Reads current or historical (if block_number is specified) previous incarnation.
std::optional<uint64_t> read_previous_incarnation(mdbx::txn& txn, const evmc::address& address,
                                                  std::optional<uint64_t> block_number = std::nullopt);

AccountChanges read_account_changes(mdbx::txn& txn, uint64_t block_number);

StorageChanges read_storage_changes(mdbx::txn& txn, uint64_t block_number);

bool migration_happened(mdbx::txn& txn, const char* name);

// Retrieves the chain_id for which database is populated
// See Erigon chainConfig / chainConfigWithGenesis
std::optional<ChainConfig> read_chain_config(mdbx::txn& txn);

}  // namespace silkworm::db

#endif  // !SILKWORM_DB_ACCESS_LAYER_HPP_
