/*
   Copyright 2020-2022 The Silkworm Authors

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

#ifndef SILKWORM_DB_TABLES_HPP_
#define SILKWORM_DB_TABLES_HPP_

#include <optional>

#include <silkworm/db/mdbx.hpp>

/*
Part of the compatibility layer with the Turbo-Geth DB format;
see its common/dbutils/bucket.go.
*/
namespace silkworm::db::table {

inline constexpr VersionBase kRequiredSchemaVersion{3, 0, 0};  // We're compatible with this

inline constexpr const char* kLastHeaderKey{"LastHeader"};

/* Canonical tables */

//! \details At block N stores value of state of account for block N-1.
//! \struct
//! \verbatim
//!   key   : block_num_u64 (BE)
//!   value : address + previous_account (encoded)
//! \endverbatim
//! \example If block N changed account A from value X to Y. Then:\n
//! \verbatim
//!   key   : block_num_u64 (BE)
//!   value : address + X
//! \endverbatim
inline constexpr db::MapConfig kAccountChangeSet{"AccountChangeSet", mdbx::key_mode::usual, mdbx::value_mode::multi};

inline constexpr db::MapConfig kAccountHistory{"AccountHistory"};
inline constexpr db::MapConfig kBlockBodies{"BlockBody"};

//! \struct block_num_u64 (BE) -> header_hash
inline constexpr db::MapConfig kCanonicalHashes{"CanonicalHeader"};

//! \struct block_num_u64 (BE) + hash -> header (RLP)
inline constexpr db::MapConfig kHeaders{"Header"};

//! \struct block_num_u64 (BE) + hash -> total_difficulty (RLP)
inline constexpr db::MapConfig kDifficulty{"HeadersTotalDifficulty"};

inline constexpr db::MapConfig kBlockReceipts{"Receipt"};
inline constexpr db::MapConfig kBloomBitsIndex{"BloomBitsIndex"};
inline constexpr db::MapConfig kBloomBits{"BloomBits"};
inline constexpr db::MapConfig kBodiesSnapshotInfo{"BodiesSnapshotInfo"};
inline constexpr db::MapConfig kCallFromIndex{"CallFromIndex"};
inline constexpr db::MapConfig kCallToIndex{"CallToIndex"};
inline constexpr db::MapConfig kCallTraceSet{"CallTraceSet", mdbx::key_mode::usual, mdbx::value_mode::multi};
inline constexpr db::MapConfig kCode{"Code"};
inline constexpr db::MapConfig kConfig{"Config"};
inline constexpr db::MapConfig kContractCode{"HashedCodeHash"};
inline constexpr db::MapConfig kDatabaseInfo{"DbInfo"};
inline constexpr db::MapConfig kBlockTransactions{"BlockTransaction"};

//! \details Store "current" state for accounts
//! \remarks This table stores the same values for PlainState (Account record type) but with hashed key
//! \struct
//! \verbatim
//!   key   : account address hash (20 bytes)
//!   value : account encoded for storage
//! \endverbatim
inline constexpr db::MapConfig kHashedAccounts{"HashedAccount"};

//! \details Store "current" state for contract storage
//! \remarks This table stores the same values for PlainState (storage record type) but with hashed key
//! \struct
//! \verbatim
//!   key   : contract address hash (32 bytes) + incarnation (u64 BE)
//!   value : storage key hash (32 bytes) + storage value (hash 32 bytes)
//! \endverbatim
inline constexpr db::MapConfig kHashedStorage{"HashedStorage", mdbx::key_mode::usual, mdbx::value_mode::multi};
inline constexpr db::MapConfig kHeadBlock{"LastBlock"};
inline constexpr db::MapConfig kHeadHeader{"LastHeader"};
inline constexpr db::MapConfig kHeaderNumbers{"HeaderNumber"};
inline constexpr db::MapConfig kHeadersSnapshotInfo{"HeadersSnapshotInfo"};

//! \details Stores the last incarnation of last contract SelfDestruct
//! \struct
//! \verbatim
//!   key   : contract address (unhashed 20 bytes)
//!   value : incarnation (u64 BE)
//! \endverbatim
inline constexpr db::MapConfig kIncarnationMap{"IncarnationMap"};
inline constexpr db::MapConfig kLogAddressIndex{"LogAddressIndex"};
inline constexpr db::MapConfig kLogTopicIndex{"LogTopicIndex"};
inline constexpr db::MapConfig kLogs{"TransactionLog"};
inline constexpr db::MapConfig kMigrations{"Migration"};
inline constexpr db::MapConfig kPlainContractCode{"PlainCodeHash"};

//! \details Store "current" state for accounts and storage and is used for block execution
//! \def "Incarnation" how many times given account was SelfDestruct'ed.
//! \struct
//! \verbatim
//! Accounts :
//!   key   : address (20 bytes)
//!   value : account encoded for storage
//! Storage :
//!   key   : address (20 bytes) + incarnation (u64 BE)
//!   value : storage key (32 bytes) + storage value (hash 32 bytes)
//! \endverbatim
inline constexpr db::MapConfig kPlainState{"PlainState", mdbx::key_mode::usual, mdbx::value_mode::multi};

//! \details Store recovered senders' addresses for each transaction in a block
//! \remarks Senders' addresses are not stored in transactions so they must be recovered from the signature
//! of the transaction itself
//! \struct
//! \verbatim
//!   key   : block_num (u64 BE)
//!   value : array of addresses (each 20 bytes)
//!   The addresses in array are listed in the same order of the transactions of the block
//! \endverbatim
inline constexpr db::MapConfig kSenders{"TxSender"};

//! \details Stores sequence values for different keys
//! \remarks Usually keys are table names
//! \struct
//! \verbatim
//!   key   : a string
//!   value : last increment generated (u64 BE)
//! \endverbatim
inline constexpr db::MapConfig kSequence{"Sequence"};

inline constexpr db::MapConfig kSnapshotInfo{"SnapshotInfo"};
inline constexpr db::MapConfig kStateSnapshotInfo{"StateSnapshotInfo"};

//! \details At block N stores value of state of storage for block N-1.
//! \struct
//! \verbatim
//!   key   : block_num_u64 (BE) + address + incarnation_u64 (BE)
//!   value : location (32 bytes) + previous_value (no leading zeros)
//! \endverbatim
//! \example If block N changed storage from value X to Y. Then:
//! \verbatim
//!   key   : block_num_u64 (BE) + address + incarnation_u64 (BE)
//!   value : plain_storage_location (32 bytes) + X
//! \endverbatim
inline constexpr db::MapConfig kStorageChangeSet{"StorageChangeSet", mdbx::key_mode::usual, mdbx::value_mode::multi};

inline constexpr db::MapConfig kStorageHistory{"StorageHistory"};

//! \details Stores reached progress for each stage
//! \struct
//! \verbatim
//!   key   : stage name
//!   value : block_num_u64 (BE)
//! \endverbatim
inline constexpr db::MapConfig kSyncStageProgress{"SyncStage"};

//! \brief Unwind point for stages
//! \struct stage name -> block_num_u64 (BE)
inline constexpr db::MapConfig kSyncStageUnwind{"SyncStageUnwind"};

inline constexpr db::MapConfig kTrieOfAccounts{"TrieAccount"};
inline constexpr db::MapConfig kTrieOfStorage{"TrieStorage"};
inline constexpr db::MapConfig kTxLookup{"BlockTransactionLookup"};

inline constexpr db::MapConfig kChainDataTables[]{
    kAccountChangeSet,
    kAccountHistory,
    kBlockBodies,
    kBlockReceipts,
    kBloomBits,
    kBloomBitsIndex,
    kBodiesSnapshotInfo,
    kCallFromIndex,
    kCallToIndex,
    kCallTraceSet,
    kCanonicalHashes,
    kHeaders,
    kDifficulty,
    kCode,
    kConfig,
    kContractCode,
    kDatabaseInfo,
    kBlockTransactions,
    kHashedAccounts,
    kHashedStorage,
    kHeadBlock,
    kHeadHeader,
    kHeaderNumbers,
    kHeadersSnapshotInfo,
    kIncarnationMap,
    kLogAddressIndex,
    kLogTopicIndex,
    kLogs,
    kMigrations,
    kPlainContractCode,
    kPlainState,
    kSenders,
    kSequence,
    kSnapshotInfo,
    kStateSnapshotInfo,
    kStorageChangeSet,
    kStorageHistory,
    kSyncStageProgress,
    kSyncStageUnwind,
    kTrieOfAccounts,
    kTrieOfStorage,
    kTxLookup,
};

//! \brief Ensures all defined tables are present in db with consistent flags. Should a table not exist it gets created
void check_or_create_chaindata_tables(mdbx::txn& txn);

}  // namespace silkworm::db::table

#endif  // SILKWORM_DB_TABLES_HPP_
