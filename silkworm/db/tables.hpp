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

#include <optional>

#include <silkworm/db/datastore/kvdb/mdbx.hpp>
#include <silkworm/db/util.hpp>

/// Part of the compatibility layer with the Erigon DB format.

namespace silkworm::db::table {

using datastore::kvdb::MapConfig;

//! Database schema version for compatibility w/ Erigon
//! 5.0 - BlockTransaction table has canonical IDs (txs of non-canonical blocks moved to NonCanonicalTransaction table)
//! 6.0 - BlockTransaction table has system-txs before/after each block (absent if block has no system-tx, but sequence increasing)
//! 6.1 - BlockTransaction table contains canonical/non-canonical/bad-block transactions; add BadBlockNumber table
inline constexpr VersionBase kRequiredSchemaVersion{6, 1, 0};  // Erigon2 latest schema version

/* Canonical tables */

//! \details At block N stores value of state of account for block N-1.
//! \struct
//! \verbatim
//!   key   : block_num_u64 (BE)
//!   value : address + previous_account (encoded)
//! \endverbatim
//! \example If block N changed account A from value X to Y. Then:
//! \verbatim
//!   key   : block_num_u64 (BE)
//!   value : address + X
//! \endverbatim
inline constexpr const char* kAccountChangeSetName{"AccountChangeSet"};
inline constexpr MapConfig kAccountChangeSet{kAccountChangeSetName, mdbx::key_mode::usual, mdbx::value_mode::multi};

//! \details Holds the list of blocks in which a specific account has been changed
//! \struct
//! \verbatim
//!   key   : plain account address (20 bytes) + suffix (BE 64bit unsigned integer)
//!   value : binary bitmap holding list of blocks including a state change for the account
//! \endverbatim
//! \remark Each record's key holds a suffix which is a 64bit unsigned integer specifying the "upper bound" limit
//! of the list of blocks contained in value part. When this integer is equal to UINT64_MAX it means this
//! record holds the last known chunk of blocks which have changed the account. This is due to
//! how RoaringBitmap64 work.
//! \remark This table/bucket indexes the contents of PlainState (Account record type) therefore honoring the
//! same content limits wrt pruning
inline constexpr const char* kAccountHistoryName{"AccountHistory"};
inline constexpr MapConfig kAccountHistory{kAccountHistoryName};

//! \details Holds block body data
//! \struct
//! \verbatim
//!   key   : block number (BE 8 bytes) + block header hash (32 bytes)
//!   value : block body data RLP encoded
//! \endverbatim
inline constexpr const char* kBlockBodiesName{"BlockBody"};
inline constexpr MapConfig kBlockBodies{kBlockBodiesName};

//! \details Stores the binding of *canonical* block number with header hash
//! \struct
//! \verbatim
//!   key   : block_num_u64 (BE)
//!   value : header_hash
//! \endverbatim
inline constexpr const char* kCanonicalHashesName{"CanonicalHeader"};
inline constexpr MapConfig kCanonicalHashes{kCanonicalHashesName};

//! \details Stores the headers downloaded from peers
//! \struct
//! \verbatim
//!   key   : block_num_u64 (BE) + header hash
//!   value : header RLP encoded
//! \endverbatim
inline constexpr const char* kHeadersName{"Header"};
inline constexpr MapConfig kHeaders{kHeadersName};

//! \details Stores the total difficulty accrued at each block number
//! \struct
//! \verbatim
//!   key   : block_num_u64 (BE) + header hash
//!   value : total difficulty (RLP encoded
//! \endverbatim
inline constexpr const char* kDifficultyName{"HeadersTotalDifficulty"};
inline constexpr MapConfig kDifficulty{kDifficultyName};

//! \details Stores the receipts for every canonical block
//! \remarks Non canonical blocks' receipts are not stored
//! \struct
//! \verbatim
//!   key   : block_num_u64 (BE)
//!   value : receipts (CBOR Encoded)
//! \endverbatim
inline constexpr const char* kBlockReceiptsName{"Receipt"};
inline constexpr MapConfig kBlockReceipts{kBlockReceiptsName};

//! \details Stores the mapping of block number to the set (sorted) of all accounts touched by call traces.
//! \struct
//! \verbatim
//!   key   : block_num_u64 (BE)
//!   value : account address + two bits (one for "from" + another for "to")
//! \endverbatim
inline constexpr const char* kCallTraceSetName{"CallTraceSet"};
inline constexpr MapConfig kCallTraceSet{kCallTraceSetName, mdbx::key_mode::usual, mdbx::value_mode::multi};

//! \details Stores the list of blocks in which a specific call sender (i.e. "from") has been traced
//! \struct
//! \verbatim
//!   key   : address (20 bytes) + suffix (BE 64bit unsigned integer)
//!   value : binary bitmap holding list of blocks
//! \endverbatim
//! \remark Each record key holds a suffix which is a 64bit unsigned integer specifying the "upper bound" limit
//! of the list of blocks contained in the value part. When this integer is equal to UINT64_MAX, it means this
//! record holds the last known chunk of blocks which contain the address as sender for some call. This is due
//! to how roaring bitmaps work.
inline constexpr const char* kCallFromIndexName{"CallFromIndex"};
inline constexpr MapConfig kCallFromIndex{kCallFromIndexName};

//! \details Stores the list of blocks in which a specific call receiver (i.e. "to") has been traced
//! \struct
//! \verbatim
//!   key   : address (20 bytes) + suffix (BE 64bit unsigned integer)
//!   value : binary bitmap holding list of blocks
//! \endverbatim
//! \remark Each record key holds a suffix which is a 64bit unsigned integer specifying the "upper bound" limit
//! of the list of blocks contained in the value part. When this integer is equal to UINT64_MAX, it means this
//! record holds the last known chunk of blocks which contain the address as receiver for some call. This is due
//! to how roaring bitmaps work.
inline constexpr const char* kCallToIndexName{"CallToIndex"};
inline constexpr MapConfig kCallToIndex{kCallToIndexName};

//! \details Stores contract's code
//! \struct
//! \verbatim
//!   key   : contract code hash
//!   value : contract code
//! \endverbatim
inline constexpr const char* kCodeName{"Code"};
inline constexpr MapConfig kCode{kCodeName};

inline constexpr const char* kConfigName{"Config"};
inline constexpr MapConfig kConfig{kConfigName};

inline constexpr const char* kDatabaseInfoName{"DbInfo"};
inline constexpr MapConfig kDatabaseInfo{kDatabaseInfoName};

inline constexpr const char* kBlockTransactionsName{"BlockTransaction"};
inline constexpr MapConfig kBlockTransactions{kBlockTransactionsName};

//! \details Store "current" state for accounts with hashed address key
//! \remarks This table stores the same values for PlainState (Account record type) but with hashed key
//! \struct
//! \verbatim
//!   key   : account address hash (32 bytes)
//!   value : account encoded for storage
//! \endverbatim
inline constexpr const char* kHashedAccountsName{"HashedAccount"};
inline constexpr MapConfig kHashedAccounts{kHashedAccountsName};

//! \details Store contract code hash for given contract by key hashed address + incarnation
//! \remarks This table stores the same values for PlainCodeHash but with hashed key address
//! \def "Incarnation" how many times given account was SelfDestruct'ed.
//! \struct
//! \verbatim
//!   key   : contract address hash (32 bytes) + incarnation (u64 BE)
//!   value : code hash (32 bytes)
//! \endverbatim
inline constexpr MapConfig kHashedCodeHash{"HashedCodeHash"};

//! \details Store "current" state for contract storage with hashed address
//! \remarks This table stores the same values for PlainState (storage record type) but with hashed key
//! \struct
//! \verbatim
//!   key   : contract address hash (32 bytes) + incarnation (u64 BE)
//!   value : storage key hash (32 bytes) + storage value (hash 32 bytes)
//! \endverbatim
inline constexpr const char* kHashedStorageName{"HashedStorage"};
inline constexpr MapConfig kHashedStorage{kHashedStorageName, mdbx::key_mode::usual, mdbx::value_mode::multi};

inline constexpr const char* kHeadBlockName{"LastBlock"};
inline constexpr MapConfig kHeadBlock{kHeadBlockName};

//! \details Store last canonical header hash for ease of access and performance
//! \remarks This table stores the last record present also in Headers
//! \struct
//! \verbatim
//!   key   : "LastHeader" as bytes
//!   value : last header hash (32 bytes)
//! \endverbatim
inline constexpr const char* kHeadHeaderName{"LastHeader"};
inline constexpr MapConfig kHeadHeader{kHeadHeaderName};

inline constexpr const char* kHeaderNumbersName{"HeaderNumber"};
inline constexpr MapConfig kHeaderNumbers{kHeaderNumbersName};

//! \details Stores the last incarnation of last contract SelfDestruct
//! \struct
//! \verbatim
//!   key   : contract address (unhashed 20 bytes)
//!   value : incarnation (u64 BE)
//! \endverbatim
inline constexpr const char* kIncarnationMapName{"IncarnationMap"};
inline constexpr MapConfig kIncarnationMap{kIncarnationMapName};

//! \details Holds the list of blocks in which a specific log address has been touched
//! \struct
//! \verbatim
//!   key   : address (20 bytes) + suffix (BE 32bit unsigned integer)
//!   value : binary bitmap holding list of blocks
//! \endverbatim
//! \remark Each record's key holds a suffix which is a 32bit unsigned integer specifying the "upper bound" limit
//! of the list of blocks contained in value part. When this integer is equal to UINT32_MAX it means this
//! record holds the last known chunk of blocks which have changed the account. This is due to
//! how roaring bitmaps work.
inline constexpr const char* kLogAddressIndexName{"LogAddressIndex"};
inline constexpr MapConfig kLogAddressIndex{kLogAddressIndexName};

//! \details Holds the list of blocks in which a specific log topic has been touched
//! \struct
//! \verbatim
//!   key   : hash (32 bytes) + suffix (BE 32bit unsigned integer)
//!   value : binary bitmap holding list of blocks
//! \endverbatim
//! \remark Each record's key holds a suffix which is a 32bit unsigned integer specifying the "upper bound" limit
//! of the list of blocks contained in value part. When this integer is equal to UINT32_MAX it means this
//! record holds the last known chunk of blocks which have changed the account. This is due to
//! how roaring bitmaps work.
inline constexpr const char* kLogTopicIndexName{"LogTopicIndex"};
inline constexpr MapConfig kLogTopicIndex{kLogTopicIndexName};

//! \details Stores the logs for every transaction in canonical blocks
//! \remarks Non canonical blocks' transactions logs are not stored
//! \struct
//! \verbatim
//!   key   : block_num_u64 (BE) + transaction_index_u32 (BE)
//!   value : logs of transaction (CBOR Encoded)
//! \endverbatim
inline constexpr const char* kLogsName{"TransactionLog"};
inline constexpr MapConfig kLogs{kLogsName};

inline constexpr const char* kMigrationsName{"Migration"};
inline constexpr MapConfig kMigrations{kMigrationsName};

//! \details Store contract code hash for given contract address + incarnation
//! \def "Incarnation" how many times given account was SelfDestruct'ed.
//! \struct
//! \verbatim
//!   key   : contract address (20 bytes) + incarnation (u64 BE)
//!   value : code hash (32 bytes)
//! \endverbatim
inline constexpr const char* kPlainCodeHashName{"PlainCodeHash"};
inline constexpr MapConfig kPlainCodeHash{kPlainCodeHashName};

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
inline constexpr const char* kPlainStateName{"PlainState"};
inline constexpr MapConfig kPlainState{kPlainStateName, mdbx::key_mode::usual, mdbx::value_mode::multi};

//! \details Store recovered senders' addresses for each transaction in a block
//! \remarks Senders' addresses are not stored in transactions so they must be recovered from the signature
//! of the transaction itself
//! \struct
//! \verbatim
//!   key   : block_num_u64 (BE) + block_hash
//!   value : array of addresses (each 20 bytes)
//!   The addresses in array are listed in the same order of the transactions of the block
//! \endverbatim
inline constexpr const char* kSendersName{"TxSender"};
inline constexpr MapConfig kSenders{kSendersName};

//! \details Stores sequence values for different keys
//! \remarks Usually keys are table names
//! \struct
//! \verbatim
//!   key   : a string
//!   value : last increment generated (u64 BE)
//! \endverbatim
inline constexpr const char* kSequenceName{"Sequence"};
inline constexpr MapConfig kSequence{kSequenceName};

//! \details At block N stores value of state of storage for block N-1.
//! \struct
//! \verbatim
//!   key   : block_num_u64 (BE) + address + incarnation_u64 (BE)
//!   value : plain_storage_location (32 bytes) + previous_value (no leading zeros)
//! \endverbatim
//! \example If block N changed storage from value X to Y. Then:
//! \verbatim
//!   key   : block_num_u64 (BE) + address + incarnation_u64 (BE)
//!   value : plain_storage_location (32 bytes) + X
//! \endverbatim
inline constexpr const char* kStorageChangeSetName{"StorageChangeSet"};
inline constexpr MapConfig kStorageChangeSet{kStorageChangeSetName, mdbx::key_mode::usual, mdbx::value_mode::multi};

//! \details Holds the list of blocks in which a specific storage location has been changed
//! \struct
//! \verbatim
//!   key   : plain contract account address (20 bytes) + location (32 bytes hash) + suffix (BE 64bit unsigned integer)
//!   value : binary bitmap holding list of blocks including a state change for the account
//! \endverbatim
//! \remark Each record's key holds a suffix which is a 64bit unsigned integer specifying the "upper bound" limit
//! of the list of blocks contained in value part. When this integer is equal to UINT64_MAX it means this
//! record holds the last known chunk of blocks which have changed the account. This is due to
//! how RoaringBitmap64 work.
//! \remark This table/bucket indexes the contents of PlainState (Account record type) therefore honoring the
//! same content limits wrt pruning
inline constexpr const char* kStorageHistoryName{"StorageHistory"};
inline constexpr MapConfig kStorageHistory{kStorageHistoryName};

//! \details Stores reached progress for each stage
//! \struct
//! \verbatim
//!   key   : stage name
//!   value : block_num_u64 (BE)
//! \endverbatim
inline constexpr const char* kSyncStageProgressName{"SyncStage"};
inline constexpr MapConfig kSyncStageProgress{kSyncStageProgressName};

//! \brief Hold the nodes composing the StateRoot
//! \verbatim
//!   key   : node key
//!   value : serialized node value (see core::trie::Node)
//! \endverbatim
//! \remark The only record with empty key is the root node
inline constexpr const char* kTrieOfAccountsName{"TrieAccount"};
inline constexpr MapConfig kTrieOfAccounts{kTrieOfAccountsName};

//! \brief Hold the nodes composing the StorageRoot for each contract
//! \verbatim
//!   key   : db::kHashedStoragePrefix(40 bytes == hashed address + incarnation) + node key
//!   value : serialized node value (see core::trie::Node)
//! \endverbatim
//! \remark Each trie has its own invariant db::kHashedStoragePrefix
//! \remark Records with key len == 40 (ie node key == 0) are root nodes
inline constexpr const char* kTrieOfStorageName{"TrieStorage"};
inline constexpr MapConfig kTrieOfStorage{kTrieOfStorageName};

inline constexpr const char* kTxLookupName{"BlockTransactionLookup"};
inline constexpr MapConfig kTxLookup{kTxLookupName};

inline constexpr const char* kLastForkchoiceName{"LastForkchoice"};
inline constexpr MapConfig kLastForkchoice{kLastForkchoiceName};

//! \brief Hold the maximum canonical transaction number for each block
//! \verbatim
//!  key: block_num_u64 (BE)
//!  value: max_tx_num_in_block_u64 (BE)
//! \endverbatim
//! \details In Erigon3: table MaxTxNum storing TxNum (not TxnID). History/Indices are using TxNum (not TxnID).
inline constexpr const char* kMaxTxNumName{"MaxTxNum"};
inline constexpr MapConfig kMaxTxNum{kMaxTxNumName};

inline constexpr MapConfig kChainDataTables[]{
    kAccountChangeSet,
    kAccountHistory,
    kBlockBodies,
    kBlockReceipts,
    kCallFromIndex,
    kCallToIndex,
    kCallTraceSet,
    kCanonicalHashes,
    kHeaders,
    kDifficulty,
    kCode,
    kConfig,
    kHashedCodeHash,
    kDatabaseInfo,
    kBlockTransactions,
    kHashedAccounts,
    kHashedStorage,
    kHeadBlock,
    kHeadHeader,
    kHeaderNumbers,
    kIncarnationMap,
    kLastForkchoice,
    kLogAddressIndex,
    kLogTopicIndex,
    kLogs,
    kMaxTxNum,
    kMigrations,
    kPlainCodeHash,
    kPlainState,
    kSenders,
    kSequence,
    kStorageChangeSet,
    kStorageHistory,
    kSyncStageProgress,
    kTrieOfAccounts,
    kTrieOfStorage,
    kTxLookup,
};

//! \brief Ensures all defined tables are present in db with consistent flags. Should a table not exist it gets created
void check_or_create_chaindata_tables(datastore::kvdb::RWTxn& txn);

//! \brief Get the table config associated to the table name (if any)
std::optional<MapConfig> get_map_config(const std::string& map_name);

/// Part of the compatibility layer with Erigon snapshot format

//! \details Domain storing the account common information
inline constexpr const char* kAccountDomain{"accounts"};
inline constexpr const char* kStorageDomain{"storage"};
inline constexpr const char* kCodeDomain{"code"};
inline constexpr const char* kCommitmentDomain{"commitment"};
inline constexpr const char* kReceiptDomain{"receipt"};

//! \details Inverted Index storing the account common information
inline constexpr const char* kAccountsHistoryIdx{"AccountsHistoryIdx"};
inline constexpr const char* kStorageHistoryIdx{"StorageHistoryIdx"};
inline constexpr const char* kCodeHistoryIdx{"CodeHistoryIdx"};
inline constexpr const char* kCommitmentHistoryIdx{"CommitmentHistoryIdx"};
inline constexpr const char* kReceiptHistoryIdx{"ReceiptHistoryIdx"};
inline constexpr const char* kTracesFromIdx{"TracesFromIdx"};
inline constexpr const char* kTracesToIdx{"TracesToIdx"};
inline constexpr const char* kLogAddrIdx{"LogAddrIdx"};
inline constexpr const char* kLogTopicIdx{"LogTopicIdx"};

}  // namespace silkworm::db::table
