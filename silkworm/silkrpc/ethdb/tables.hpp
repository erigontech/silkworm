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

#pragma once

namespace silkrpc::db::table {

constexpr const char* kAccountHistory{"AccountHistory"};
constexpr const char* kBlockBodies{"BlockBody"};
constexpr const char* kLastForkchoice{"LastForkchoice"};

constexpr const char* kCanonicalHashes{"CanonicalHeader"};
constexpr const char* kHeaders{"Header"};
constexpr const char* kDifficulty{"HeadersTotalDifficulty"};

constexpr const char* kBlockReceipts{"Receipt"};
constexpr const char* kBloomBitsIndex{"BloomBitsIndex"};
constexpr const char* kBloomBits{"BloomBits"};
constexpr const char* kBodiesSnapshotInfo{"BodiesSnapshotInfo"};
constexpr const char* kCallFromIndex{"CallFromIndex"};
constexpr const char* kCallToIndex{"CallToIndex"};
constexpr const char* kClique{"Clique"};
constexpr const char* kCode{"Code"};
constexpr const char* kConfig{"Config"};
constexpr const char* kContractCode{"HashedCodeHash"};
constexpr const char* kDatabaseInfo{"DbInfo"};
constexpr const char* kEthTx{"BlockTransaction"};
constexpr const char* kNonCanonicalTx{"NonCanonicalTransaction"};
constexpr const char* kHashedAccounts{"HashedAccount"};
constexpr const char* kHashedStorage{"HashedStorage"};
constexpr const char* kHeadBlock{"LastBlock"};
constexpr const char* kHeadHeader{"LastHeader"};
constexpr const char* kHeaderNumbers{"HeaderNumber"};
constexpr const char* kHeadersSnapshotInfo{"HeadersSnapshotInfo"};
constexpr const char* kIncarnationMap{"IncarnationMap"};
constexpr const char* kLogAddressIndex{"LogAddressIndex"};
constexpr const char* kLogTopicIndex{"LogTopicIndex"};
constexpr const char* kLogs{"TransactionLog"};
constexpr const char* kMigrations{"Migration"};
constexpr const char* kPlainAccountChangeSet{"AccountChangeSet"};
constexpr const char* kPlainContractCode{"PlainCodeHash"};
constexpr const char* kPlainState{"PlainState"};
constexpr const char* kPlainStorageChangeSet{"StorageChangeSet"};
constexpr const char* kSenders{"TxSender"};
constexpr const char* kSequence{"Sequence"};
constexpr const char* kSnapshotInfo{"SnapshotInfo"};
constexpr const char* kStateSnapshotInfo{"StateSnapshotInfo"};
constexpr const char* kStorageHistory{"StorageHistory"};
constexpr const char* kSyncStageProgress{"SyncStage"};
constexpr const char* kSyncStageUnwind{"SyncStageUnwind"};
constexpr const char* kTrieOfAccounts{"TrieAccount"};
constexpr const char* kTrieOfStorage{"TrieStorage"};
constexpr const char* kTxLookup{"BlockTransactionLookup"};
constexpr const char* kIssuance{"Issuance"};
constexpr const char* kCumulativeGasIndex{"CumulativeGasIndex"};


}  // namespace silkrpc::db::table

