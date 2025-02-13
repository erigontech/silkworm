/*
   Copyright 2024 The Silkworm Authors

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

#include "../datastore/common/entity_name.hpp"
#include "../datastore/kvdb/database.hpp"
#include "../datastore/kvdb/domain.hpp"
#include "../datastore/kvdb/inverted_index.hpp"
#include "../datastore/kvdb/schema.hpp"
#include "../datastore/snapshots/domain.hpp"
#include "../datastore/snapshots/index_builders_factory.hpp"
#include "../datastore/snapshots/inverted_index.hpp"
#include "../datastore/snapshots/schema.hpp"
#include "../datastore/snapshots/snapshot_repository.hpp"

namespace silkworm::db::state {

inline constexpr datastore::EntityName kStateRepositoryNameLatest{"StateLatest"};
inline constexpr datastore::EntityName kStateRepositoryNameHistorical{"StateHistorical"};

snapshots::Schema::RepositoryDef make_state_repository_schema_latest();
snapshots::Schema::RepositoryDef make_state_repository_schema_historical();
datastore::kvdb::Schema::DatabaseDef make_state_database_schema();

snapshots::SnapshotRepository make_state_repository_latest(
    std::filesystem::path dir_path,
    bool open = true,
    std::optional<uint32_t> index_salt = std::nullopt);

snapshots::SnapshotRepository make_state_repository_historical(
    std::filesystem::path dir_path,
    bool open = true,
    std::optional<uint32_t> index_salt = std::nullopt);

inline constexpr datastore::EntityName kDomainNameAccounts{"Account"};
inline constexpr datastore::EntityName kDomainNameStorage{"Storage"};
inline constexpr datastore::EntityName kDomainNameCode{"Code"};
inline constexpr datastore::EntityName kDomainNameCommitment{"Commitment"};
inline constexpr datastore::EntityName kDomainNameReceipts{"Receipt"};

inline constexpr datastore::EntityName kInvIdxNameLogAddress{"LogAddress"};
inline constexpr datastore::EntityName kInvIdxNameLogTopics{"LogTopics"};
inline constexpr datastore::EntityName kInvIdxNameTracesFrom{"TracesFrom"};
inline constexpr datastore::EntityName kInvIdxNameTracesTo{"TracesTo"};

inline constexpr std::string_view kDomainAccountsTag{"accounts"};
inline constexpr std::string_view kInvIdxLogAddressTag{"logaddrs"};

struct BundleDataRef {
    const snapshots::SnapshotBundle& bundle;

    snapshots::Domain accounts_domain() const { return {bundle.domain(kDomainNameAccounts)}; }
    snapshots::Domain storage_domain() const { return {bundle.domain(kDomainNameStorage)}; }
    snapshots::Domain code_domain() const { return {bundle.domain(kDomainNameCode)}; }
    snapshots::Domain commitment_domain() const { return {bundle.domain(kDomainNameCommitment)}; }
    snapshots::Domain receipts_domain() const { return {bundle.domain(kDomainNameReceipts)}; }

    snapshots::InvertedIndex log_address_inverted_index() const { return {bundle.inverted_index(kInvIdxNameLogAddress)}; }
    snapshots::InvertedIndex log_topics_inverted_index() const { return {bundle.inverted_index(kInvIdxNameLogTopics)}; }
    snapshots::InvertedIndex traces_from_inverted_index() const { return {bundle.inverted_index(kInvIdxNameTracesFrom)}; }
    snapshots::InvertedIndex traces_to_inverted_index() const { return {bundle.inverted_index(kInvIdxNameTracesTo)}; }
};

struct StateDatabaseRef {
    const datastore::kvdb::DatabaseRef& database;

    datastore::kvdb::Domain accounts_domain() const { return {database.domain(kDomainNameAccounts)}; }
    datastore::kvdb::Domain storage_domain() const { return {database.domain(kDomainNameStorage)}; }
    datastore::kvdb::Domain code_domain() const { return {database.domain(kDomainNameCode)}; }
    datastore::kvdb::Domain commitment_domain() const { return {database.domain(kDomainNameCommitment)}; }
    datastore::kvdb::Domain receipts_domain() const { return {database.domain(kDomainNameReceipts)}; }

    datastore::kvdb::InvertedIndex log_address_inverted_index() const { return {database.inverted_index(kInvIdxNameLogAddress)}; }
    datastore::kvdb::InvertedIndex log_topics_inverted_index() const { return {database.inverted_index(kInvIdxNameLogTopics)}; }
    datastore::kvdb::InvertedIndex traces_from_inverted_index() const { return {database.inverted_index(kInvIdxNameTracesFrom)}; }
    datastore::kvdb::InvertedIndex traces_to_inverted_index() const { return {database.inverted_index(kInvIdxNameTracesTo)}; }
};

inline constexpr snapshots::SegmentAndAccessorIndexNames kHistorySegmentAndIdxNamesAccounts{
    kDomainNameAccounts,
    snapshots::Schema::kHistorySegmentName,
    snapshots::Schema::kHistoryAccessorIndexName,
};
inline constexpr snapshots::SegmentAndAccessorIndexNames kHistorySegmentAndIdxNamesStorage{
    kDomainNameStorage,
    snapshots::Schema::kHistorySegmentName,
    snapshots::Schema::kHistoryAccessorIndexName,
};
inline constexpr snapshots::SegmentAndAccessorIndexNames kHistorySegmentAndIdxNamesCode{
    kDomainNameCode,
    snapshots::Schema::kHistorySegmentName,
    snapshots::Schema::kHistoryAccessorIndexName,
};
inline constexpr snapshots::SegmentAndAccessorIndexNames kHistorySegmentAndIdxNamesCommitment{
    kDomainNameCommitment,
    snapshots::Schema::kHistorySegmentName,
    snapshots::Schema::kHistoryAccessorIndexName,
};
inline constexpr snapshots::SegmentAndAccessorIndexNames kHistorySegmentAndIdxNamesReceipts{
    kDomainNameReceipts,
    snapshots::Schema::kHistorySegmentName,
    snapshots::Schema::kHistoryAccessorIndexName,
};

}  // namespace silkworm::db::state
