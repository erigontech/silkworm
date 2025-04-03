// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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

inline const datastore::EntityName kStateRepositoryNameLatest{"StateLatest"};
inline const datastore::EntityName kStateRepositoryNameHistorical{"StateHistorical"};

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

inline const datastore::EntityName kDomainNameAccounts{"Account"};
inline const datastore::EntityName kDomainNameStorage{"Storage"};
inline const datastore::EntityName kDomainNameCode{"Code"};
inline const datastore::EntityName kDomainNameCommitment{"Commitment"};
inline const datastore::EntityName kDomainNameReceipts{"Receipt"};

inline const datastore::EntityName kInvIdxNameLogAddress{"LogAddress"};
inline const datastore::EntityName kInvIdxNameLogTopics{"LogTopics"};
inline const datastore::EntityName kInvIdxNameTracesFrom{"TracesFrom"};
inline const datastore::EntityName kInvIdxNameTracesTo{"TracesTo"};

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

inline const snapshots::SegmentAndAccessorIndexNames kHistorySegmentAndIdxNamesAccounts{
    kDomainNameAccounts,
    snapshots::Schema::kHistorySegmentName,
    snapshots::Schema::kHistoryAccessorIndexName,
};
inline const snapshots::SegmentAndAccessorIndexNames kHistorySegmentAndIdxNamesStorage{
    kDomainNameStorage,
    snapshots::Schema::kHistorySegmentName,
    snapshots::Schema::kHistoryAccessorIndexName,
};
inline const snapshots::SegmentAndAccessorIndexNames kHistorySegmentAndIdxNamesCode{
    kDomainNameCode,
    snapshots::Schema::kHistorySegmentName,
    snapshots::Schema::kHistoryAccessorIndexName,
};
inline const snapshots::SegmentAndAccessorIndexNames kHistorySegmentAndIdxNamesCommitment{
    kDomainNameCommitment,
    snapshots::Schema::kHistorySegmentName,
    snapshots::Schema::kHistoryAccessorIndexName,
};
inline const snapshots::SegmentAndAccessorIndexNames kHistorySegmentAndIdxNamesReceipts{
    kDomainNameReceipts,
    snapshots::Schema::kHistorySegmentName,
    snapshots::Schema::kHistoryAccessorIndexName,
};

}  // namespace silkworm::db::state
