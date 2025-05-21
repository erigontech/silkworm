// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "schema_config.hpp"

#include <array>

#include <silkworm/infra/common/environment.hpp>

#include "../datastore/snapshots/domain_get_latest_query.hpp"
#include "../datastore/snapshots/inverted_index_seek_query.hpp"
#include "state_index_builders_factory.hpp"
#include "step_txn_id_converter.hpp"

namespace silkworm::db::state {

snapshots::Schema::RepositoryDef make_state_repository_schema_latest() {
    snapshots::Schema::RepositoryDef schema;
    schema.index_salt_file_name("salt-state.txt");
    schema.step_size(kStepSizeForTemporalSnapshots);

    schema.domain(kDomainNameAccounts)
        .tag_override(kDomainAccountsTag);
    schema.domain(kDomainNameStorage)
        .kv_segment_compression_kind(snapshots::seg::CompressionKind::kKeys);
    schema.domain(kDomainNameCode)
        .kv_segment_compression_kind(snapshots::seg::CompressionKind::kValues);
    // TODO(canepat): enable after fixing .kvi configuration with IndexList-like implementation
    // schema.domain(kDomainNameCommitment)
    //    .kv_segment_compression_kind(snapshots::seg::CompressionKind::kKeys);
    schema.domain(kDomainNameReceipts);

    return schema;
}

snapshots::Schema::RepositoryDef make_state_repository_schema_historical() {
    snapshots::Schema::RepositoryDef schema;
    schema.index_salt_file_name("salt-state.txt");
    schema.step_size(kStepSizeForTemporalSnapshots);

    schema.history(kDomainNameAccounts)
        .tag_override(kDomainAccountsTag);
    schema.history(kDomainNameStorage);
    schema.history(kDomainNameCode)
        .segment(snapshots::Schema::kHistorySegmentName)
        .compression_enabled(true);
    schema.history(kDomainNameReceipts);

    schema.inverted_index(kInvIdxNameLogAddress)
        .tag_override(kInvIdxLogAddressTag);
    schema.inverted_index(kInvIdxNameLogTopics);
    schema.inverted_index(kInvIdxNameTracesFrom);
    schema.inverted_index(kInvIdxNameTracesTo);

    return schema;
}

datastore::kvdb::Schema::DatabaseDef make_state_database_schema() {
    datastore::kvdb::Schema::DatabaseDef schema;

    schema.domain(kDomainNameAccounts);
    schema.domain(kDomainNameStorage);
    schema.domain(kDomainNameCode)
        .enable_large_values()
        .values_disable_multi_value();
    schema.domain(kDomainNameCommitment)
        .without_history();
    schema.domain(kDomainNameReceipts);

    schema.inverted_index(kInvIdxNameLogAddress);
    schema.inverted_index(kInvIdxNameLogTopics);
    schema.inverted_index(kInvIdxNameTracesFrom);
    schema.inverted_index(kInvIdxNameTracesTo);

    return schema;
}

snapshots::QueryCachesSchema make_query_caches_schema() {
    snapshots::QueryCachesSchema schema;
    schema.index_salt_file_name("salt-state.txt");

    schema.enable(kDomainNameAccounts);
    schema.enable(kDomainNameStorage);
    schema.enable(kDomainNameCode);
    schema.enable(kDomainNameReceipts);

    static constexpr size_t kDefaultDomainCacheSize = 10'000;
    static constexpr size_t kDefaultInvertedIndexCacheSize = 4'096;
    schema.cache_size(snapshots::DomainGetLatestQueryRawWithCache::kName, kDefaultDomainCacheSize);
    schema.cache_size(snapshots::InvertedIndexSeekQueryRawWithCache::kName, kDefaultInvertedIndexCacheSize);

    return schema;
}

static snapshots::SnapshotRepository make_state_repository(
    datastore::EntityName name,
    std::filesystem::path dir_path,
    bool open,
    const snapshots::Schema::RepositoryDef& schema,
    std::optional<uint32_t> index_salt) {
    return snapshots::SnapshotRepository{
        std::move(name),
        std::move(dir_path),
        open,
        schema,
        index_salt,
        std::make_unique<StateIndexBuildersFactory>(schema),
    };
}

snapshots::SnapshotRepository make_state_repository_latest(
    std::filesystem::path dir_path,
    bool open,
    std::optional<uint32_t> index_salt) {
    return make_state_repository(kStateRepositoryNameLatest,
                                 std::move(dir_path), open, make_state_repository_schema_latest(), index_salt);
}

snapshots::SnapshotRepository make_state_repository_historical(
    std::filesystem::path dir_path,
    bool open,
    std::optional<uint32_t> index_salt) {
    return make_state_repository(kStateRepositoryNameHistorical,
                                 std::move(dir_path), open, make_state_repository_schema_historical(), index_salt);
}

}  // namespace silkworm::db::state
