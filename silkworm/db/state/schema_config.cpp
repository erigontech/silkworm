// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "schema_config.hpp"

#include <array>

#include <silkworm/infra/common/environment.hpp>

#include "state_index_builders_factory.hpp"
#include "step_txn_id_converter.hpp"

namespace silkworm::db::state {

snapshots::Schema::RepositoryDef make_state_repository_schema_latest() {
    snapshots::Schema::RepositoryDef schema;
    schema.index_salt_file_name("salt-state.txt");

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

static constexpr size_t kDefaultDomainCacheSize = 10'000;
static constexpr size_t kDefaultInvertedIndexCacheSize = 4'096;

// 1. std::array instead of const char* because MSVC is stricter on non-type template parameters passed by reference
// 2. explicit std::array template arguments to avoid incorrect CTAD as std::array<const char*, 1>
static constexpr std::array<const char, 17> kDomainCacheEnvVar{"D_LRU_CACHE_SIZE"};
static constexpr std::array<const char, 18> kInvertedIndexCacheEnvVar{"II_LRU_CACHE_SIZE"};

template <typename Cache, const auto& env_var_name, size_t default_size>
static size_t cache_size() {
    const auto cache_size_var = Environment::get(env_var_name.data());
    return cache_size_var.empty() ? default_size : std::stoul(cache_size_var);
}

template <typename Cache, const auto& env_var_name, size_t default_size>
static std::unique_ptr<Cache> make_cache(std::optional<uint32_t> salt) {
    const size_t size = cache_size<Cache, env_var_name, default_size>();
    return size > 0 ? std::make_unique<Cache>(size, salt.value_or(0)) : nullptr;
}

template <typename Cache, const auto& env_var_name, size_t default_size>
static auto make_caches(std::optional<uint32_t> salt) {
    std::map<datastore::EntityName, std::unique_ptr<Cache>> caches;
    for (const auto& entity_name : {kDomainNameAccounts, kDomainNameStorage, kDomainNameCode, kDomainNameReceipts}) {
        caches.emplace(entity_name, make_cache<Cache, env_var_name, default_size>(salt));
    }
    return caches;
}

static snapshots::DomainGetLatestCaches make_domain_caches(std::optional<uint32_t> salt) {
    return make_caches<snapshots::DomainGetLatestCache, kDomainCacheEnvVar, kDefaultDomainCacheSize>(salt);
}

static snapshots::InvertedIndexSeekCaches make_inverted_index_caches(std::optional<uint32_t> salt) {
    return make_caches<snapshots::InvertedIndexSeekCache, kInvertedIndexCacheEnvVar, kDefaultInvertedIndexCacheSize>(salt);
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
        kStepToTxnIdConverter,
        index_salt,
        std::make_unique<StateIndexBuildersFactory>(schema),
        make_domain_caches(index_salt),
        make_inverted_index_caches(index_salt),
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
