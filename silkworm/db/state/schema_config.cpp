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

#include "schema_config.hpp"

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
