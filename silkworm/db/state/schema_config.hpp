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
#include "../datastore/domain.hpp"
#include "../datastore/inverted_index.hpp"
#include "../datastore/snapshots/index_builders_factory.hpp"
#include "../datastore/snapshots/schema.hpp"
#include "../datastore/snapshots/snapshot_repository.hpp"

namespace silkworm::db::state {

inline constexpr datastore::EntityName kStateRepositoryName{"State"};

snapshots::Schema::RepositoryDef make_state_repository_schema();

std::unique_ptr<snapshots::IndexBuildersFactory> make_state_index_builders_factory();

snapshots::SnapshotRepository make_state_repository(
    std::filesystem::path dir_path,
    bool open = true);

inline constexpr datastore::EntityName kDomainNameAccounts{"Accounts"};
inline constexpr datastore::EntityName kDomainNameStorage{"Storage"};
inline constexpr datastore::EntityName kDomainNameCode{"Code"};
inline constexpr datastore::EntityName kDomainNameCommitment{"Commitment"};
inline constexpr datastore::EntityName kDomainNameReceipts{"Receipts"};

inline constexpr datastore::EntityName kInvIdxNameLogAddress{"LogAddress"};
inline constexpr datastore::EntityName kInvIdxNameLogTopics{"LogTopics"};
inline constexpr datastore::EntityName kInvIdxNameTracesFrom{"TracesFrom"};
inline constexpr datastore::EntityName kInvIdxNameTracesTo{"TracesTo"};

struct BundleDataRef {
    const snapshots::SnapshotBundle& bundle;

    datastore::Domain accounts_domain() const { return {bundle.domain(kDomainNameAccounts)}; }
    datastore::Domain storage_domain() const { return {bundle.domain(kDomainNameStorage)}; }
    datastore::Domain code_domain() const { return {bundle.domain(kDomainNameCode)}; }
    datastore::Domain commitment_domain() const { return {bundle.domain(kDomainNameCommitment)}; }
    datastore::Domain receipts_domain() const { return {bundle.domain(kDomainNameReceipts)}; }

    datastore::InvertedIndex log_address_inv_idx() const { return {bundle.inverted_index(kInvIdxNameLogAddress)}; }
    datastore::InvertedIndex log_topics_inv_idx() const { return {bundle.inverted_index(kInvIdxNameLogTopics)}; }
    datastore::InvertedIndex traces_from_inv_idx() const { return {bundle.inverted_index(kInvIdxNameTracesFrom)}; }
    datastore::InvertedIndex traces_to_inv_idx() const { return {bundle.inverted_index(kInvIdxNameTracesTo)}; }
};

}  // namespace silkworm::db::state
