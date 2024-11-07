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
#include "../datastore/snapshots/schema.hpp"
#include "../datastore/snapshots/snapshot_bundle_factory.hpp"
#include "../datastore/snapshots/snapshot_repository.hpp"

namespace silkworm::db::state {

inline constexpr datastore::EntityName kStateRepositoryName{"State"};

inline constexpr std::string_view kFileExtKV{".kv"};
inline constexpr std::string_view kFileExtKVI{".kvi"};
inline constexpr std::string_view kFileExtKVEI{".kvei"};
inline constexpr std::string_view kFileExtBT{".bt"};
inline constexpr std::string_view kFileExtV{".v"};
inline constexpr std::string_view kFileExtVI{".vi"};
inline constexpr std::string_view kFileExtEF{".ef"};
inline constexpr std::string_view kFileExtEFI{".efi"};

snapshots::Schema::RepositoryDef make_state_repository_schema();

std::unique_ptr<snapshots::SnapshotBundleFactory> make_state_bundle_factory();

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
    const snapshots::SnapshotBundleData& data;
};

}  // namespace silkworm::db::state
