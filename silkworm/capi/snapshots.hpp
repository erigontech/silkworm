/*
   Copyright 2025 The Silkworm Authors

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

#include <span>

#include <tl/expected.hpp>

#include <silkworm/infra/common/memory_mapped_file.hpp>

#include "silkworm.h"

namespace silkworm::snapshots {
struct SnapshotBundle;
struct SnapshotBundleEntityData;
}  // namespace silkworm::snapshots

using SnapshotBundleResult = tl::expected<silkworm::snapshots::SnapshotBundle, int>;
using SnapshotBundleEntityDataResult = tl::expected<silkworm::snapshots::SnapshotBundleEntityData, int>;

silkworm::MemoryMappedRegion make_region(const SilkwormMemoryMappedFile& mmf);

SnapshotBundleEntityDataResult build_inverted_index_entity_data(const SilkwormInvertedIndexSnapshot& snapshot);

SnapshotBundleEntityDataResult build_domain_entity_data(const SilkwormDomainSnapshot& snapshot, uint32_t salt);

SnapshotBundleResult build_state_snapshot(const SilkwormStateSnapshot* snapshot, uint32_t salt);
