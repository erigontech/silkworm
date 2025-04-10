// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/datastore/kvdb/database.hpp>
#include <silkworm/db/datastore/snapshots/snapshot_repository.hpp>

namespace silkworm::db::capi {

struct Component {
    silkworm::snapshots::SnapshotRepository blocks_repository;
    silkworm::snapshots::SnapshotRepository state_repository_latest;
    silkworm::snapshots::SnapshotRepository state_repository_historical;
    std::unique_ptr<silkworm::datastore::kvdb::DatabaseUnmanaged> chaindata;

    DataStoreRef data_store() {
        SILKWORM_ASSERT(chaindata);
        return DataStoreRef{
            chaindata->ref(),
            blocks_repository,
            state_repository_latest,
            state_repository_historical,
        };
    }

    DataModelFactory data_model_factory() {
        return DataModelFactory{data_store()};
    }
};

}  // namespace silkworm::db::capi
