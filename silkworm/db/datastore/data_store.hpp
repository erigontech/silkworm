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

#include <map>
#include <memory>

#include "common/entity_name.hpp"
#include "mdbx/mdbx.hpp"
#include "snapshots/snapshot_repository.hpp"

namespace silkworm::datastore {

class DataStore {
  public:
    DataStore(
        mdbx::env_managed chaindata_env,
        std::map<EntityName, std::unique_ptr<snapshots::SnapshotRepository>> repositories)
        : chaindata_env_{std::move(chaindata_env)},
          repositories_{std::move(repositories)} {}

    void close() {
        chaindata_env_.close();
        for (auto& entry : repositories_)
            entry.second->close();
    }

    db::ROAccess chaindata() const { return db::ROAccess{chaindata_env_}; }
    db::RWAccess chaindata_rw() const { return db::RWAccess{chaindata_env_}; }
    snapshots::SnapshotRepository& repository(const EntityName& name) const { return *repositories_.at(name); }

  private:
    mdbx::env_managed chaindata_env_;
    std::map<EntityName, std::unique_ptr<snapshots::SnapshotRepository>> repositories_;
};

}  // namespace silkworm::datastore
