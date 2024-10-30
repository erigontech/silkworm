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

#include "data_store.hpp"

#include "snapshot_bundle_factory_impl.hpp"

namespace silkworm::db {

DataStore::DataStore(
    EnvConfig chaindata_env_config,
    std::filesystem::path repository_path)
    : DataStore{
          db::open_env(chaindata_env_config),
          snapshots::SnapshotRepository{
              std::move(repository_path),
              std::make_unique<snapshots::StepToBlockNumConverter>(),
              std::make_unique<db::SnapshotBundleFactoryImpl>(),
          },
      } {}

}  // namespace silkworm::db
