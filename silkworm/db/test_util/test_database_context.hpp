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

#include <filesystem>

#include <silkworm/core/state/in_memory_state.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/blocks/schema_config.hpp>
#include <silkworm/db/data_store.hpp>
#include <silkworm/db/datastore/kvdb/mdbx.hpp>
#include <silkworm/db/state/schema_config.hpp>
#include <silkworm/infra/common/directories.hpp>

namespace silkworm::db::test_util {

std::filesystem::path get_tests_dir();

InMemoryState populate_genesis(db::RWTxn& txn, const std::filesystem::path& tests_dir);

void populate_blocks(db::RWTxn& txn, const std::filesystem::path& tests_dir, InMemoryState& state_buffer);

class TestDatabaseContext {
  public:
    explicit TestDatabaseContext(const TemporaryDirectory& tmp_dir);
    virtual ~TestDatabaseContext() = default;

    virtual datastore::kvdb::ROAccess chaindata() const {
        return datastore::kvdb::ROAccess{*env_};
    }
    virtual datastore::kvdb::RWAccess chaindata_rw() const {
        return datastore::kvdb::RWAccess{*env_};
    }

    silkworm::ChainConfig get_chain_config() const;
    const std::filesystem::path& chaindata_dir_path() const { return chaindata_dir_path_; }

  protected:
    mdbx::env_managed move_env() {
        mdbx::env_managed env{std::move(*env_)};
        env_.reset();
        return env;
    }

    std::filesystem::path chaindata_dir_path_;
    std::unique_ptr<mdbx::env_managed> env_;
};

class TestDataStore : public TestDatabaseContext {
  public:
    explicit TestDataStore(const TemporaryDirectory& tmp_dir)
        : TestDatabaseContext{tmp_dir},
          data_store_{
              move_env(),
              DataDirectory{tmp_dir.path(), true}.snapshots().path(),
          } {}
    ~TestDataStore() override = default;

    db::DataStore& operator*() { return data_store_; }
    db::DataStore* operator->() { return &data_store_; }

    datastore::kvdb::ROAccess chaindata() const override {
        return data_store_.chaindata().access_ro();
    }
    datastore::kvdb::RWAccess chaindata_rw() const override {
        return data_store_.chaindata().access_rw();
    }

    db::DataModelFactory data_model_factory() {
        return db::DataModelFactory{data_store_.ref()};
    }

  private:
    db::DataStore data_store_;
};

}  // namespace silkworm::db::test_util
