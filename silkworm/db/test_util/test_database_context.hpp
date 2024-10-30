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
#include <silkworm/db/datastore/mdbx/mdbx.hpp>
#include <silkworm/infra/common/directories.hpp>

namespace silkworm::db::test_util {

std::filesystem::path get_tests_dir();

InMemoryState populate_genesis(db::RWTxn& txn, const std::filesystem::path& tests_dir);

void populate_blocks(db::RWTxn& txn, const std::filesystem::path& tests_dir, InMemoryState& state_buffer);

class TestDatabaseContext {
  public:
    TestDatabaseContext();

    virtual ~TestDatabaseContext() {
        if (env_) {
            env_->close();
            std::filesystem::remove_all(chaindata_dir_path_);
        }
    }

    // TODO: make private and use RXAccess
    virtual mdbx::env mdbx_env() const {
        return *env_;  // NOLINT(cppcoreguidelines-slicing)
    }
    db::ROAccess chaindata() const {
        return db::ROAccess{mdbx_env()};
    }
    db::RWAccess chaindata_rw() const {
        return db::RWAccess{mdbx_env()};
    }

    silkworm::ChainConfig get_chain_config() const;

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
        : data_store_{
              move_env(),
              blocks::make_blocks_repository(
                  DataDirectory{tmp_dir.path(), true}.snapshots().path()),
          } {}

    ~TestDataStore() override {
        data_store_.close();
        std::filesystem::remove_all(chaindata_dir_path_);
    }

    mdbx::env mdbx_env() const override {
        return data_store_.chaindata_env();
    }

    db::DataStore& operator*() { return data_store_; }
    db::DataStore* operator->() { return &data_store_; }

    db::DataModelFactory data_model_factory() {
        return [ref = data_store_.ref()](db::ROTxn& tx) { return db::DataModel{tx, ref.repository}; };
    }

  private:
    db::DataStore data_store_;
};

}  // namespace silkworm::db::test_util
