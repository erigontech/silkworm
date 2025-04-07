// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/blocks/schema_config.hpp>
#include <silkworm/db/data_store.hpp>
#include <silkworm/db/datastore/kvdb/mdbx.hpp>
#include <silkworm/db/prune_mode.hpp>
#include <silkworm/db/state/schema_config.hpp>
#include <silkworm/infra/common/directories.hpp>

namespace silkworm::db::test_util {

//! \brief TempChainData is a helper resource manager for a temporary directory plus an in-memory database.
//! Upon construction, it creates all the necessary data directories and database tables.
//! \remarks TempChainData follows the RAII idiom and cleans up its temporary directory upon destruction.
class TempChainData {
  public:
    explicit TempChainData(bool with_create_tables = true, bool in_memory = true);
    virtual ~TempChainData() = default;

    // Not copyable nor movable
    TempChainData(const TempChainData&) = delete;
    TempChainData& operator=(const TempChainData&) = delete;

    const ChainConfig& chain_config() const { return chain_config_; }

    void add_genesis_data() const;

    const DataDirectory& dir() const { return data_dir_; }

    const datastore::kvdb::EnvConfig& chaindata_env_config() const { return chaindata_env_config_; }

    virtual datastore::kvdb::ROAccess chaindata() const {
        return datastore::kvdb::ROAccess{*env_};
    }
    virtual datastore::kvdb::RWAccess chaindata_rw() const {
        return datastore::kvdb::RWAccess{*env_};
    }

    mdbx::txn& txn() const { return *txn_; }

    db::RWTxn& rw_txn() const { return *txn_; }

    void commit_txn() const { txn_->commit_and_stop(); }

    void commit_and_renew_txn() const { txn_->commit_and_renew(); }

    const db::PruneMode& prune_mode() const { return prune_mode_; }
    void set_prune_mode(const db::PruneMode& prune_mode) { prune_mode_ = prune_mode; }

  protected:
    mdbx::env_managed move_env() {
        mdbx::env_managed env{std::move(*env_)};
        env_.reset();
        return env;
    }

    TemporaryDirectory tmp_dir_;
    DataDirectory data_dir_;
    ChainConfig chain_config_;
    datastore::kvdb::EnvConfig chaindata_env_config_;
    std::unique_ptr<mdbx::env_managed> env_;
    std::unique_ptr<db::RWTxn> txn_;
    db::PruneMode prune_mode_;
};

class TempChainDataStore : public TempChainData {
  public:
    TempChainDataStore()
        : data_store_{
              move_env(),
              data_dir_.snapshots().path(),
          } {}
    ~TempChainDataStore() override {
        // need to destroy a started RWTxn in the base class before destroying env_managed inside the data_store_
        txn_.reset();
    }

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
