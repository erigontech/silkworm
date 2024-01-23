/*
   Copyright 2022 The Silkworm Authors

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

#include <memory>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/node/db/mdbx.hpp>
#include <silkworm/node/db/prune_mode.hpp>

namespace silkworm::db::test_util {

//! \brief Context is a helper resource manager for test temporary directory and inmemory database.
//! Upon construction, it creates all the necessary data directories and DB tables.
//! \remarks Context follows the RAII idiom and cleans up its temporary directory upon destruction.
class TempChainData {
  public:
    explicit TempChainData(bool with_create_tables = true, bool in_memory = true);

    // Not copyable nor movable
    TempChainData(const TempChainData&) = delete;
    TempChainData& operator=(const TempChainData&) = delete;

    [[nodiscard]] const ChainConfig& chain_config() const { return chain_config_; }

    void add_genesis_data() const;

    [[nodiscard]] const DataDirectory& dir() const { return data_dir_; }

    [[nodiscard]] const db::EnvConfig& chaindata_env_config() const { return chaindata_env_config_; }

    [[nodiscard]] mdbx::env& env() { return env_; }

    [[nodiscard]] mdbx::txn& txn() const { return *txn_; }

    [[nodiscard]] db::RWTxn& rw_txn() const { return *txn_; }

    void commit_txn() const { txn_->commit_and_stop(); }

    void commit_and_renew_txn() const { txn_->commit_and_renew(); }

    [[nodiscard]] const db::PruneMode& prune_mode() const { return prune_mode_; }
    void set_prune_mode(const db::PruneMode& prune_mode) { prune_mode_ = prune_mode; }

  private:
    TemporaryDirectory tmp_dir_;
    DataDirectory data_dir_;
    ChainConfig chain_config_;
    db::EnvConfig chaindata_env_config_;
    mdbx::env_managed env_;
    std::unique_ptr<db::RWTxn> txn_;
    db::PruneMode prune_mode_;
};

}  // namespace silkworm::db::test_util
