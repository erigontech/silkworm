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

#include <silkworm/common/directories.hpp>
#include <silkworm/common/settings.hpp>
#include <silkworm/db/mdbx.hpp>

namespace silkworm::test {

//! \brief Context is a helper resource manager for test temporary directory and inmemory database.
//! Upon construction, it creates all the necessary data directories and DB tables.
//! \remarks Context follows the RAII idiom and cleans up its temporary directory upon destruction.
class Context {
  public:
    explicit Context(bool with_create_tables = true, bool inmemory = true);

    // Not copyable nor movable
    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;

    [[nodiscard]] silkworm::NodeSettings& node_settings() { return node_settings_; }

    [[nodiscard]] const DataDirectory& dir() const { return *(node_settings_.data_directory); }

    [[nodiscard]] mdbx::txn& txn() { return txn_; }

    [[nodiscard]] mdbx::env& env() { return env_; }

    void commit_txn() { txn_.commit(); }

    void commit_and_renew_txn() {
        txn_.commit();
        txn_ = env_.start_write();
    }

  private:
    TemporaryDirectory tmp_dir_{};
    silkworm::NodeSettings node_settings_;
    mdbx::env_managed env_;
    mdbx::txn_managed txn_;
};

}  // namespace silkworm::test
