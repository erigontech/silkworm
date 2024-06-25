/*
   Copyright 2023 The Silkworm Authors

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
#include <string>
#include <utility>

#include <silkworm/db/kv/api/state_cache.hpp>
#include <silkworm/db/kv/api/transaction.hpp>
#include <silkworm/db/mdbx/mdbx.hpp>
#include <silkworm/rpc/ethdb/database.hpp>

namespace silkworm::rpc::ethdb::file {

using db::kv::api::StateCache;

class LocalDatabase : public Database {
  public:
    explicit LocalDatabase(StateCache* state_cache, mdbx::env chaindata_env);

    ~LocalDatabase() override;

    LocalDatabase(const LocalDatabase&) = delete;
    LocalDatabase& operator=(const LocalDatabase&) = delete;

    Task<std::unique_ptr<db::kv::api::Transaction>> begin() override;

  private:
    StateCache* state_cache_;
    mdbx::env chaindata_env_;
};

}  // namespace silkworm::rpc::ethdb::file
