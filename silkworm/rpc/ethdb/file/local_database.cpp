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

#include "local_database.hpp"

#include <utility>

#include <silkworm/db/kv/api/local_transaction.hpp>
#include <silkworm/infra/common/log.hpp>

namespace silkworm::rpc::ethdb::file {

LocalDatabase::LocalDatabase(
    db::DataStoreRef data_store,
    StateCache* state_cache)
    : data_store_{std::move(data_store)},
      state_cache_{state_cache} {
    SILK_TRACE << "LocalDatabase::ctor " << this;
}

LocalDatabase::~LocalDatabase() {
    SILK_TRACE << "LocalDatabase::dtor " << this;
}

Task<std::unique_ptr<db::kv::api::Transaction>> LocalDatabase::begin() {
    SILK_TRACE << "LocalDatabase::begin " << this << " start";
    auto txn = std::make_unique<db::kv::api::LocalTransaction>(data_store_, state_cache_);
    co_await txn->open();
    SILK_TRACE << "LocalDatabase::begin " << this << " txn: " << txn.get() << " end";
    co_return txn;
}

}  // namespace silkworm::rpc::ethdb::file
