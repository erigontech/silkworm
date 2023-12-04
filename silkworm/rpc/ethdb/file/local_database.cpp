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

#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/ethdb/file/local_transaction.hpp>

namespace silkworm::rpc::ethdb::file {

LocalDatabase::LocalDatabase(mdbx::env chaindata_env) : chaindata_env_{std::move(chaindata_env)} {
    SILK_TRACE << "LocalDatabase::ctor " << this;
}

LocalDatabase::~LocalDatabase() {
    SILK_TRACE << "LocalDatabase::dtor " << this;
}

Task<std::unique_ptr<Transaction>> LocalDatabase::begin() {
    SILK_TRACE << "LocalDatabase::begin " << this << " start";
    auto txn = std::make_unique<LocalTransaction>(chaindata_env_);
    co_await txn->open();
    SILK_TRACE << "LocalDatabase::begin " << this << " txn: " << txn.get() << " end";
    co_return txn;
}

}  // namespace silkworm::rpc::ethdb::file
