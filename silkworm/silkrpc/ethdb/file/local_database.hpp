/*
   Copyright 2020 The Silkrpc Authors

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
#include <utility>
#include <string>

#include <silkworm/silkrpc/ethdb/database.hpp>
#include <silkworm/silkrpc/ethdb/transaction.hpp>

#include <silkworm/node/db/mdbx.hpp>

namespace silkrpc::ethdb::file {

class LocalDatabase: public Database {
public:
    explicit LocalDatabase(std::shared_ptr<mdbx::env_managed> chaindata_env);

    ~LocalDatabase();

    LocalDatabase(const LocalDatabase&) = delete;
    LocalDatabase& operator=(const LocalDatabase&) = delete;

    boost::asio::awaitable<std::unique_ptr<Transaction>> begin() override;

private:
    std::shared_ptr<mdbx::env_managed> chaindata_env_;
};

} // namespace silkrpc::ethdb::file

