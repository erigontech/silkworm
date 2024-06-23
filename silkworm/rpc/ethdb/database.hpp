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

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/io_context.hpp>

#include <silkworm/db/remote/kv/api/transaction.hpp>

namespace silkworm::rpc::ethdb {

class Database {
  public:
    Database() = default;
    virtual ~Database() = default;

    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;

    virtual Task<std::unique_ptr<db::kv::api::Transaction>> begin() = 0;
};

}  // namespace silkworm::rpc::ethdb
