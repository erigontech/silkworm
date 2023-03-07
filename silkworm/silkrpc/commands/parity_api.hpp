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

#include <silkworm/silkrpc/config.hpp> // NOLINT(build/include_order)

#include <boost/asio/awaitable.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/silkrpc/concurrency/context_pool.hpp>
#include <silkworm/silkrpc/core/rawdb/accessors.hpp>
#include <silkworm/silkrpc/json/types.hpp>
#include <silkworm/silkrpc/ethdb/database.hpp>

namespace silkrpc::http { class RequestHandler; }

namespace silkrpc::commands {

class ParityRpcApi {
public:
    explicit ParityRpcApi(Context& context) : database_(context.database()), context_(context) {}
    virtual ~ParityRpcApi() {}

    ParityRpcApi(const ParityRpcApi&) = delete;
    ParityRpcApi& operator=(const ParityRpcApi&) = delete;

protected:
    boost::asio::awaitable<void> handle_parity_get_block_receipts(const nlohmann::json& request, nlohmann::json& reply);
    boost::asio::awaitable<void> handle_parity_list_storage_keys(const nlohmann::json& request, nlohmann::json& reply);

private:
    std::unique_ptr<ethdb::Database>& database_;
    Context& context_;

    friend class silkrpc::http::RequestHandler;
};

} // namespace silkrpc::commands

