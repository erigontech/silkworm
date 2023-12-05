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

#include <bit>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <utility>
#include <vector>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/thread_pool.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/core/chain/genesis.hpp>
#include <silkworm/core/execution/execution.hpp>
#include <silkworm/core/state/in_memory_state.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/receipt.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/node/db/access_layer.hpp>
#include <silkworm/node/db/buffer.hpp>
#include <silkworm/node/db/genesis.hpp>
#include <silkworm/rpc/common/constants.hpp>
#include <silkworm/rpc/ethdb/file/local_database.hpp>
#include <silkworm/rpc/http/request_handler.hpp>
#include <silkworm/rpc/test/context_test_base.hpp>

namespace silkworm::rpc::test {

std::filesystem::path get_tests_dir();

InMemoryState populate_genesis(db::RWTxn& txn, const std::filesystem::path& tests_dir);

void populate_blocks(db::RWTxn& txn, const std::filesystem::path& tests_dir, InMemoryState& state_buffer);

class RequestHandler_ForTest : public silkworm::rpc::http::RequestHandler {
  public:
    RequestHandler_ForTest(boost::asio::ip::tcp::socket& socket,
                           commands::RpcApi& rpc_api,
                           const commands::RpcApiTable& rpc_api_table,
                           std::optional<std::string> jwt_secret)
        : silkworm::rpc::http::RequestHandler(socket, rpc_api, rpc_api_table, allowed_origins, std::move(jwt_secret)) {
    }

    Task<void> request_and_create_reply(const nlohmann::json& request_json, http::Reply& reply) {
        co_await RequestHandler::handle_request_and_create_reply(request_json, reply);
    }

    Task<void> handle_request(const std::string& request_str, http::Reply& reply) {
        http::Request request;
        request.content = request_str;
        co_await RequestHandler::handle(request);
        reply = std::move(reply_);
    }

    // Override required to avoid writing to socket and to intercept the reply
    Task<void> do_write(http::Reply& reply) override {
        try {
            reply.headers.emplace_back(http::Header{"Content-Length", std::to_string(reply.content.size())});
            reply.headers.emplace_back(http::Header{"Content-Type", "application/json"});

            reply_ = std::move(reply);
        } catch (const boost::system::system_error& se) {
            std::rethrow_exception(std::make_exception_ptr(se));
        } catch (const std::exception& e) {
            std::rethrow_exception(std::make_exception_ptr(e));
        }
        co_return;
    }

  private:
    inline static const std::vector<std::string> allowed_origins;
    http::Reply reply_;
};

class LocalContextTestBase : public silkworm::rpc::test::ContextTestBase {
  public:
    explicit LocalContextTestBase(mdbx::env& chaindata_env) : ContextTestBase() {
        add_private_service<ethdb::Database>(io_context_, std::make_unique<ethdb::file::LocalDatabase>(chaindata_env));
    }
};

template <typename TestRequestHandler>
class RpcApiTestBase : public LocalContextTestBase {
  public:
    explicit RpcApiTestBase(mdbx::env& chaindata_env) : LocalContextTestBase(chaindata_env), workers_{1}, socket{io_context_}, rpc_api{io_context_, workers_}, rpc_api_table{kDefaultEth1ApiSpec} {
    }

    template <auto method, typename... Args>
    auto run(Args&&... args) {
        TestRequestHandler handler{socket, rpc_api, rpc_api_table, ""};
        return spawn_and_wait((handler.*method)(std::forward<Args>(args)...));
    }

    boost::asio::thread_pool workers_;
    boost::asio::ip::tcp::socket socket;
    commands::RpcApi rpc_api;
    commands::RpcApiTable rpc_api_table;
};

class TestDatabaseContext {
  public:
    TestDatabaseContext();

    ~TestDatabaseContext() {
        auto db_path = db.get_path();
        db.close();
        std::filesystem::remove_all(db_path);
    }

    mdbx::env_managed db;
};

}  // namespace silkworm::rpc::test