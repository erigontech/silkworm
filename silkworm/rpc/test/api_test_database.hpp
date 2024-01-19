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
#include <silkworm/core/common/empty_hashes.hpp>
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
#include <silkworm/rpc/http/channel.hpp>
#include <silkworm/rpc/http/request_handler.hpp>
#include <silkworm/rpc/test/context_test_base.hpp>

namespace silkworm::rpc::test {

std::filesystem::path get_tests_dir();

InMemoryState populate_genesis(db::RWTxn& txn, const std::filesystem::path& tests_dir);

void populate_blocks(db::RWTxn& txn, const std::filesystem::path& tests_dir, InMemoryState& state_buffer);

class ChannelForTest : public Channel {
  public:
    Task<void> open_stream() override { co_return; }
    Task<void> write_rsp(std::string& response) override {
        response_ = response;
        co_return;
    }
    Task<std::size_t> write(std::string_view /* content */) override { co_return 0; }
    Task<void> close() override { co_return; }

    std::string& get_response() { return response_; }

  private:
    std::string response_;
};

class RequestHandler_ForTest : public http::RequestHandler {
  public:
    RequestHandler_ForTest(ChannelForTest* channel,
                           commands::RpcApi& rpc_api,
                           const commands::RpcApiTable& rpc_api_table)
        : http::RequestHandler(channel, rpc_api, rpc_api_table) {}

    Task<void> request_and_create_reply(const nlohmann::json& request_json, std::string& response) {
        co_await RequestHandler::handle_request_and_create_reply(request_json, response);
    }

    Task<void> handle_request(const std::string& request_str, std::string& response) {
        co_await RequestHandler::handle(request_str);
        response = std::move(channel_->get_response());
    }

  private:
    inline static const std::vector<std::string> allowed_origins;
    ChannelForTest* channel_;
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
    explicit RpcApiTestBase(mdbx::env& chaindata_env)
        : LocalContextTestBase(chaindata_env),
          workers_{1},
          socket_{io_context_},
          rpc_api_{io_context_, workers_},
          rpc_api_table_{kDefaultEth1ApiSpec} {
    }

    template <auto method, typename... Args>
    auto run(Args&&... args) {
        ChannelForTest channel;
        TestRequestHandler handler{&channel, rpc_api_, rpc_api_table_};
        return spawn_and_wait((handler.*method)(std::forward<Args>(args)...));
    }

    boost::asio::thread_pool workers_;
    boost::asio::ip::tcp::socket socket_;
    commands::RpcApi rpc_api_;
    commands::RpcApiTable rpc_api_table_;
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

class RpcApiE2ETest : public TestDatabaseContext, RpcApiTestBase<RequestHandler_ForTest> {
  public:
    explicit RpcApiE2ETest() : RpcApiTestBase<RequestHandler_ForTest>(db) {}
    using RpcApiTestBase<RequestHandler_ForTest>::run;

  private:
    static inline test_util::SetLogVerbosityGuard log_guard_{log::Level::kNone};
};

}  // namespace silkworm::rpc::test
