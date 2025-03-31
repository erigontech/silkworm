// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <utility>

#include <boost/asio/co_spawn.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/core/chain/genesis.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/kv/api/client.hpp>
#include <silkworm/db/kv/api/direct_client.hpp>
#include <silkworm/db/kv/api/direct_service.hpp>
#include <silkworm/db/kv/api/service_router.hpp>
#include <silkworm/db/kv/api/state_cache.hpp>
#include <silkworm/db/test_util/test_database_context.hpp>
#include <silkworm/rpc/common/constants.hpp>
#include <silkworm/rpc/common/worker_pool.hpp>
#include <silkworm/rpc/json_rpc/request_handler.hpp>
#include <silkworm/rpc/json_rpc/validator.hpp>
#include <silkworm/rpc/test_util/service_context_test_base.hpp>
#include <silkworm/rpc/transport/stream_writer.hpp>

namespace silkworm::rpc::test_util {

inline constexpr size_t kDefaultCapacity = 4 * 1024;

class ChannelForTest : public StreamWriter {
  public:
    Task<void> open_stream() override { co_return; }
    size_t get_capacity() const noexcept override { return kDefaultCapacity; }
    Task<void> close_stream() override { co_return; }
    Task<size_t> write(std::string_view /* content */, bool /* last */) override { co_return 0; }
};

class RequestHandlerForTest : public json_rpc::RequestHandler {
  public:
    RequestHandlerForTest(ChannelForTest* channel,
                          commands::RpcApi& rpc_api,
                          const commands::RpcApiTable& rpc_api_table)
        : json_rpc::RequestHandler(channel, rpc_api, rpc_api_table) {}

    Task<void> request_and_create_reply(const nlohmann::json& request_json, std::string& response) {
        co_await RequestHandler::handle_request_and_create_reply(request_json, response);
    }

    Task<void> handle_request(const std::string& request, std::string& response) {
        auto answer = co_await RequestHandler::handle(request);
        if (answer) {
            response = *answer;
        }
    }
};

class TestDataStoreBase {
  public:
    db::DataStoreRef data_store() { return data_store_->ref(); }

  private:
    TemporaryDirectory tmp_dir_;
    db::test_util::TestDataStore data_store_{tmp_dir_};
};

class LocalContextTestBase : public ServiceContextTestBase {
  public:
    LocalContextTestBase(db::DataStoreRef data_store, db::kv::api::StateCache* state_cache) {
        datastore::kvdb::ROTxnManaged ro_txn = data_store.chaindata.access_ro().start_ro_tx();
        auto chain_config = db::read_chain_config(ro_txn);
        SILKWORM_ASSERT(chain_config);
        chain_config_ = std::move(*chain_config);
        db::kv::api::StateChangeRunner runner{ioc_.get_executor()};
        db::kv::api::ServiceRouter router{runner.state_changes_calls_channel()};
        add_private_service<db::kv::api::Client>(ioc_,
                                                 std::make_unique<db::kv::api::DirectClient>(
                                                     std::make_shared<db::kv::api::DirectService>(
                                                         router, std::move(data_store), chain_config_, state_cache)));
    }

  private:
    ChainConfig chain_config_;
};

template <typename TestRequestHandler>
class RpcApiTestBase : public LocalContextTestBase {
  public:
    explicit RpcApiTestBase(db::DataStoreRef data_store)
        : LocalContextTestBase{std::move(data_store), &state_cache_},
          workers_{1},
          socket_{ioc_},
          rpc_api_{ioc_, workers_},
          rpc_api_table_{kDefaultEth1ApiSpec} {
    }

    template <auto method, typename... Args>
    auto run(Args&&... args) {
        ChannelForTest channel;
        TestRequestHandler handler{&channel, rpc_api_, rpc_api_table_};
        return spawn_and_wait((handler.*method)(std::forward<Args>(args)...));
    }

  private:
    WorkerPool workers_;
    boost::asio::ip::tcp::socket socket_;
    commands::RpcApi rpc_api_;
    commands::RpcApiTable rpc_api_table_;
    db::kv::api::CoherentStateCache state_cache_;
};

class RpcApiE2ETest : public TestDataStoreBase, RpcApiTestBase<RequestHandlerForTest> {
  public:
    explicit RpcApiE2ETest() : RpcApiTestBase{data_store()} {
        // Ensure JSON RPC spec has been loaded into the validator
        if (!jsonrpc_spec_loaded) {
            json_rpc::Validator::load_specification();
            jsonrpc_spec_loaded = true;
        }
    }
    using RpcApiTestBase<RequestHandlerForTest>::run;

  private:
    static inline bool jsonrpc_spec_loaded{false};
};

}  // namespace silkworm::rpc::test_util
