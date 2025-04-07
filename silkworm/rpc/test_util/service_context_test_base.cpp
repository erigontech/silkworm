// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "service_context_test_base.hpp"

#include <memory>

#include <silkworm/core/common/block_cache.hpp>
#include <silkworm/db/kv/api/client.hpp>
#include <silkworm/db/kv/api/state_cache.hpp>
#include <silkworm/db/kv/grpc/client/remote_client.hpp>
#include <silkworm/infra/concurrency/private_service.hpp>
#include <silkworm/infra/concurrency/shared_service.hpp>
#include <silkworm/rpc/core/filter_storage.hpp>
#include <silkworm/rpc/ethbackend/remote_backend.hpp>
#include <silkworm/rpc/ethdb/kv/backend_providers.hpp>
#include <silkworm/rpc/txpool/miner.hpp>
#include <silkworm/rpc/txpool/transaction_pool.hpp>

#include "mock_execution_engine.hpp"

namespace silkworm::rpc::test_util {

ServiceContextTestBase::ServiceContextTestBase()
    : ContextTestBase() {
    add_shared_service(ioc_, std::make_shared<BlockCache>());
    add_shared_service(ioc_, std::make_shared<FilterStorage>(1024));
    add_shared_service<db::kv::api::StateCache>(ioc_, std::make_shared<db::kv::api::CoherentStateCache>());
    add_shared_service<engine::ExecutionEngine>(ioc_, std::make_shared<ExecutionEngineMock>());
    auto* state_cache{must_use_shared_service<db::kv::api::StateCache>(ioc_)};
    auto grpc_channel{::grpc::CreateChannel("localhost:12345", ::grpc::InsecureChannelCredentials())};
    auto backend{std::make_unique<ethbackend::RemoteBackEnd>(grpc_channel, grpc_context_)};
    add_private_service<db::kv::api::Client>(ioc_, std::make_unique<db::kv::grpc::client::RemoteClient>(
                                                       [=]() { return grpc_channel; },
                                                       grpc_context_,
                                                       state_cache,
                                                       ethdb::kv::make_backend_providers(backend.get())));
    add_private_service<ethbackend::BackEnd>(ioc_, std::move(backend));
    add_private_service<txpool::Miner>(ioc_, std::make_unique<txpool::Miner>(grpc_channel, grpc_context_));
    add_private_service<txpool::TransactionPool>(ioc_, std::make_unique<txpool::TransactionPool>(grpc_channel, grpc_context_));
}

}  // namespace silkworm::rpc::test_util
