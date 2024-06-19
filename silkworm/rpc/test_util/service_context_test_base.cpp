/*
   Copyright 2024 The Silkworm Authors

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

#include "service_context_test_base.hpp"

#include <memory>

#include <silkworm/core/common/block_cache.hpp>
#include <silkworm/infra/concurrency/private_service.hpp>
#include <silkworm/infra/concurrency/shared_service.hpp>
#include <silkworm/rpc/core/filter_storage.hpp>
#include <silkworm/rpc/ethbackend/remote_backend.hpp>
#include <silkworm/rpc/ethdb/kv/remote_database.hpp>
#include <silkworm/rpc/ethdb/kv/state_cache.hpp>
#include <silkworm/rpc/txpool/miner.hpp>
#include <silkworm/rpc/txpool/transaction_pool.hpp>

#include "mock_execution_engine.hpp"

namespace silkworm::rpc::test_util {

ServiceContextTestBase::ServiceContextTestBase()
    : ContextTestBase() {
    add_shared_service(io_context_, std::make_shared<BlockCache>());
    add_shared_service(io_context_, std::make_shared<FilterStorage>(1024));
    add_shared_service<ethdb::kv::StateCache>(io_context_, std::make_shared<ethdb::kv::CoherentStateCache>());
    add_shared_service<engine::ExecutionEngine>(io_context_, std::make_shared<ExecutionEngineMock>());
    auto* state_cache{must_use_shared_service<ethdb::kv::StateCache>(io_context_)};
    auto grpc_channel{::grpc::CreateChannel("localhost:12345", ::grpc::InsecureChannelCredentials())};
    auto backend{std::make_unique<ethbackend::RemoteBackEnd>(io_context_, grpc_channel, grpc_context_)};
    add_private_service<ethdb::Database>(io_context_, std::make_unique<ethdb::kv::RemoteDatabase>(backend.get(), state_cache, grpc_context_, grpc_channel));
    add_private_service<ethbackend::BackEnd>(io_context_, std::move(backend));
    add_private_service<txpool::Miner>(io_context_, std::make_unique<txpool::Miner>(io_context_, grpc_channel, grpc_context_));
    add_private_service<txpool::TransactionPool>(io_context_, std::make_unique<txpool::TransactionPool>(io_context_, grpc_channel, grpc_context_));
}

}  // namespace silkworm::rpc::test_util
