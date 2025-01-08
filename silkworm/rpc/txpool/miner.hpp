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
#include <utility>

#include <silkworm/infra/concurrency/task.hpp>

#include <agrpc/grpc_context.hpp>
#include <evmc/evmc.hpp>
#include <grpcpp/grpcpp.h>
#include <intx/intx.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/interfaces/txpool/mining.grpc.pb.h>
#include <silkworm/interfaces/types/types.pb.h>
#include <silkworm/rpc/common/util.hpp>

namespace silkworm::rpc::txpool {

struct WorkResult {
    evmc::bytes32 header_hash;
    evmc::bytes32 seed_hash;
    evmc::bytes32 target;
    silkworm::Bytes block_num;
};

struct MiningResult {
    bool enabled;
    bool running;
};

class Miner final {
  public:
    Miner(const std::shared_ptr<grpc::Channel>& channel, agrpc::GrpcContext& grpc_context);
    Miner(std::unique_ptr<::txpool::Mining::StubInterface> stub, agrpc::GrpcContext& grpc_context);

    Task<WorkResult> get_work();

    Task<bool> submit_work(const silkworm::Bytes& block_nonce, const evmc::bytes32& pow_hash, const evmc::bytes32& digest);

    Task<bool> submit_hash_rate(const intx::uint256& rate, const evmc::bytes32& id);

    Task<uint64_t> get_hash_rate();

    Task<MiningResult> get_mining();

  private:
    std::unique_ptr<::txpool::Mining::StubInterface> stub_;
    agrpc::GrpcContext& grpc_context_;
};

}  // namespace silkworm::rpc::txpool
