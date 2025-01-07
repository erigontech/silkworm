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

#include "miner.hpp"

#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/infra/common/clock_time.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/grpc/client/call.hpp>

namespace silkworm::rpc::txpool {

namespace proto = ::txpool;
using Stub = proto::Mining::StubInterface;

Miner::Miner(boost::asio::io_context& ioc, const std::shared_ptr<grpc::Channel>& channel, agrpc::GrpcContext& grpc_context)
    : Miner(ioc.get_executor(), ::txpool::Mining::NewStub(channel), grpc_context) {}

Miner::Miner(boost::asio::io_context::executor_type executor, std::unique_ptr<Stub> stub, agrpc::GrpcContext& grpc_context)
    : executor_(std::move(executor)), stub_(std::move(stub)), grpc_context_(grpc_context) {
    SILK_TRACE << "Miner::ctor " << this;
}

Miner::~Miner() {
    SILK_TRACE << "Miner::dtor " << this;
}

Task<WorkResult> Miner::get_work() {
    const auto start_time = clock_time::now();
    SILK_DEBUG << "Miner::get_work";
    const proto::GetWorkRequest request;
    const auto reply = co_await rpc::unary_rpc(&Stub::AsyncGetWork, *stub_, request, grpc_context_);
    const auto header_hash = bytes32_from_hex(reply.header_hash());
    const auto seed_hash = bytes32_from_hex(reply.seed_hash());
    const auto target = bytes32_from_hex(reply.target());
    const auto block_num = from_hex(reply.block_number()).value_or(Bytes{});
    WorkResult result{header_hash, seed_hash, target, block_num};
    SILK_DEBUG << "Miner::get_work header_hash=" << to_hex(header_hash) << " seed_hash=" << to_hex(seed_hash)
               << " target=" << to_hex(target) << " block_num=" << block_num << " t=" << clock_time::since(start_time);
    co_return result;
}

Task<bool> Miner::submit_work(const silkworm::Bytes& block_nonce, const evmc::bytes32& pow_hash, const evmc::bytes32& digest) {
    const auto start_time = clock_time::now();
    SILK_DEBUG << "Miner::submit_work block_nonce=" << block_nonce << " pow_hash=" << to_hex(pow_hash)
               << " digest=" << to_hex(digest);
    proto::SubmitWorkRequest request;
    request.set_block_nonce(block_nonce.data(), block_nonce.size());
    request.set_pow_hash(pow_hash.bytes, silkworm::kHashLength);
    request.set_digest(digest.bytes, silkworm::kHashLength);
    const auto reply = co_await rpc::unary_rpc(&Stub::AsyncSubmitWork, *stub_, request, grpc_context_);
    const auto ok = reply.ok();
    SILK_DEBUG << "Miner::submit_work ok=" << std::boolalpha << ok << " t=" << clock_time::since(start_time);
    co_return ok;
}

Task<bool> Miner::submit_hash_rate(const intx::uint256& rate, const evmc::bytes32& id) {
    const auto start_time = clock_time::now();
    SILK_DEBUG << "Miner::submit_hash_rate rate=" << rate << " id=" << to_hex(id);
    ::txpool::SubmitHashRateRequest request;
    request.set_rate(uint64_t{rate});
    request.set_id(id.bytes, kHashLength);
    const auto reply = co_await rpc::unary_rpc(&Stub::AsyncSubmitHashRate, *stub_, request, grpc_context_);
    const auto ok = reply.ok();
    SILK_DEBUG << "Miner::submit_hash_rate ok=" << std::boolalpha << ok << " t=" << clock_time::since(start_time);
    co_return ok;
}

Task<uint64_t> Miner::get_hash_rate() {
    const auto start_time = clock_time::now();
    SILK_DEBUG << "Miner::hash_rate";
    const proto::HashRateRequest request;
    const auto reply = co_await rpc::unary_rpc(&Stub::AsyncHashRate, *stub_, request, grpc_context_);
    const auto hash_rate = reply.hash_rate();
    SILK_DEBUG << "Miner::hash_rate hash_rate=" << hash_rate << " t=" << clock_time::since(start_time);
    co_return hash_rate;
}

Task<MiningResult> Miner::get_mining() {
    const auto start_time = clock_time::now();
    SILK_DEBUG << "Miner::get_mining";
    const proto::MiningRequest request;
    const auto reply = co_await rpc::unary_rpc(&Stub::AsyncMining, *stub_, request, grpc_context_);
    const auto enabled = reply.enabled();
    const auto running = reply.running();
    MiningResult result{enabled, running};
    SILK_DEBUG << "Miner::get_mining enabled=" << std::boolalpha << enabled << " running=" << running
               << " t=" << clock_time::since(start_time);
    co_return result;
}

}  // namespace silkworm::rpc::txpool
