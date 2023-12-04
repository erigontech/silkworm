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
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/common/clock_time.hpp>
#include <silkworm/rpc/grpc/unary_rpc.hpp>

namespace silkworm::rpc::txpool {

Miner::Miner(boost::asio::io_context& context, const std::shared_ptr<grpc::Channel>& channel, agrpc::GrpcContext& grpc_context)
    : Miner(context.get_executor(), ::txpool::Mining::NewStub(channel), grpc_context) {}

Miner::Miner(boost::asio::io_context::executor_type executor, std::unique_ptr<::txpool::Mining::StubInterface> stub, agrpc::GrpcContext& grpc_context)
    : executor_(std::move(executor)), stub_(std::move(stub)), grpc_context_(grpc_context) {
    SILK_TRACE << "Miner::ctor " << this;
}

Miner::~Miner() {
    SILK_TRACE << "Miner::dtor " << this;
}

Task<WorkResult> Miner::get_work() {
    const auto start_time = clock_time::now();
    SILK_DEBUG << "Miner::get_work";
    UnaryRpc<&::txpool::Mining::StubInterface::AsyncGetWork> get_work_rpc{*stub_, grpc_context_};
    const auto reply = co_await get_work_rpc.finish_on(executor_, ::txpool::GetWorkRequest{});
    const auto header_hash = silkworm::bytes32_from_hex(reply.header_hash());
    SILK_DEBUG << "Miner::get_work header_hash=" << silkworm::to_hex(header_hash);
    const auto seed_hash = silkworm::bytes32_from_hex(reply.seed_hash());
    SILK_DEBUG << "Miner::get_work seed_hash=" << silkworm::to_hex(seed_hash);
    const auto target = silkworm::bytes32_from_hex(reply.target());
    SILK_DEBUG << "Miner::get_work target=" << silkworm::to_hex(target);
    const auto block_number = silkworm::from_hex(reply.block_number()).value_or(silkworm::Bytes{});
    SILK_DEBUG << "Miner::get_work block_number=" << block_number;
    WorkResult result{header_hash, seed_hash, target, block_number};
    SILK_DEBUG << "Miner::get_work t=" << clock_time::since(start_time);
    co_return result;
}

Task<bool> Miner::submit_work(const silkworm::Bytes& block_nonce, const evmc::bytes32& pow_hash, const evmc::bytes32& digest) {
    const auto start_time = clock_time::now();
    SILK_DEBUG << "Miner::submit_work block_nonce=" << block_nonce << " pow_hash=" << silkworm::to_hex(pow_hash) << " digest=" << silkworm::to_hex(digest);
    ::txpool::SubmitWorkRequest submit_work_request;
    submit_work_request.set_block_nonce(block_nonce.data(), block_nonce.size());
    submit_work_request.set_pow_hash(pow_hash.bytes, silkworm::kHashLength);
    submit_work_request.set_digest(digest.bytes, silkworm::kHashLength);
    UnaryRpc<&::txpool::Mining::StubInterface::AsyncSubmitWork> submit_work_rpc{*stub_, grpc_context_};
    const auto reply = co_await submit_work_rpc.finish_on(executor_, submit_work_request);
    const auto ok = reply.ok();
    SILK_DEBUG << "Miner::submit_work ok=" << std::boolalpha << ok << " t=" << clock_time::since(start_time);
    co_return ok;
}

Task<bool> Miner::submit_hash_rate(const intx::uint256& rate, const evmc::bytes32& id) {
    const auto start_time = clock_time::now();
    SILK_DEBUG << "Miner::submit_hash_rate rate=" << rate << " id=" << silkworm::to_hex(id);
    ::txpool::SubmitHashRateRequest submit_hash_rate_request;
    submit_hash_rate_request.set_rate(uint64_t(rate));
    submit_hash_rate_request.set_id(id.bytes, silkworm::kHashLength);
    UnaryRpc<&::txpool::Mining::StubInterface::AsyncSubmitHashRate> submit_hash_rate_rpc{*stub_, grpc_context_};
    const auto reply = co_await submit_hash_rate_rpc.finish_on(executor_, submit_hash_rate_request);
    const auto ok = reply.ok();
    SILK_DEBUG << "Miner::submit_hash_rate ok=" << std::boolalpha << ok << " t=" << clock_time::since(start_time);
    co_return ok;
}

Task<uint64_t> Miner::get_hash_rate() {
    const auto start_time = clock_time::now();
    SILK_DEBUG << "Miner::hash_rate";
    UnaryRpc<&::txpool::Mining::StubInterface::AsyncHashRate> get_hash_rate_rpc{*stub_, grpc_context_};
    const auto reply = co_await get_hash_rate_rpc.finish_on(executor_, ::txpool::HashRateRequest{});
    const auto hash_rate = reply.hash_rate();
    SILK_DEBUG << "Miner::hash_rate hash_rate=" << hash_rate << " t=" << clock_time::since(start_time);
    co_return hash_rate;
}

Task<MiningResult> Miner::get_mining() {
    const auto start_time = clock_time::now();
    SILK_DEBUG << "Miner::get_mining";
    UnaryRpc<&::txpool::Mining::StubInterface::AsyncMining> get_mining_rpc{*stub_, grpc_context_};
    const auto reply = co_await get_mining_rpc.finish_on(executor_, ::txpool::MiningRequest{});
    const auto enabled = reply.enabled();
    SILK_DEBUG << "Miner::get_mining enabled=" << std::boolalpha << enabled;
    const auto running = reply.running();
    SILK_DEBUG << "Miner::get_mining running=" << std::boolalpha << running;
    MiningResult result{enabled, running};
    SILK_DEBUG << "Miner::get_mining t=" << clock_time::since(start_time);
    co_return result;
}

}  // namespace silkworm::rpc::txpool
