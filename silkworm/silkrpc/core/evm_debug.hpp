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

#include <map>
#include <stack>
#include <string>
#include <vector>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/thread_pool.hpp>
#include <gsl/narrow>
#include <nlohmann/json.hpp>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wattributes"
#include <silkworm/core/execution/evm.hpp>
#pragma GCC diagnostic pop
#include <silkworm/core/state/intra_block_state.hpp>
#include <silkworm/silkrpc/common/block_cache.hpp>
#include <silkworm/silkrpc/core/rawdb/accessors.hpp>
#include <silkworm/silkrpc/ethdb/transaction.hpp>
#include <silkworm/silkrpc/ethdb/transaction_database.hpp>
#include <silkworm/silkrpc/json/stream.hpp>
#include <silkworm/silkrpc/types/block.hpp>
#include <silkworm/silkrpc/types/call.hpp>
#include <silkworm/silkrpc/types/transaction.hpp>

namespace silkworm::rpc::debug {

struct DebugConfig {
    bool disableStorage{false};
    bool disableMemory{false};
    bool disableStack{false};
};

void from_json(const nlohmann::json& json, DebugConfig& tc);
std::ostream& operator<<(std::ostream& out, const DebugConfig& tc);

using Storage = std::map<std::string, std::string>;

struct DebugLog {
    uint32_t pc;
    std::string op;
    int64_t gas;
    int64_t gas_cost;
    int32_t depth;
    bool error{false};
    std::vector<std::string> memory;
    std::vector<std::string> stack;
    Storage storage;
};

class DebugTracer : public silkworm::EvmTracer {
  public:
    explicit DebugTracer(json::Stream& stream, const DebugConfig& config = {})
        : stream_(stream), config_(config) {}

    DebugTracer(const DebugTracer&) = delete;
    DebugTracer& operator=(const DebugTracer&) = delete;

    void on_execution_start(evmc_revision rev, const evmc_message& msg, evmone::bytes_view code) noexcept override;

    void on_instruction_start(uint32_t pc, const intx::uint256* stack_top, int stack_height, int64_t gas,
                              const evmone::ExecutionState& execution_state, const silkworm::IntraBlockState& intra_block_state) noexcept override;
    void on_execution_end(const evmc_result& result, const silkworm::IntraBlockState& intra_block_state) noexcept override;
    void on_precompiled_run(const evmc_result& result, int64_t gas, const silkworm::IntraBlockState& intra_block_state) noexcept override;
    void on_reward_granted(const silkworm::CallResult& /*result*/, const silkworm::IntraBlockState& /*intra_block_state*/) noexcept override {}
    void on_creation_completed(const evmc_result& /*result*/, const silkworm::IntraBlockState& /*intra_block_state*/) noexcept override {}

    void flush_logs();

  private:
    void write_log(const DebugLog& log);

    json::Stream& stream_;
    const DebugConfig& config_;
    std::vector<DebugLog> logs_;
    std::map<evmc::address, Storage> storage_;
    const char* const* opcode_names_ = nullptr;
    std::int64_t start_gas_{0};
    std::int64_t gas_on_precompiled_{0};
};

class DebugExecutor {
  public:
    explicit DebugExecutor(
        const core::rawdb::DatabaseReader& database_reader,
        BlockCache& block_cache,
        boost::asio::thread_pool& workers,
        ethdb::Transaction& tx,
        DebugConfig config = {})
        : database_reader_(database_reader), block_cache_(block_cache), workers_{workers}, tx_{tx}, config_{config} {}
    virtual ~DebugExecutor() = default;

    DebugExecutor(const DebugExecutor&) = delete;
    DebugExecutor& operator=(const DebugExecutor&) = delete;

    boost::asio::awaitable<void> trace_block(json::Stream& stream, std::uint64_t block_number);
    boost::asio::awaitable<void> trace_block(json::Stream& stream, const evmc::bytes32& block_hash);
    boost::asio::awaitable<void> trace_call(json::Stream& stream, const BlockNumberOrHash& bnoh, const Call& call);
    boost::asio::awaitable<void> trace_transaction(json::Stream& stream, const evmc::bytes32& tx_hash);
    boost::asio::awaitable<void> trace_call_many(json::Stream& stream, const Bundles& bundles, const SimulationContext& context);

    boost::asio::awaitable<void> execute(json::Stream& stream, const silkworm::Block& block, const Call& call);

  private:
    boost::asio::awaitable<void> execute(json::Stream& stream, const silkworm::Block& block);
    boost::asio::awaitable<void> execute(json::Stream& stream, std::uint64_t block_number,
                                         const silkworm::Block& block, const Transaction& transaction, int32_t = -1);

    boost::asio::awaitable<void> execute(json::Stream& stream,
                                         const silkworm::BlockWithHash& block_with_hash,
                                         const Bundles& bundles,
                                         int32_t transaction_index);

    const core::rawdb::DatabaseReader& database_reader_;
    BlockCache& block_cache_;
    boost::asio::thread_pool& workers_;
    ethdb::Transaction& tx_;
    DebugConfig config_;
};
}  // namespace silkworm::rpc::debug
