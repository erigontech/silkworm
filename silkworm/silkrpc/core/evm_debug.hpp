/*
   Copyright 2021 The Silkrpc Authors

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
#include <nlohmann/json.hpp>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wattributes"
#include <silkworm/core/execution/evm.hpp>
#pragma GCC diagnostic pop
#include <silkworm/core/state/intra_block_state.hpp>

#include <silkworm/silkrpc/concurrency/context_pool.hpp>
#include <silkworm/silkrpc/core/rawdb/accessors.hpp>
#include <silkworm/silkrpc/json/stream.hpp>
#include <silkworm/silkrpc/types/block.hpp>
#include <silkworm/silkrpc/types/call.hpp>
#include <silkworm/silkrpc/types/transaction.hpp>

namespace silkrpc::debug {

struct DebugConfig {
    bool disableStorage{false};
    bool disableMemory{false};
    bool disableStack{false};
};

static const DebugConfig DEFAULT_DEBUG_CONFIG{false, false, false};

void from_json(const nlohmann::json& json, DebugConfig& tc);
std::ostream& operator<<(std::ostream& out, const DebugConfig& tc);

using Storage = std::map<std::string, std::string>;

struct DebugLog {
    std::uint32_t pc;
    std::string op;
    std::int64_t gas;
    std::int64_t gas_cost;
    std::uint32_t depth;
    bool error{false};
    std::vector<std::string> memory;
    std::vector<std::string> stack;
    Storage storage;
};

class DebugTracer : public silkworm::EvmTracer {
public:
    explicit DebugTracer(std::vector<DebugLog>& logs, const DebugConfig& config = {}, json::Stream* stream = nullptr)
        : logs_(logs), config_(config), stream_(stream) {}

    DebugTracer(const DebugTracer&) = delete;
    DebugTracer& operator=(const DebugTracer&) = delete;

    void on_execution_start(evmc_revision rev, const evmc_message& msg, evmone::bytes_view code) noexcept override;

    void on_instruction_start(uint32_t pc , const intx::uint256 *stack_top, const int stack_height,
        const evmone::ExecutionState& execution_state, const silkworm::IntraBlockState& intra_block_state) noexcept override;
    void on_execution_end(const evmc_result& result, const silkworm::IntraBlockState& intra_block_state) noexcept override;
    void on_precompiled_run(const evmc_result& result, int64_t gas, const silkworm::IntraBlockState& intra_block_state) noexcept override;
    void on_reward_granted(const silkworm::CallResult& result, const silkworm::IntraBlockState& intra_block_state) noexcept override {};
    void on_creation_completed(const evmc_result& result, const silkworm::IntraBlockState& intra_block_state) noexcept override {};

    void flush_logs();

private:
    void write_log(const DebugLog& log);

    std::vector<DebugLog>& logs_;
    const DebugConfig& config_;
    json::Stream* stream_ = nullptr;
    std::map<evmc::address, Storage> storage_;
    const char* const* opcode_names_ = nullptr;
    std::int64_t start_gas_{0};
    std::int64_t gas_on_precompiled_{0};
};

class NullTracer : public silkworm::EvmTracer {
public:
    NullTracer() {}

    NullTracer(const NullTracer&) = delete;
    NullTracer& operator=(const NullTracer&) = delete;

    void on_execution_start(evmc_revision rev, const evmc_message& msg, evmone::bytes_view code) noexcept override {};
    void on_instruction_start(uint32_t pc, const intx::uint256* stack_top, const int stack_size,
         const evmone::ExecutionState& execution_state, const silkworm::IntraBlockState& intra_block_state) noexcept override {};
    void on_execution_end(const evmc_result& result, const silkworm::IntraBlockState& intra_block_state) noexcept override {};
    void on_precompiled_run(const evmc_result& result, int64_t gas, const silkworm::IntraBlockState& intra_block_state) noexcept override {};
    void on_reward_granted(const silkworm::CallResult& result, const silkworm::IntraBlockState& intra_block_state) noexcept override {};
    void on_creation_completed(const evmc_result& result, const silkworm::IntraBlockState& intra_block_state) noexcept override {};

    std::int64_t get_end_gas() const {return 0;}
};

struct DebugTrace {
    bool failed;
    std::int64_t gas{0};
    std::string return_value;
    std::vector<DebugLog> debug_logs;

    DebugConfig debug_config;
};

void to_json(nlohmann::json& json, const DebugTrace& debug_trace);

struct DebugExecutorResult {
    DebugTrace debug_trace;
    std::optional<std::string> pre_check_error{std::nullopt};
};

template<typename WorldState = silkworm::IntraBlockState, typename VM = silkworm::EVM>
class DebugExecutor {
public:
    explicit DebugExecutor(
        boost::asio::io_context& io_context,
        const core::rawdb::DatabaseReader& database_reader,
        boost::asio::thread_pool& workers,
        const DebugConfig& config = DEFAULT_DEBUG_CONFIG)
        : io_context_(io_context), database_reader_(database_reader), workers_{workers}, config_{config} {}
    virtual ~DebugExecutor() {}

    DebugExecutor(const DebugExecutor&) = delete;
    DebugExecutor& operator=(const DebugExecutor&) = delete;

    boost::asio::awaitable<std::vector<DebugTrace>> execute(const silkworm::Block& block, json::Stream* stream = nullptr);
    boost::asio::awaitable<DebugExecutorResult> execute(const silkworm::Block& block, const silkrpc::Call& call, json::Stream* stream = nullptr);
    boost::asio::awaitable<DebugExecutorResult> execute(const silkworm::Block& block, const silkrpc::Transaction& transaction,
            json::Stream* stream = nullptr) {
        return execute(block.header.number-1, block, transaction, transaction.transaction_index, stream);
    }

private:
    boost::asio::awaitable<DebugExecutorResult> execute(std::uint64_t block_number, const silkworm::Block& block,
        const silkrpc::Transaction& transaction, std::int32_t = -1, json::Stream* stream = nullptr);

    boost::asio::io_context& io_context_;
    const core::rawdb::DatabaseReader& database_reader_;
    boost::asio::thread_pool& workers_;
    const DebugConfig& config_;
};
} // namespace silkrpc::debug

