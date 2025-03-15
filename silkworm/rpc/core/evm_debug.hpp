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
#include <optional>
#include <stack>
#include <string>
#include <vector>

#include <silkworm/infra/concurrency/task.hpp>

#include <evmc/hex.hpp>
#include <evmc/instructions.h>
#include <gsl/narrow>
#include <nlohmann/json.hpp>

#include <silkworm/core/common/block_cache.hpp>
#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/execution/evm.hpp>
#include <silkworm/core/state/intra_block_state.hpp>
#include <silkworm/db/kv/api/state_cache.hpp>
#include <silkworm/db/kv/api/transaction.hpp>
#include <silkworm/rpc/common/worker_pool.hpp>
#include <silkworm/rpc/json/stream.hpp>
#include <silkworm/rpc/types/block.hpp>
#include <silkworm/rpc/types/call.hpp>
#include <silkworm/rpc/types/transaction.hpp>

namespace silkworm::rpc::debug {

using namespace db::chain;

struct DebugConfig {
    bool disable_storage{false};
    bool disable_memory{false};
    bool disable_stack{false};
    bool no_refunds{false};
    std::optional<int32_t> tx_index;
};

std::string uint256_to_hex(const evmone::uint256& x);
std::string bytes_to_hex(evmc::bytes_view bv);

void from_json(const nlohmann::json& json, DebugConfig& tc);
std::ostream& operator<<(std::ostream& out, const DebugConfig& tc);

using Storage = std::map<std::string, std::string>;

struct DebugLog {
    std::uint32_t pc{0};
    unsigned char op_code{0};
    std::optional<std::string> op_name;
    std::int64_t gas{0};
    std::int64_t gas_cost{0};
    std::int32_t depth{0};
    std::string error;
    int stack_height{0};
    std::vector<std::string> memory;
    std::vector<std::string> stack;
    Storage storage;
};

class DebugTracer : public EvmTracer {
  public:
    explicit DebugTracer(json::Stream& stream, const DebugConfig& config = {})
        : stream_(stream), config_(config) {}

    DebugTracer(const DebugTracer&) = delete;
    DebugTracer& operator=(const DebugTracer&) = delete;

    void on_execution_start(evmc_revision rev, const evmc_message& msg, evmone::bytes_view code) noexcept override;
    void on_instruction_start(uint32_t pc, const intx::uint256* stack_top, int stack_height, int64_t gas,
                              const evmone::ExecutionState& execution_state,
                              const silkworm::IntraBlockState& intra_block_state) noexcept override;
    void on_execution_end(const evmc_result& result, const silkworm::IntraBlockState& intra_block_state) noexcept override;
    void on_precompiled_run(const evmc_result& result, const silkworm::IntraBlockState& intra_block_state) noexcept override;

    void flush_logs();

  private:
    void write_log(const DebugLog& log);

    json::Stream& stream_;
    const DebugConfig& config_;
    std::vector<DebugLog> logs_;
    std::map<evmc::address, Storage> storage_;
    const evmc_instruction_metrics* metrics_ = nullptr;
    std::optional<uint8_t> last_opcode_;
};

class AccountTracer : public EvmTracer {
  public:
    explicit AccountTracer(const evmc::address& address) : address_{address} {}

    AccountTracer(const AccountTracer&) = delete;
    AccountTracer& operator=(const AccountTracer&) = delete;

    void on_execution_end(const evmc_result& result, const silkworm::IntraBlockState& intra_block_state) noexcept override;

  private:
    const evmc::address& address_;
    uint64_t nonce_{0};
    intx::uint256 balance_;
    evmc::bytes32 code_hash_{kEmptyHash};
    silkworm::Bytes code_;
};

class DebugExecutor {
  public:
    explicit DebugExecutor(
        BlockCache& block_cache,
        WorkerPool& workers,
        db::kv::api::Transaction& tx,
        db::kv::api::StateCache* state_cache,
        DebugConfig config = {})
        : block_cache_(block_cache), workers_{workers}, tx_{tx}, state_cache_{state_cache}, config_{config} {}
    virtual ~DebugExecutor() = default;

    DebugExecutor(const DebugExecutor&) = delete;
    DebugExecutor& operator=(const DebugExecutor&) = delete;

    Task<void> trace_block(json::Stream& stream, const ChainStorage& storage, BlockNum block_num);
    Task<void> trace_block(json::Stream& stream, const ChainStorage& storage, const evmc::bytes32& block_hash);
    Task<void> trace_call(json::Stream& stream, const BlockNumOrHash& block_num_or_hash, const ChainStorage& storage, const Call& call, bool is_latest_block);
    Task<void> trace_transaction(json::Stream& stream, const ChainStorage& storage, const evmc::bytes32& tx_hash);
    Task<void> trace_call_many(json::Stream& stream, const ChainStorage& storage, const Bundles& bundles, const SimulationContext& context, bool is_latest_block);

  protected:
    Task<void> execute(json::Stream& stream, const ChainStorage& storage, const silkworm::Block& block, const Call& call);

  private:
    Task<void> execute(json::Stream& stream, const ChainStorage& storage, const silkworm::Block& block);

    Task<void> execute(
        json::Stream& stream,
        const ChainStorage& storage,
        BlockNum block_num,
        const silkworm::Block& block,
        const Transaction& transaction,
        int32_t index = -1,
        bool is_latest_block = false);

    Task<void> execute(
        json::Stream& stream,
        const ChainStorage& storage,
        std::shared_ptr<BlockWithHash> block_with_hash,
        const Bundles& bundles,
        int32_t transaction_index,
        bool is_latest_block = false);

    BlockCache& block_cache_;
    WorkerPool& workers_;
    db::kv::api::Transaction& tx_;
    db::kv::api::StateCache* state_cache_;
    DebugConfig config_;
};

}  // namespace silkworm::rpc::debug
