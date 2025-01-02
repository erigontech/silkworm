/*
   Copyright 2022 The Silkworm Authors

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

#include "execution.hpp"

#include <catch2/catch_test_macros.hpp>
#include <ethash/keccak.hpp>

#include <silkworm/core/common/test_util.hpp>
#include <silkworm/core/execution/call_tracer.hpp>
#include <silkworm/core/protocol/param.hpp>
#include <silkworm/core/state/in_memory_state.hpp>
#include <silkworm/core/trie/vector_root.hpp>
#include <silkworm/core/types/account.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>

namespace silkworm {

static constexpr evmc::address kMiner{0x5a0b54d5dc17e0aadc383d2db43b0a0d3e029c4c_address};
static constexpr evmc::address kSender{0xb685342b8c54347aad148e1f22eff3eb3eb29391_address};

TEST_CASE("Execute two blocks") {
    // ---------------------------------------
    // Prepare
    // ---------------------------------------
    Block block{};
    block.header.number = 1;
    block.header.beneficiary = kMiner;
    block.header.gas_limit = 100'000;
    block.header.gas_used = 98'824;

    static constexpr auto kEncoder = [](Bytes& to, const Receipt& r) { rlp::encode(to, r); };
    std::vector<Receipt> receipts{
        {TransactionType::kDynamicFee, true, block.header.gas_used, {}, {}},
    };
    block.header.receipts_root = trie::root_hash(receipts, kEncoder);

    // This contract initially sets its 0th storage to 0x2a and its 1st storage to 0x01c9.
    // When called, it updates its 0th storage to the input provided.
    Bytes contract_code{*from_hex("600035600055")};
    Bytes deployment_code{*from_hex("602a6000556101c960015560068060166000396000f3") + contract_code};

    block.transactions.resize(1);
    block.transactions[0].data = deployment_code;
    block.transactions[0].gas_limit = block.header.gas_limit;
    block.transactions[0].type = TransactionType::kDynamicFee;
    block.transactions[0].max_priority_fee_per_gas = 0;
    block.transactions[0].max_fee_per_gas = 20 * kGiga;

    block.transactions[0].r = 1;  // dummy
    block.transactions[0].s = 1;  // dummy
    block.transactions[0].set_sender(kSender);

    InMemoryState state;
    Account sender_account{};
    sender_account.balance = kEther;
    state.update_account(kSender, std::nullopt, sender_account);

    // ---------------------------------------
    // Execute first block
    // ---------------------------------------
    REQUIRE(execute_block(block, state, test::kLondonConfig) == ValidationResult::kOk);

    auto contract_address{create_address(kSender, /*nonce=*/0)};
    std::optional<Account> contract_account{state.read_account(contract_address)};
    REQUIRE(contract_account != std::nullopt);

    ethash::hash256 code_hash{keccak256(contract_code)};
    CHECK(to_hex(contract_account->code_hash) == to_hex(code_hash.bytes));

    evmc::bytes32 storage_key0{};
    evmc::bytes32 storage0{state.read_storage(contract_address, kDefaultIncarnation, storage_key0)};
    CHECK(to_hex(storage0) == "000000000000000000000000000000000000000000000000000000000000002a");

    evmc::bytes32 storage_key1{to_bytes32(*from_hex("01"))};
    evmc::bytes32 storage1{state.read_storage(contract_address, kDefaultIncarnation, storage_key1)};
    CHECK(to_hex(storage1) == "00000000000000000000000000000000000000000000000000000000000001c9");

    std::optional<Account> miner_account{state.read_account(kMiner)};
    REQUIRE(miner_account);
    CHECK(miner_account->balance == protocol::kBlockRewardConstantinople);

    // ---------------------------------------
    // Execute second block
    // ---------------------------------------
    std::string new_val{"000000000000000000000000000000000000000000000000000000000000003e"};

    block.header.number = 2;
    block.header.gas_used = 26'149;
    receipts[0].cumulative_gas_used = block.header.gas_used;
    block.header.receipts_root = trie::root_hash(receipts, kEncoder);

    block.transactions[0].nonce = 1;
    block.transactions[0].to = contract_address;
    block.transactions[0].data = *from_hex(new_val);
    block.transactions[0].max_priority_fee_per_gas = 20 * kGiga;

    REQUIRE(execute_block(block, state, test::kLondonConfig) == ValidationResult::kOk);

    storage0 = state.read_storage(contract_address, kDefaultIncarnation, storage_key0);
    CHECK(to_hex(storage0) == new_val);

    miner_account = state.read_account(kMiner);
    REQUIRE(miner_account != std::nullopt);
    CHECK(miner_account->balance > 2 * protocol::kBlockRewardConstantinople);
    CHECK(miner_account->balance < 3 * protocol::kBlockRewardConstantinople);
}

class BlockTracer : public EvmTracer {
  public:
    explicit BlockTracer() = default;

    void on_block_start(const silkworm::Block& /*block*/) noexcept override {
        block_start_called_ = true;
    }
    void on_block_end(const silkworm::Block& /*block*/) noexcept override {
        block_end_called_ = true;
    }

    bool block_start_called() const { return block_start_called_; }
    bool block_end_called() const { return block_end_called_; }

  private:
    bool block_start_called_{false};
    bool block_end_called_{false};
};

TEST_CASE("Execute block with tracing") {
    // ---------------------------------------
    // Prepare
    // ---------------------------------------
    Block block{};
    block.header.number = 1;
    block.header.beneficiary = kMiner;
    block.header.gas_limit = 100'000;
    block.header.gas_used = 0;

    static constexpr auto kEncoder = [](Bytes& to, const Receipt& r) { rlp::encode(to, r); };
    block.header.receipts_root = trie::root_hash(std::vector<Receipt>{}, kEncoder);

    InMemoryState state;
    Account sender_account{};
    sender_account.balance = kEther;
    state.update_account(kSender, std::nullopt, sender_account);

    // ---------------------------------------
    // Execute block
    // ---------------------------------------
    const auto chain_config{test::kLondonConfig};
    std::vector<Receipt> receipts;
    const auto rule_set{protocol::rule_set_factory(chain_config)};
    REQUIRE(rule_set);
    ExecutionProcessor processor{block, *rule_set, state, chain_config, true};

    BlockTracer block_tracer{};
    processor.evm().add_tracer(block_tracer);
    CallTraces call_traces{};
    CallTracer call_tracer{call_traces};
    processor.evm().add_tracer(call_tracer);

    REQUIRE(processor.execute_block(receipts) == ValidationResult::kOk);

    CHECK((block_tracer.block_start_called() && block_tracer.block_end_called()));
    CHECK(call_traces.senders.empty());
    CHECK(call_traces.recipients.size() == 1);
    CHECK(call_traces.recipients.contains(kMiner));  // header beneficiary
}

}  // namespace silkworm
