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

#pragma once

#include <map>
#include <vector>

#include <silkworm/core/common/hash_maps.hpp>
#include <silkworm/core/state/state.hpp>

namespace silkworm {

//! InMemoryState holds the entire state in memory.
class InMemoryState : public State {
  public:
    // address -> initial value
    using AccountChanges = FlatHashMap<evmc::address, std::optional<Account>>;

    // address -> incarnation -> location -> initial value
    using StorageChanges = FlatHashMap<evmc::address, FlatHashMap<uint64_t, FlatHashMap<evmc::bytes32, evmc::bytes32>>>;

    // address -> incarnation -> location -> value
    using Storage = FlatHashMap<evmc::address, FlatHashMap<uint64_t, FlatHashMap<evmc::bytes32, evmc::bytes32>>>;

    std::optional<Account> read_account(const evmc::address& address) const noexcept override;

    ByteView read_code(const evmc::address& address, const evmc::bytes32& code_hash) const noexcept override;

    evmc::bytes32 read_storage(const evmc::address& address, uint64_t incarnation,
                               const evmc::bytes32& location) const noexcept override;

    uint64_t previous_incarnation(const evmc::address& address) const noexcept override;

    std::optional<BlockHeader> read_header(BlockNum block_num,
                                           const evmc::bytes32& block_hash) const noexcept override;

    [[nodiscard]] bool read_body(BlockNum block_num, const evmc::bytes32& block_hash,
                                 BlockBody& out) const noexcept override;

    std::optional<intx::uint256> total_difficulty(BlockNum block_num,
                                                  const evmc::bytes32& block_hash) const noexcept override;

    evmc::bytes32 state_root_hash() const override;

    BlockNum current_canonical_block() const override;

    std::optional<evmc::bytes32> canonical_hash(BlockNum block_num) const override;

    void insert_block(const Block& block, const evmc::bytes32& hash) override;

    void canonize_block(BlockNum block_num, const evmc::bytes32& block_hash) override;

    void decanonize_block(BlockNum block_num) override;

    void insert_receipts(BlockNum block_num, const std::vector<Receipt>& receipts) override;

    void insert_call_traces(BlockNum block_num, const CallTraces& traces) override;

    void begin_block(BlockNum block_num, size_t updated_accounts_count) override;

    void update_account(const evmc::address& address, std::optional<Account> initial,
                        std::optional<Account> current) override;

    void update_account_code(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& code_hash,
                             ByteView code) override;

    void update_storage(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& location,
                        const evmc::bytes32& initial, const evmc::bytes32& current) override;

    void unwind_state_changes(BlockNum block_num) override;

    const FlatHashMap<BlockNum, AccountChanges>& account_changes() const { return account_changes_; }
    const FlatHashMap<evmc::address, Account>& accounts() const { return accounts_; }

    size_t storage_size(const evmc::address& address, uint64_t incarnation) const;
    const Storage& storage() const { return storage_; }

  private:
    evmc::bytes32 account_storage_root(const evmc::address& address, uint64_t incarnation) const;

    FlatHashMap<evmc::address, Account> accounts_;

    // hash -> code
    FlatHashMap<evmc::bytes32, Bytes> code_;

    FlatHashMap<evmc::address, uint64_t> prev_incarnations_;

    Storage storage_;

    // block number -> hash -> header
    std::map<BlockNum, FlatHashMap<evmc::bytes32, BlockHeader>> headers_;

    // block number -> hash -> body
    std::map<BlockNum, FlatHashMap<evmc::bytes32, BlockBody>> bodies_;

    // block number -> hash -> total difficulty
    std::map<BlockNum, FlatHashMap<evmc::bytes32, intx::uint256>> difficulty_;

    std::map<BlockNum, evmc::bytes32> canonical_hashes_;

    FlatHashMap<BlockNum, AccountChanges> account_changes_;  // per block
    FlatHashMap<BlockNum, StorageChanges> storage_changes_;  // per block

    BlockNum block_num_{0};
};

}  // namespace silkworm
