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

#include <silkworm/core/state/block_state.hpp>
#include <silkworm/core/types/account.hpp>
#include <silkworm/core/types/call_traces.hpp>
#include <silkworm/core/types/receipt.hpp>

namespace silkworm {

class State : public BlockState {
  public:
    State() = default;

    // Move-only
    State(State&& other) = default;
    State& operator=(State&& other) = default;

    ~State() override = default;

    /** @name Readers */
    //!@{

    virtual std::optional<Account> read_account(const evmc::address& address) const noexcept = 0;

    virtual ByteView read_code(const evmc::address& address, const evmc::bytes32& code_hash) const noexcept = 0;

    virtual evmc::bytes32 read_storage(
        const evmc::address& address,
        uint64_t incarnation,
        const evmc::bytes32& location) const noexcept = 0;

    /** Previous non-zero incarnation of an account; 0 if none exists. */
    virtual uint64_t previous_incarnation(const evmc::address& address) const noexcept = 0;

    virtual evmc::bytes32 state_root_hash() const = 0;

    virtual BlockNum current_canonical_block() const = 0;

    virtual std::optional<evmc::bytes32> canonical_hash(BlockNum block_num) const = 0;

    //!@}

    virtual void insert_block(const Block& block, const evmc::bytes32& hash) = 0;

    virtual void canonize_block(BlockNum block_num, const evmc::bytes32& block_hash) = 0;

    virtual void decanonize_block(BlockNum block_num) = 0;

    virtual void insert_receipts(BlockNum block_num, const std::vector<Receipt>& receipts) = 0;

    virtual void insert_call_traces(BlockNum block_num, const CallTraces& traces) = 0;

    /** @name State changes
     *  Change sets are backward changes of the state, i.e. account/storage values <em>at the beginning of a block</em>.
     */
    //!@{

    /** Mark the beginning of a new block.
     * Must be called prior to calling update_account/update_account_code/update_storage.
     */
    virtual void begin_block(BlockNum block_num, size_t updated_accounts_count) = 0;

    virtual void update_account(const evmc::address& address, std::optional<Account> initial,
                                std::optional<Account> current) = 0;

    virtual void update_account_code(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& code_hash,
                                     ByteView code) = 0;

    virtual void update_storage(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& location,
                                const evmc::bytes32& initial, const evmc::bytes32& current) = 0;

    virtual void unwind_state_changes(BlockNum block_num) = 0;

    //!@}
};

}  // namespace silkworm
