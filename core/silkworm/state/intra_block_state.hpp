/*
   Copyright 2020-2021 The Silkworm Authors

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

#ifndef SILKWORM_STATE_INTRA_BLOCK_STATE_HPP_
#define SILKWORM_STATE_INTRA_BLOCK_STATE_HPP_

#include <memory>
#include <vector>

#include <intx/intx.hpp>

#include <silkworm/common/base.hpp>
#include <silkworm/common/hash_maps.hpp>
#include <silkworm/state/buffer.hpp>
#include <silkworm/state/delta.hpp>
#include <silkworm/state/object.hpp>
#include <silkworm/types/log.hpp>

namespace silkworm {

class IntraBlockState {
  public:
    class Snapshot {
      public:
        Snapshot(Snapshot&&) = default;
        Snapshot& operator=(Snapshot&&) = default;

      private:
        friend class IntraBlockState;

        Snapshot() = default;

        size_t journal_size_{0};
        size_t log_size_{0};
        uint64_t refund_{0};
    };

    IntraBlockState(const IntraBlockState&) = delete;
    IntraBlockState& operator=(const IntraBlockState&) = delete;

    explicit IntraBlockState(StateBuffer& db) noexcept : db_{db} {}

    StateBuffer& db() { return db_; }

    bool exists(const evmc::address& address) const noexcept;

    // https://eips.ethereum.org/EIPS/eip-161
    bool is_dead(const evmc::address& address) const noexcept;

    void create_contract(const evmc::address& address) noexcept;

    void destruct(const evmc::address& address);

    void record_suicide(const evmc::address& address) noexcept;
    void destruct_suicides();
    void destruct_touched_dead();

    size_t number_of_self_destructs() const noexcept { return self_destructs_.size(); }

    intx::uint256 get_balance(const evmc::address& address) const noexcept;
    void set_balance(const evmc::address& address, const intx::uint256& value) noexcept;
    void add_to_balance(const evmc::address& address, const intx::uint256& addend) noexcept;
    void subtract_from_balance(const evmc::address& address, const intx::uint256& subtrahend) noexcept;

    void touch(const evmc::address& address) noexcept;

    uint64_t get_nonce(const evmc::address& address) const noexcept;
    void set_nonce(const evmc::address& address, uint64_t nonce) noexcept;

    ByteView get_code(const evmc::address& address) const noexcept;
    evmc::bytes32 get_code_hash(const evmc::address& address) const noexcept;
    void set_code(const evmc::address& address, Bytes code) noexcept;

    evmc_access_status access_account(const evmc::address& address) noexcept;

    evmc_access_status access_storage(const evmc::address& address, const evmc::bytes32& key) noexcept;

    evmc::bytes32 get_current_storage(const evmc::address& address, const evmc::bytes32& key) const noexcept;

    // https://eips.ethereum.org/EIPS/eip-2200
    evmc::bytes32 get_original_storage(const evmc::address& address, const evmc::bytes32& key) const noexcept;

    void set_storage(const evmc::address& address, const evmc::bytes32& key, const evmc::bytes32& value) noexcept;

    void write_to_db(uint64_t block_number);

    Snapshot take_snapshot() const noexcept;
    void revert_to_snapshot(const Snapshot& snapshot) noexcept;

    void finalize_transaction();

    // See Section 6.1 "Substate" of the Yellow Paper
    void clear_journal_and_substate();

    void add_log(const Log& log) noexcept;

    const std::vector<Log>& logs() const noexcept { return logs_; }

    void add_refund(uint64_t addend) noexcept;
    void subtract_refund(uint64_t subtrahend) noexcept;

    uint64_t get_refund() const noexcept { return refund_; }

  private:
    friend class state::CreateDelta;
    friend class state::UpdateDelta;
    friend class state::SuicideDelta;
    friend class state::TouchDelta;
    friend class state::StorageChangeDelta;
    friend class state::StorageWipeDelta;
    friend class state::StorageCreateDelta;
    friend class state::StorageAccessDelta;
    friend class state::AccountAccessDelta;

    evmc::bytes32 get_storage(const evmc::address& address, const evmc::bytes32& key, bool original) const noexcept;

    state::Object* get_object(const evmc::address& address) const noexcept;
    state::Object& get_or_create_object(const evmc::address& address) noexcept;

    StateBuffer& db_;

    mutable FlatHashMap<evmc::address, state::Object> objects_;
    mutable FlatHashMap<evmc::address, state::Storage> storage_;

    // we want pointer stability here, thus node map
    mutable NodeHashMap<evmc::bytes32, Bytes> code_;

    std::vector<std::unique_ptr<state::Delta>> journal_;

    // substate
    FlatHashSet<evmc::address> self_destructs_;
    std::vector<Log> logs_;
    FlatHashSet<evmc::address> touched_;
    uint64_t refund_{0};
    // EIP-2929 substate
    FlatHashSet<evmc::address> accessed_addresses_;
    FlatHashMap<evmc::address, FlatHashSet<evmc::bytes32>> accessed_storage_keys_;
};

}  // namespace silkworm

#endif  // SILKWORM_STATE_INTRA_BLOCK_STATE_HPP_
