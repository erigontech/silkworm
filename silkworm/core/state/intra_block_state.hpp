// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>
#include <vector>

#include <intx/intx.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/common/hash_maps.hpp>
#include <silkworm/core/state/delta.hpp>
#include <silkworm/core/state/object.hpp>
#include <silkworm/core/state/state.hpp>
#include <silkworm/core/types/log.hpp>

namespace silkworm {

class IntraBlockState {
  public:
    class Snapshot {
      public:
        // Only movable
        Snapshot(Snapshot&&) = default;
        Snapshot& operator=(Snapshot&&) = default;

      private:
        friend class IntraBlockState;

        Snapshot() = default;

        size_t journal_size_{0};
        size_t log_size_{0};
    };

    // Not copyable nor movable
    IntraBlockState(const IntraBlockState&) = delete;
    IntraBlockState& operator=(const IntraBlockState&) = delete;

    explicit IntraBlockState(State& db) noexcept : db_{db} {}

    State& db() { return db_; }

    bool exists(const evmc::address& address) const noexcept;

    // See EIP-161: State trie clearing (invariant-preserving alternative)
    bool is_dead(const evmc::address& address) const noexcept;

    void create_contract(const evmc::address& address, bool is_code_delegation) noexcept;

    void destruct(const evmc::address& address);

    bool record_suicide(const evmc::address& address) noexcept;
    void destruct_suicides();
    void destruct_touched_dead();

    size_t number_of_self_destructs() const noexcept { return self_destructs_.size(); }
    bool is_self_destructed(const evmc::address& address) const noexcept;

    intx::uint256 get_balance(const evmc::address& address) const noexcept;
    void set_balance(const evmc::address& address, const intx::uint256& value) noexcept;
    void add_to_balance(const evmc::address& address, const intx::uint256& addend) noexcept;
    void subtract_from_balance(const evmc::address& address, const intx::uint256& subtrahend) noexcept;

    void touch(const evmc::address& address) noexcept;

    uint64_t get_nonce(const evmc::address& address) const noexcept;
    void set_nonce(const evmc::address& address, uint64_t nonce) noexcept;

    ByteView get_code(const evmc::address& address) const noexcept;
    evmc::bytes32 get_code_hash(const evmc::address& address) const noexcept;
    void set_code(const evmc::address& address, ByteView code) noexcept;

    evmc_access_status access_account(const evmc::address& address) noexcept;

    evmc_access_status access_storage(const evmc::address& address, const evmc::bytes32& key) noexcept;

    evmc::bytes32 get_current_storage(const evmc::address& address, const evmc::bytes32& key) const noexcept;

    // https://eips.ethereum.org/EIPS/eip-2200
    evmc::bytes32 get_original_storage(const evmc::address& address, const evmc::bytes32& key) const noexcept;

    void set_storage(const evmc::address& address, const evmc::bytes32& key, const evmc::bytes32& value) noexcept;

    void write_to_db(uint64_t block_num);

    Snapshot take_snapshot() const noexcept;
    void revert_to_snapshot(const Snapshot& snapshot) noexcept;

    void finalize_transaction(evmc_revision rev);

    // See Section 6.1 "Substate" of the Yellow Paper
    void clear_journal_and_substate();

    void add_log(const Log& log) noexcept;

    std::vector<Log>& logs() noexcept { return logs_; }
    const std::vector<Log>& logs() const noexcept { return logs_; }

    const FlatHashSet<evmc::address>& touched() const noexcept { return touched_; }

    const FlatHashSet<evmc::address>& created() const noexcept { return created_; }

    evmc::bytes32 get_transient_storage(const evmc::address& address, const evmc::bytes32& key);

    void set_transient_storage(const evmc::address& addr, const evmc::bytes32& key, const evmc::bytes32& value);

  private:
    friend class state::CreateDelta;
    friend class state::UpdateDelta;
    friend class state::UpdateBalanceDelta;
    friend class state::SuicideDelta;
    friend class state::TouchDelta;
    friend class state::StorageChangeDelta;
    friend class state::StorageWipeDelta;
    friend class state::StorageCreateDelta;
    friend class state::StorageAccessDelta;
    friend class state::AccountAccessDelta;
    friend class state::TransientStorageChangeDelta;
    friend class StateView;
    friend class ExecutionProcessor;

    evmc::bytes32 get_storage(const evmc::address& address, const evmc::bytes32& key, bool original) const noexcept;

    const state::Object* get_object(const evmc::address& address) const noexcept;
    state::Object* get_object(const evmc::address& address) noexcept;

    state::Object& get_or_create_object(const evmc::address& address) noexcept;

    State& db_;

    mutable FlatHashMap<evmc::address, state::Object> objects_;
    mutable FlatHashMap<evmc::address, state::Storage> storage_;

    mutable FlatHashMap<evmc::bytes32, ByteView> existing_code_;
    FlatHashMap<evmc::bytes32, std::vector<uint8_t>> new_code_;
    // EIP- 7702
    FlatHashSet<evmc::address> delegated_designations_;

    std::vector<std::unique_ptr<state::Delta>> journal_;

    // substate
    FlatHashSet<evmc::address> self_destructs_;
    std::vector<Log> logs_;
    FlatHashSet<evmc::address> touched_;
    FlatHashSet<evmc::address> created_;  // required for EIP-6780
    // EIP-2929 substate
    FlatHashSet<evmc::address> accessed_addresses_;
    FlatHashMap<evmc::address, FlatHashSet<evmc::bytes32>> accessed_storage_keys_;

    FlatHashMap<evmc::address, FlatHashMap<evmc::bytes32, evmc::bytes32>> transient_storage_;
};

}  // namespace silkworm
