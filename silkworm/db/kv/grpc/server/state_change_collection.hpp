// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>

#include <evmc/evmc.hpp>
#include <gsl/pointers>

#include <silkworm/core/common/util.hpp>
#include <silkworm/interfaces/remote/kv.pb.h>

namespace silkworm {

using StateChangeConsumer = std::function<void(std::optional<remote::StateChangeBatch>)>;

struct StateChangeFilter {
    bool with_storage{false};
    bool with_transactions{false};
};

using StateChangeToken = uint32_t;

class StateChangeSource {
  public:
    virtual ~StateChangeSource() = default;

    virtual StateChangeToken last_token() const noexcept = 0;

    virtual std::optional<StateChangeToken> subscribe(StateChangeConsumer consumer, StateChangeFilter filter) = 0;

    virtual bool unsubscribe(StateChangeToken token) = 0;
};

class StateChangeCollection : public StateChangeSource {
  public:
    explicit StateChangeCollection() = default;

    uint64_t tx_id() const { return tx_id_; }

    StateChangeToken last_token() const noexcept override { return next_token_ - 1; }

    std::optional<StateChangeToken> subscribe(StateChangeConsumer consumer, StateChangeFilter filter) override;

    bool unsubscribe(StateChangeToken token) override;

    void reset(uint64_t tx_id);

    void start_new_batch(BlockNum block_num, const evmc::bytes32& block_hash, const std::vector<Bytes>&& tx_rlps, bool unwind);

    void change_account(const evmc::address& address, uint64_t incarnation, const Bytes& data);

    void change_code(const evmc::address& address, uint64_t incarnation, const Bytes& code);

    void change_storage(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& location, const Bytes& data);

    void delete_account(const evmc::address& address);

    void notify_batch(uint64_t pending_base_fee, uint64_t gas_limit);

    void close();

  protected:
    //! The token number for the next subscription.
    StateChangeToken next_token_{0};

  private:
    //! The database transaction ID associated with the state changes.
    uint64_t tx_id_{0};

    //! The current batch of state changes.
    remote::StateChangeBatch state_changes_;

    //! The latest state change in the batch.
    remote::StateChange* latest_change_{nullptr};

    //! The mapping between accounts and their change indexes.
    std::map<evmc::address, size_t> account_change_index_;

    //! The mapping between account storage locations and their change indexes.
    std::map<evmc::address, std::map<evmc::bytes32, size_t>> storage_change_index_;

    //! The registered batch consumers.
    std::map<StateChangeToken, StateChangeConsumer> consumers_;

    //! The mutual exclusion protecting access to the registered consumers.
    std::mutex consumers_mutex_;
};

}  // namespace silkworm
