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

#include "state_change_collection.hpp"

#include <silkworm/common/assert.hpp>
#include <silkworm/common/base.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/rpc/common/conversion.hpp>

namespace silkworm {

std::optional<StateChangeToken> StateChangeCollection::subscribe(StateChangeConsumer consumer,
                                                                 StateChangeFilter /*filter*/) {
    std::unique_lock consumers_lock{consumers_mutex_};
    StateChangeToken token = ++next_token_;
    const auto [_, inserted] = consumers_.insert({token, consumer});
    return inserted ? std::make_optional(token) : std::nullopt;
}

bool StateChangeCollection::unsubscribe(StateChangeToken token) {
    std::unique_lock consumers_lock{consumers_mutex_};
    const auto consumer_it = consumers_.erase(token);
    return consumer_it != 0;
}

void StateChangeCollection::reset(uint64_t tx_id) {
    tx_id_ = tx_id;
    state_changes_.clear_changebatch();
    latest_change_ = nullptr;
    account_change_index_.clear();
    storage_change_index_.clear();
}

void StateChangeCollection::start_new_batch(BlockNum block_height, const evmc::bytes32& block_hash,
                                            const std::vector<Bytes>&& tx_rlps, bool unwind) {
    SILK_TRACE << "StateChangeCollection::start_new_batch " << this << " block: " << block_height
               << " unwind:" << unwind << " START";

    SILKWORM_ASSERT(latest_change_ == nullptr);

    latest_change_ = state_changes_.add_changebatch();
    latest_change_->set_blockheight(block_height);
    latest_change_->set_allocated_blockhash(rpc::H256_from_bytes32(block_hash).release());
    latest_change_->set_direction(unwind ? remote::Direction::UNWIND : remote::Direction::FORWARD);
    for (auto& tx_rlp : tx_rlps) {
        latest_change_->add_txs(to_hex(tx_rlp));
    }

    SILK_TRACE << "StateChangeCollection::start_new_batch " << this << " END";
}

void StateChangeCollection::change_account(const evmc::address& address, uint64_t incarnation, const Bytes& data) {
    SILKWORM_ASSERT(latest_change_ != nullptr);

    const auto& ac_it = account_change_index_.find(address);
    std::optional<size_t> index{ac_it != account_change_index_.end() ? std::make_optional(ac_it->second)
                                                                     : std::nullopt};

    if (!index.has_value() || incarnation > latest_change_->changes(static_cast<int>(index.value())).incarnation()) {
        index = latest_change_->changes_size();
        latest_change_->add_changes()->set_allocated_address(
            rpc::H160_from_address(address).release());  // takes ownership
        account_change_index_[address] = index.value();
    }

    remote::AccountChange* account_change = latest_change_->mutable_changes(static_cast<int>(index.value()));
    switch (account_change->action()) {
        case remote::Action::STORAGE:
            account_change->set_action(remote::Action::UPSERT);
            break;
        case remote::Action::CODE:
            account_change->set_action(remote::Action::UPSERT_CODE);
            break;
        case remote::Action::REMOVE:
            SILK_CRIT << "cannot change deleted account: " << to_hex(address) << " incarnation: " << incarnation;
            SILKWORM_ASSERT(false);
            break;
        default:
            break;
    }
    account_change->set_incarnation(incarnation);
    account_change->set_data(to_hex(data));
}

void StateChangeCollection::change_code(const evmc::address& address, uint64_t incarnation, const Bytes& code) {
    SILKWORM_ASSERT(latest_change_ != nullptr);

    const auto& ac_it = account_change_index_.find(address);
    std::optional<size_t> index{ac_it != account_change_index_.end() ? std::make_optional(ac_it->second)
                                                                     : std::nullopt};

    if (!index.has_value() || incarnation > latest_change_->changes(static_cast<int>(index.value())).incarnation()) {
        index = latest_change_->changes_size();
        remote::AccountChange* account_change = latest_change_->add_changes();
        account_change->set_allocated_address(rpc::H160_from_address(address).release());  // takes ownership
        account_change->set_action(remote::Action::CODE);
        account_change_index_[address] = index.value();
    }

    remote::AccountChange* account_change = latest_change_->mutable_changes(static_cast<int>(index.value()));
    switch (account_change->action()) {
        case remote::Action::STORAGE:
            account_change->set_action(remote::Action::CODE);
            break;
        case remote::Action::UPSERT:
            account_change->set_action(remote::Action::UPSERT_CODE);
            break;
        case remote::Action::REMOVE:
            SILK_CRIT << "cannot change code for deleted account: " << to_hex(address)
                      << " incarnation: " << incarnation;
            SILKWORM_ASSERT(false);
            break;
        default:
            break;
    }
    account_change->set_incarnation(incarnation);
    account_change->set_code(to_hex(code));
}

void StateChangeCollection::change_storage(const evmc::address& address, uint64_t incarnation,
                                           const evmc::bytes32& location, const Bytes& data) {
    SILKWORM_ASSERT(latest_change_ != nullptr);

    const auto& ac_it = account_change_index_.find(address);
    std::optional<std::size_t> ac_index{ac_it != account_change_index_.end() ? std::make_optional(ac_it->second)
                                                                             : std::nullopt};

    if (!ac_index || incarnation > latest_change_->changes(static_cast<int>(ac_index.value())).incarnation()) {
        ac_index = latest_change_->changes_size();
        remote::AccountChange* account_change = latest_change_->add_changes();
        account_change->set_allocated_address(rpc::H160_from_address(address).release());  // takes ownership
        account_change->set_action(remote::Action::STORAGE);
        account_change_index_[address] = ac_index.value();
    }

    remote::AccountChange* account_change = latest_change_->mutable_changes(static_cast<int>(ac_index.value()));
    switch (account_change->action()) {
        case remote::Action::REMOVE:
            SILK_CRIT << "cannot change storage for deleted account: " << to_hex(address)
                      << " incarnation: " << incarnation;
            SILKWORM_ASSERT(false);
            break;
        default:
            break;
    }
    account_change->set_incarnation(incarnation);

    auto& index_by_location = storage_change_index_[address];  // insert if not present
    const auto& loc_it = index_by_location.find(location);
    auto loc_index{loc_it != index_by_location.end() ? std::make_optional(loc_it->second) : std::nullopt};
    if (!loc_index) {
        loc_index = account_change->storagechanges_size();
        account_change->add_storagechanges();
        index_by_location[location] = loc_index.value();
    }

    remote::StorageChange* storage_change = account_change->mutable_storagechanges(static_cast<int>(loc_index.value()));
    storage_change->set_allocated_location(rpc::H256_from_bytes32(location).release());  // takes ownership
    storage_change->set_data(to_hex(data));
}

void StateChangeCollection::delete_account(const evmc::address& address) {
    SILKWORM_ASSERT(latest_change_ != nullptr);

    const auto& ac_it = account_change_index_.find(address);
    auto index{ac_it != account_change_index_.end() ? std::make_optional(ac_it->second) : std::nullopt};

    if (!index.has_value()) {
        index = latest_change_->changes_size();
        latest_change_->add_changes()->set_allocated_address(
            rpc::H160_from_address(address).release());  // takes ownership
        account_change_index_[address] = index.value();
    }

    remote::AccountChange* account_change = latest_change_->mutable_changes(static_cast<int>(index.value()));
    SILKWORM_ASSERT(account_change->action() == remote::Action::STORAGE);  // TODO(canepat) check Erigon
    account_change->set_action(remote::Action::REMOVE);
    account_change->clear_code();
    account_change->clear_data();
    account_change->clear_storagechanges();
}

void StateChangeCollection::notify_batch(uint64_t pending_base_fee, uint64_t gas_limit) {
    SILK_TRACE << "StateChangeCollection::notify_batch " << this << " pending_base_fee: " << pending_base_fee
               << " gas_limit:" << gas_limit << " START";

    state_changes_.set_pendingblockbasefee(pending_base_fee);
    state_changes_.set_blockgaslimit(gas_limit);
    state_changes_.set_databaseviewid(tx_id_);

    std::unique_lock consumers_lock{consumers_mutex_};
    for (const auto& [_, batch_callback] : consumers_) {
        // Make a copy of state change batch for every consumer because lifecycle is independent
        const std::optional<remote::StateChangeBatch> frozen_batch = state_changes_;
        SILK_DEBUG << "Notify callback=" << &batch_callback << " batch=" << &frozen_batch;
        batch_callback(frozen_batch);
        SILK_DEBUG << "Notify callback=" << &batch_callback << " done";
    }
    reset(0);

    SILK_TRACE << "StateChangeCollection::notify_batch " << this << " END";
}

void StateChangeCollection::close() {
    std::unique_lock consumers_lock{consumers_mutex_};
    for (const auto& [_, batch_callback] : consumers_) {
        SILK_DEBUG << "Notify close to callback=" << &batch_callback;
        batch_callback(std::nullopt);
        SILK_DEBUG << "Notify close to callback=" << &batch_callback << " done";
    }
    reset(0);
}

}  // namespace silkworm
