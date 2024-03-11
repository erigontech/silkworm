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

#include "state_cache.hpp"

#include <optional>

#include <magic_enum.hpp>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/grpc/common/conversion.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/core/rawdb/util.hpp>
#include <silkworm/rpc/ethdb/transaction_database.hpp>

namespace silkworm::rpc::ethdb::kv {

CoherentStateView::CoherentStateView(Transaction& txn, CoherentStateCache* cache) : txn_(txn), cache_(cache) {}

Task<std::optional<silkworm::Bytes>> CoherentStateView::get(const silkworm::Bytes& key) {
    co_return co_await cache_->get(key, txn_);
}

Task<std::optional<silkworm::Bytes>> CoherentStateView::get_code(const silkworm::Bytes& key) {
    co_return co_await cache_->get_code(key, txn_);
}

CoherentStateCache::CoherentStateCache(CoherentCacheConfig config) : config_(config) {
    if (config.max_views == 0) {
        throw std::invalid_argument{"unexpected zero max_views"};
    }
}

std::unique_ptr<StateView> CoherentStateCache::get_view(Transaction& txn) {
    const auto view_id = txn.view_id();
    std::unique_lock write_lock{rw_mutex_};
    CoherentStateRoot* root = get_root(view_id);
    return root->ready ? std::make_unique<CoherentStateView>(txn, this) : nullptr;
}

std::size_t CoherentStateCache::latest_data_size() {
    std::shared_lock read_lock{rw_mutex_};
    if (latest_state_view_ == nullptr) {
        return 0;
    }
    return static_cast<std::size_t>(latest_state_view_->cache.size());
}

std::size_t CoherentStateCache::latest_code_size() {
    std::shared_lock read_lock{rw_mutex_};
    if (latest_state_view_ == nullptr) {
        return 0;
    }
    return static_cast<std::size_t>(latest_state_view_->code_cache.size());
}

void CoherentStateCache::on_new_block(const remote::StateChangeBatch& state_changes) {
    if (state_changes.change_batch_size() == 0) {
        SILK_WARN << "Unexpected empty batch received and skipped";
        return;
    }

    std::unique_lock write_lock{rw_mutex_};

    const auto view_id = state_changes.state_version_id();
    CoherentStateRoot* root = advance_root(view_id);
    for (const auto& state_change : state_changes.change_batch()) {
        for (const auto& account_change : state_change.changes()) {
            switch (account_change.action()) {
                case remote::Action::UPSERT: {
                    process_upsert_change(root, view_id, account_change);
                    break;
                }
                case remote::Action::UPSERT_CODE: {
                    process_upsert_change(root, view_id, account_change);
                    process_code_change(root, view_id, account_change);
                    break;
                }
                case remote::Action::REMOVE: {
                    process_delete_change(root, view_id, account_change);
                    break;
                }
                case remote::Action::STORAGE: {
                    if (config_.with_storage && account_change.storage_changes_size() > 0) {
                        process_storage_change(root, view_id, account_change);
                    }
                    break;
                }
                case remote::Action::CODE: {
                    process_code_change(root, view_id, account_change);
                    break;
                }
                default: {
                    SILK_ERROR << "Unexpected action: " << magic_enum::enum_name(account_change.action()) << " skipped";
                }
            }
        }
    }

    state_key_count_ = static_cast<std::size_t>(latest_state_view_->cache.size());
    code_key_count_ = static_cast<std::size_t>(latest_state_view_->code_cache.size());

    root->ready = true;
}

void CoherentStateCache::process_upsert_change(CoherentStateRoot* root, StateViewId view_id,
                                               const remote::AccountChange& change) {
    const auto address = silkworm::rpc::address_from_H160(change.address());
    const auto data_bytes = silkworm::bytes_of_string(change.data());
    SILK_DEBUG << "CoherentStateCache::process_upsert_change address: " << address << " data: " << data_bytes;
    const silkworm::Bytes address_key{address.bytes, silkworm::kAddressLength};
    add({address_key, data_bytes}, root, view_id);
}

void CoherentStateCache::process_code_change(CoherentStateRoot* root, StateViewId view_id, const remote::AccountChange& change) {
    const auto code_bytes = silkworm::bytes_of_string(change.code());
    const ethash::hash256 code_hash{silkworm::keccak256(code_bytes)};
    const silkworm::Bytes code_hash_key{code_hash.bytes, silkworm::kHashLength};
    SILK_DEBUG << "CoherentStateCache::process_code_change code_hash_key: " << code_hash_key;
    add_code({code_hash_key, code_bytes}, root, view_id);
}

void CoherentStateCache::process_delete_change(CoherentStateRoot* root, StateViewId view_id,
                                               const remote::AccountChange& change) {
    const auto address = silkworm::rpc::address_from_H160(change.address());
    SILK_DEBUG << "CoherentStateCache::process_delete_change address: " << address;
    const silkworm::Bytes address_key{address.bytes, silkworm::kAddressLength};
    add({address_key, {}}, root, view_id);
}

void CoherentStateCache::process_storage_change(CoherentStateRoot* root, StateViewId view_id,
                                                const remote::AccountChange& change) {
    const auto address = silkworm::rpc::address_from_H160(change.address());
    SILK_DEBUG << "CoherentStateCache::process_storage_change address=" << address;
    for (const auto& storage_change : change.storage_changes()) {
        const auto location_hash = silkworm::rpc::bytes32_from_H256(storage_change.location());
        const auto storage_key = composite_storage_key(address, change.incarnation(), location_hash.bytes);
        const auto value = silkworm::bytes_of_string(storage_change.data());
        SILK_DEBUG << "CoherentStateCache::process_storage_change key=" << storage_key << " value=" << value;
        add({storage_key, value}, root, view_id);
    }
}

bool CoherentStateCache::add(const KeyValue& kv, CoherentStateRoot* root, StateViewId view_id) {
    auto [it, inserted] = root->cache.insert(kv);
    SILK_DEBUG << "Data cache kv.key=" << silkworm::to_hex(kv.key) << " inserted=" << inserted << " view=" << view_id;
    std::optional<KeyValue> replaced;
    if (!inserted) {
        replaced = *it;
        root->cache.erase(it);
        std::tie(it, inserted) = root->cache.insert(kv);
        SILKWORM_ASSERT(inserted);
    }
    if (latest_state_view_id_ != view_id) {
        return inserted;
    }
    if (replaced) {
        state_evictions_.remove(*replaced);
        SILK_DEBUG << "Data evictions removed replaced.key=" << silkworm::to_hex(replaced->key);
    }
    state_evictions_.push_front(kv);

    // Remove the longest unused key-value pair when size exceeded
    if (state_evictions_.size() > config_.max_state_keys) {
        const auto oldest = state_evictions_.back();
        SILK_DEBUG << "Data cache resize oldest.key=" << silkworm::to_hex(oldest.key);
        state_evictions_.pop_back();
        const auto num_erased = root->cache.erase(oldest);
        SILKWORM_ASSERT(num_erased == 1);
    }
    return inserted;
}

bool CoherentStateCache::add_code(const KeyValue& kv, CoherentStateRoot* root, StateViewId view_id) {
    auto [it, inserted] = root->code_cache.insert(kv);
    SILK_DEBUG << "Code cache kv.key=" << silkworm::to_hex(kv.key) << " inserted=" << inserted << " view=" << view_id;
    std::optional<KeyValue> replaced;
    if (!inserted) {
        replaced = *it;
        root->code_cache.erase(it);
        std::tie(it, inserted) = root->code_cache.insert(kv);
        SILKWORM_ASSERT(inserted);
    }
    if (latest_state_view_id_ != view_id) {
        return inserted;
    }
    if (replaced) {
        code_evictions_.remove(*replaced);
        SILK_DEBUG << "Code evictions removed replaced.key=" << silkworm::to_hex(replaced->key);
    }
    code_evictions_.push_front(kv);

    // Remove the longest unused key-value pair when size exceeded
    if (code_evictions_.size() > config_.max_code_keys) {
        const auto oldest = code_evictions_.back();
        SILK_DEBUG << "Code cache resize oldest.key=" << silkworm::to_hex(oldest.key);
        code_evictions_.pop_back();
        const auto num_erased = root->code_cache.erase(oldest);
        SILKWORM_ASSERT(num_erased == 1);
    }
    return inserted;
}

Task<std::optional<silkworm::Bytes>> CoherentStateCache::get(const silkworm::Bytes& key, Transaction& txn) {
    std::shared_lock read_lock{rw_mutex_};

    const auto view_id = txn.view_id();
    const auto root_it = state_view_roots_.find(view_id);
    if (root_it == state_view_roots_.end()) {
        co_return std::nullopt;
    }

    KeyValue kv{key};
    auto& cache = root_it->second->cache;
    const auto kv_it = cache.find(kv);
    if (kv_it != cache.end()) {
        ++state_hit_count_;

        SILK_DEBUG << "Hit in state cache key=" << key << " value=" << kv_it->value;

        if (view_id == latest_state_view_id_) {
            state_evictions_.remove(kv);
            state_evictions_.push_front(kv);
        }

        co_return kv_it->value;
    }

    ++state_miss_count_;

    TransactionDatabase tx_database{txn};
    const auto value = co_await tx_database.get_one(db::table::kPlainStateName, key);
    SILK_DEBUG << "Miss in state cache: lookup in PlainState key=" << key << " value=" << value;
    if (value.empty()) {
        co_return std::nullopt;
    }

    read_lock.unlock();
    std::unique_lock write_lock{rw_mutex_};

    add({key, value}, root_it->second.get(), view_id);

    co_return value;
}

Task<std::optional<silkworm::Bytes>> CoherentStateCache::get_code(const silkworm::Bytes& key, Transaction& txn) {
    std::shared_lock read_lock{rw_mutex_};

    const auto view_id = txn.view_id();
    const auto root_it = state_view_roots_.find(view_id);
    if (root_it == state_view_roots_.end()) {
        co_return std::nullopt;
    }

    KeyValue kv{key};
    auto& code_cache = root_it->second->code_cache;
    const auto kv_it = code_cache.find(kv);
    if (kv_it != code_cache.end()) {
        ++code_hit_count_;

        SILK_DEBUG << "Hit in code cache key=" << key << " value=" << kv_it->value;

        if (view_id == latest_state_view_id_) {
            code_evictions_.remove(kv);
            code_evictions_.push_front(kv);
        }

        co_return kv_it->value;
    }

    ++code_miss_count_;

    TransactionDatabase tx_database{txn};
    const auto value = co_await tx_database.get_one(db::table::kCodeName, key);
    SILK_DEBUG << "Miss in code cache: lookup in Code key=" << key << " value=" << value;
    if (value.empty()) {
        co_return std::nullopt;
    }

    read_lock.unlock();
    std::unique_lock write_lock{rw_mutex_};

    add_code({key, value}, root_it->second.get(), view_id);

    co_return value;
}

CoherentStateRoot* CoherentStateCache::get_root(StateViewId view_id) {
    const auto root_it = state_view_roots_.find(view_id);
    if (root_it != state_view_roots_.end()) {
        SILK_DEBUG << "CoherentStateCache::get_root view_id=" << view_id << " root=" << root_it->second.get() << " found";
        return root_it->second.get();
    }
    const auto [new_root_it, _] = state_view_roots_.emplace(view_id, std::make_unique<CoherentStateRoot>());
    SILK_DEBUG << "CoherentStateCache::get_root view_id=" << view_id << " root=" << root_it->second.get() << " created";
    return new_root_it->second.get();
}

CoherentStateRoot* CoherentStateCache::advance_root(StateViewId view_id) {
    CoherentStateRoot* root = get_root(view_id);

    const auto previous_root_it = state_view_roots_.find(view_id - 1);
    if (previous_root_it != state_view_roots_.end() && previous_root_it->second->canonical) {
        SILK_DEBUG << "CoherentStateCache::advance_root canonical view_id-1=" << (view_id - 1) << " found";
        root->cache = previous_root_it->second->cache;
        root->code_cache = previous_root_it->second->code_cache;
    } else {
        SILK_DEBUG << "CoherentStateCache::advance_root canonical view_id-1=" << (view_id - 1) << " not found";
        state_evictions_.clear();
        for (const auto& kv : root->cache) {
            state_evictions_.push_front(kv);
        }
        code_evictions_.clear();
        for (const auto& kv : root->code_cache) {
            code_evictions_.push_front(kv);
        }
    }
    root->canonical = true;

    evict_roots(view_id);

    latest_state_view_id_ = view_id;
    latest_state_view_ = root;

    state_eviction_count_ = state_evictions_.size();
    code_eviction_count_ = code_evictions_.size();

    return root;
}

void CoherentStateCache::evict_roots(StateViewId next_view_id) {
    SILK_DEBUG << "CoherentStateCache::evict_roots state_view_roots_.size()=" << state_view_roots_.size();
    if (state_view_roots_.size() <= config_.max_views) {
        return;
    }
    if (next_view_id == 0) {
        // Next view ID is zero with cache not empty => view ID wrapping => clear the cache except for new latest view
        std::erase_if(state_view_roots_, [&](const auto& item) {
            auto const& [view_id, _] = item;
            return view_id != next_view_id;
        });
        return;
    }
    // Erase older state views in order not to exceed max_views
    const auto max_view_id_to_delete = latest_state_view_id_ - config_.max_views + 1;
    SILK_DEBUG << "CoherentStateCache::evict_roots max_view_id_to_delete=" << max_view_id_to_delete;
    std::erase_if(state_view_roots_, [&](const auto& item) {
        auto const& [view_id, _] = item;
        return view_id <= max_view_id_to_delete;
    });
}

}  // namespace silkworm::rpc::ethdb::kv
