// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "state_cache.hpp"

#include <optional>

#include <magic_enum.hpp>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_one.hpp>
#include <silkworm/infra/concurrency/timeout.hpp>
#include <silkworm/infra/grpc/common/conversion.hpp>

namespace silkworm::db::kv::api {

CoherentStateView::CoherentStateView(StateVersionId version_id, Transaction& tx, CoherentStateCache* cache)
    : version_id_(version_id), tx_(tx), cache_(cache) {}

bool CoherentStateView::empty() const {
    const auto root_it = cache_->state_view_roots_.find(version_id_);
    if (root_it == cache_->state_view_roots_.end()) {
        return true;
    }
    const auto& root = root_it->second;
    return root->cache.empty() && root->code_cache.empty();
}

Task<std::optional<Bytes>> CoherentStateView::get(std::string_view table, Bytes key) {
    co_return co_await cache_->get(version_id_, table, std::move(key), tx_);
}

Task<std::optional<Bytes>> CoherentStateView::get_code(Bytes key) {
    co_return co_await cache_->get_code(version_id_, std::move(key), tx_);
}

CoherentStateCache::CoherentStateCache(CoherentCacheConfig config) : config_(config) {
    if (config.max_views == 0) {
        throw std::invalid_argument{"unexpected zero max_views"};
    }
}

Task<std::unique_ptr<StateView>> CoherentStateCache::get_view(Transaction& tx) {
    const auto version_id = co_await get_db_state_version(tx);
    if (config_.wait_for_new_block) {
        co_await wait_for_root_ready(version_id);
    }
    co_return std::make_unique<CoherentStateView>(version_id, tx, this);
}

size_t CoherentStateCache::latest_data_size() {
    std::shared_lock read_lock{rw_mutex_};
    if (latest_state_view_ == nullptr) {
        return 0;
    }
    return static_cast<size_t>(latest_state_view_->cache.size());
}

size_t CoherentStateCache::latest_code_size() {
    std::shared_lock read_lock{rw_mutex_};
    if (latest_state_view_ == nullptr) {
        return 0;
    }
    return static_cast<size_t>(latest_state_view_->code_cache.size());
}

void CoherentStateCache::on_new_block(const api::StateChangeSet& state_changes_set) {
    const auto& state_changes = state_changes_set.state_changes;
    if (state_changes.empty()) {
        SILK_WARN << "Unexpected empty batch received and skipped";
        return;
    }

    std::scoped_lock write_lock{rw_mutex_};
    new_block_wait_count_ = 0;

    const auto version_id = state_changes_set.state_version_id;
    CoherentStateRoot* root = advance_root(version_id);
    for (const auto& state_change : state_changes) {
        for (const auto& account_change : state_change.account_changes) {
            switch (account_change.change_type) {
                case Action::kUpsert: {
                    process_upsert_change(root, version_id, account_change);
                    break;
                }
                case Action::kUpsertCode: {
                    process_upsert_change(root, version_id, account_change);
                    process_code_change(root, version_id, account_change);
                    break;
                }
                case Action::kRemove: {
                    process_delete_change(root, version_id, account_change);
                    break;
                }
                case Action::kStorage: {
                    if (config_.with_storage && !account_change.storage_changes.empty()) {
                        process_storage_change(root, version_id, account_change);
                    }
                    break;
                }
                case Action::kCode: {
                    process_code_change(root, version_id, account_change);
                    break;
                }
                default: {
                    SILK_ERROR << "Unexpected action: " << magic_enum::enum_name(account_change.change_type) << " skipped";
                }
            }
        }
    }

    state_key_count_ = static_cast<size_t>(latest_state_view_->cache.size());
    code_key_count_ = static_cast<size_t>(latest_state_view_->code_cache.size());

    root->ready = true;
    root->ready_cond_var.notify_all();
}

Task<StateCache::ValidationResult> CoherentStateCache::validate_current_root(Transaction& tx) {
    StateCache::ValidationResult validation_result{.enabled = true};

    const StateVersionId current_state_version_id = co_await get_db_state_version(tx);
    validation_result.latest_state_version_id = current_state_version_id;
    // If the latest version id in the cache is not the same as the db or one below it
    // then the cache will be a new one for the next call so return early
    if (current_state_version_id > latest_state_version_id_) {
        validation_result.latest_state_behind = true;
        co_return validation_result;
    }
    const auto root = co_await wait_for_root_ready(latest_state_version_id_);

    bool clear_cache{false};
    const auto get_address_domain = [](const auto& key) {
        return key.size() == kAddressLength ? db::table::kAccountDomain : db::table::kStorageDomain;
    };
    const auto compare_cache = [&](auto& cache, bool is_code) -> Task<std::pair<bool, std::vector<Bytes>>> {
        bool cancelled{false};
        std::vector<Bytes> keys;
        if (cache.empty()) {
            co_return std::make_pair(cancelled, keys);
        }
        auto kv_node = cache.extract(cache.begin());
        if (!kv_node.empty()) {
            co_return std::make_pair(cancelled, keys);
        }
        KeyValue kv{kv_node.value()};
        const auto domain = is_code ? db::table::kCodeDomain : get_address_domain(kv.key);
        const GetLatestResult result = co_await tx.get_latest({.table = std::string{domain}, .key = kv.key});
        if (!result.success) {
            co_return std::make_pair(cancelled, keys);
        }
        if (result.value != kv.key) {
            keys.push_back(kv.key);
            clear_cache = true;
        }
        co_return std::make_pair(cancelled, keys);
    };

    auto [cache, code_cache] = clone_caches(root);

    auto [cancelled_1, keys] = co_await compare_cache(cache, /*is_code=*/false);
    if (cancelled_1) {
        validation_result.request_canceled = true;
        co_return validation_result;
    }
    validation_result.state_keys_out_of_sync = std::move(keys);
    auto [cancelled_2, code_keys] = co_await compare_cache(code_cache, /*is_code=*/true);
    if (cancelled_2) {
        validation_result.request_canceled = true;
        co_return validation_result;
    }
    validation_result.code_keys_out_of_sync = std::move(code_keys);

    if (clear_cache) {
        clear_caches(root);
    }
    validation_result.cache_cleared = true;
    co_return validation_result;
}

void CoherentStateCache::process_upsert_change(CoherentStateRoot* root, StateVersionId version_id, const AccountChange& change) {
    const auto& address = change.address;
    const auto& data_bytes = change.data;
    SILK_DEBUG << "CoherentStateCache::process_upsert_change address: " << address << " data: " << data_bytes;
    const Bytes address_key{address.bytes, kAddressLength};
    add({address_key, data_bytes}, root, version_id);
}

void CoherentStateCache::process_code_change(CoherentStateRoot* root, StateVersionId version_id, const AccountChange& change) {
    const auto& code_bytes = change.code;
    const ethash::hash256 code_hash{keccak256(code_bytes)};
    const Bytes code_hash_key{code_hash.bytes, kHashLength};
    SILK_DEBUG << "CoherentStateCache::process_code_change code_hash_key: " << code_hash_key;
    add_code({code_hash_key, code_bytes}, root, version_id);
}

void CoherentStateCache::process_delete_change(CoherentStateRoot* root, StateVersionId version_id, const AccountChange& change) {
    const auto& address = change.address;
    SILK_DEBUG << "CoherentStateCache::process_delete_change address: " << address;
    const Bytes address_key{address.bytes, kAddressLength};
    add({address_key, {}}, root, version_id);
}

void CoherentStateCache::process_storage_change(CoherentStateRoot* root, StateVersionId version_id, const AccountChange& change) {
    const auto& address = change.address;
    SILK_DEBUG << "CoherentStateCache::process_storage_change address=" << address;
    for (const auto& storage_change : change.storage_changes) {
        const auto& location_hash = storage_change.location;
        const auto storage_key = composite_storage_key(address, change.incarnation, location_hash.bytes);
        const auto& value = storage_change.data;
        SILK_DEBUG << "CoherentStateCache::process_storage_change key=" << storage_key << " value=" << value;
        add({storage_key, value}, root, version_id);
    }
}

bool CoherentStateCache::add(KeyValue&& kv, CoherentStateRoot* root, StateVersionId version_id) {
    auto [it, inserted] = root->cache.insert(kv);
    SILK_DEBUG << "Data cache kv.key=" << to_hex(kv.key) << " inserted=" << inserted << " version_id=" << version_id;
    std::optional<KeyValue> replaced;
    if (!inserted) {
        replaced = *it;
        root->cache.erase(it);
        std::tie(it, inserted) = root->cache.insert(kv);
        SILKWORM_ASSERT(inserted);
    }
    if (latest_state_version_id_ != version_id) {
        return inserted;
    }
    if (replaced) {
        state_evictions_.remove(*replaced);
        SILK_DEBUG << "Data evictions removed replaced.key=" << to_hex(replaced->key);
    }
    state_evictions_.push_front(std::move(kv));

    // Remove the longest unused key-value pair when size exceeded
    if (state_evictions_.size() > config_.max_state_keys) {
        const auto oldest = state_evictions_.back();
        SILK_DEBUG << "Data cache resize oldest.key=" << to_hex(oldest.key);
        state_evictions_.pop_back();
        const auto num_erased = root->cache.erase(oldest);
        SILKWORM_ASSERT(num_erased == 1);
    }
    return inserted;
}

bool CoherentStateCache::add_code(KeyValue&& kv, CoherentStateRoot* root, StateVersionId version_id) {
    auto [it, inserted] = root->code_cache.insert(kv);
    SILK_DEBUG << "Code cache kv.key=" << to_hex(kv.key) << " inserted=" << inserted << " version_id=" << version_id;
    std::optional<KeyValue> replaced;
    if (!inserted) {
        replaced = *it;
        root->code_cache.erase(it);
        std::tie(it, inserted) = root->code_cache.insert(kv);
        SILKWORM_ASSERT(inserted);
    }
    if (latest_state_version_id_ != version_id) {
        return inserted;
    }
    if (replaced) {
        code_evictions_.remove(*replaced);
        SILK_DEBUG << "Code evictions removed replaced.key=" << to_hex(replaced->key);
    }
    code_evictions_.push_front(std::move(kv));

    // Remove the longest unused key-value pair when size exceeded
    if (code_evictions_.size() > config_.max_code_keys) {
        const auto oldest = code_evictions_.back();
        SILK_DEBUG << "Code cache resize oldest.key=" << to_hex(oldest.key);
        code_evictions_.pop_back();
        const auto num_erased = root->code_cache.erase(oldest);
        SILKWORM_ASSERT(num_erased == 1);
    }
    return inserted;
}

Task<std::optional<Bytes>> CoherentStateCache::get(StateVersionId version_id, std::string_view table, Bytes key, Transaction& tx) {
    std::shared_lock read_lock{rw_mutex_};

    const auto root_it = state_view_roots_.find(version_id);
    if (root_it == state_view_roots_.end()) {
        co_return std::nullopt;
    }

    KeyValue kv{std::move(key)};
    auto& cache = root_it->second->cache;
    const auto kv_it = cache.find(kv);
    if (kv_it != cache.end()) {
        ++state_hit_count_;

        SILK_DEBUG << "Hit in state cache key=" << kv.key << " value=" << kv_it->value;

        if (version_id == latest_state_version_id_) {
            state_evictions_.remove(kv);
            state_evictions_.push_front(kv);
        }

        co_return kv_it->value;
    }

    ++state_miss_count_;

    const auto domain = kv.key.size() == kAddressLength ? db::table::kAccountDomain : db::table::kStorageDomain;
    const GetLatestResult result = co_await tx.get_latest({.table = std::string{table}, .key = kv.key});
    if (!result.success) {
        co_return std::nullopt;
    }

    const Bytes value = result.value;
    SILK_DEBUG << "Miss in state cache: lookup in domain " << domain << " key=" << kv.key << " value=" << value;
    if (value.empty()) {
        co_return std::nullopt;
    }

    read_lock.unlock();
    std::scoped_lock write_lock{rw_mutex_};

    kv.value = value;
    add(std::move(kv), root_it->second.get(), version_id);

    co_return value;
}

Task<std::optional<Bytes>> CoherentStateCache::get_code(StateVersionId version_id, Bytes key, Transaction& tx) {
    std::shared_lock read_lock{rw_mutex_};

    const auto root_it = state_view_roots_.find(version_id);
    if (root_it == state_view_roots_.end()) {
        co_return std::nullopt;
    }

    KeyValue kv{std::move(key)};
    auto& code_cache = root_it->second->code_cache;
    const auto kv_it = code_cache.find(kv);
    if (kv_it != code_cache.end()) {
        ++code_hit_count_;

        SILK_DEBUG << "Hit in code cache key=" << kv.key << " value=" << kv_it->value;

        if (version_id == latest_state_version_id_) {
            code_evictions_.remove(kv);
            code_evictions_.push_front(kv);
        }

        co_return kv_it->value;
    }

    ++code_miss_count_;

    const GetLatestResult result = co_await tx.get_latest({.table = std::string{db::table::kCodeDomain}, .key = kv.key});
    if (!result.success) {
        co_return std::nullopt;
    }
    const Bytes value = result.value;
    SILK_DEBUG << "Miss in code cache: lookup in domain Code key=" << kv.key << " value=" << value;
    if (value.empty()) {
        co_return std::nullopt;
    }

    read_lock.unlock();
    std::scoped_lock write_lock{rw_mutex_};

    kv.value = value;
    add_code(std::move(kv), root_it->second.get(), version_id);

    co_return value;
}

CoherentStateRoot* CoherentStateCache::get_root(StateVersionId version_id) {
    const auto root_it = state_view_roots_.find(version_id);
    if (root_it != state_view_roots_.end()) {
        SILK_DEBUG << "CoherentStateCache::get_root version_id=" << version_id << " root=" << root_it->second.get() << " found";
        return root_it->second.get();
    }
    const auto [new_root_it, _] = state_view_roots_.emplace(version_id, std::make_unique<CoherentStateRoot>());
    SILK_DEBUG << "CoherentStateCache::get_root version_id=" << version_id << " root=" << root_it->second.get() << " created";
    return new_root_it->second.get();
}

CoherentStateRoot* CoherentStateCache::advance_root(StateVersionId version_id) {
    CoherentStateRoot* root = get_root(version_id);

    const auto previous_root_it = state_view_roots_.find(version_id - 1);
    if (previous_root_it != state_view_roots_.end() && previous_root_it->second->canonical) {
        SILK_DEBUG << "CoherentStateCache::advance_root canonical view_id-1=" << (version_id - 1) << " found";
        root->cache = previous_root_it->second->cache;
        root->code_cache = previous_root_it->second->code_cache;
    } else {
        SILK_DEBUG << "CoherentStateCache::advance_root canonical view_id-1=" << (version_id - 1) << " not found";
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

    evict_roots(version_id);

    latest_state_version_id_ = version_id;
    latest_state_view_ = root;

    state_eviction_count_ = state_evictions_.size();
    code_eviction_count_ = code_evictions_.size();

    return root;
}

void CoherentStateCache::evict_roots(StateVersionId next_version_id) {
    SILK_DEBUG << "CoherentStateCache::evict_roots state_view_roots_.size()=" << state_view_roots_.size();
    if (state_view_roots_.size() <= config_.max_views) {
        return;
    }
    if (next_version_id == 0) {
        // Next version ID is zero with cache not empty => version ID wrapping => clear the cache except for new latest view
        std::erase_if(state_view_roots_, [&](const auto& item) {
            auto const& [version_id, _] = item;
            return version_id != next_version_id;
        });
        return;
    }
    // Erase older state views in order not to exceed max_views
    const auto max_version_id_to_delete = latest_state_version_id_ - config_.max_views + 1;
    SILK_DEBUG << "CoherentStateCache::evict_roots max_version_id_to_delete=" << max_version_id_to_delete;
    std::erase_if(state_view_roots_, [&](const auto& item) {
        auto const& [version_id, _] = item;
        return version_id <= max_version_id_to_delete;
    });
}

Task<CoherentStateRoot*> CoherentStateCache::wait_for_root_ready(StateVersionId version_id) {
    using namespace concurrency::awaitable_wait_for_one;
    CoherentStateRoot* root = get_root(version_id);
    while (new_block_wait_count_ <= kDefaultMaxWaitCount) {
        std::unique_lock write_lock{rw_mutex_};
        if (root->ready) co_return root;
        auto ready_waiter = root->ready_cond_var.waiter();
        write_lock.unlock();
        try {
            co_await (ready_waiter() || concurrency::timeout(config_.block_wait_duration));
        } catch (const concurrency::TimeoutExpiredError&) {
            write_lock.lock();
            ++new_block_wait_count_;
            write_lock.unlock();
        }
    }
    co_return root;
}

Task<StateVersionId> CoherentStateCache::get_db_state_version(Transaction& tx) const {
    const Bytes version = co_await tx.get_one(db::table::kSequenceName, string_view_to_byte_view(kPlainStateVersionKey));
    if (version.empty()) {
        co_return 0;
    }
    co_return endian::load_big_u64(version.data());
}

std::pair<KeyValueSet, KeyValueSet> CoherentStateCache::clone_caches(CoherentStateRoot* root) {
    std::scoped_lock write_lock{rw_mutex_};
    KeyValueSet cache = root->cache;
    KeyValueSet code_cache = root->code_cache;
    return {cache, code_cache};
}

void CoherentStateCache::clear_caches(CoherentStateRoot* root) {
    std::scoped_lock write_lock{rw_mutex_};
    root->cache.clear();
    root->code_cache.clear();
}

}  // namespace silkworm::db::kv::api
