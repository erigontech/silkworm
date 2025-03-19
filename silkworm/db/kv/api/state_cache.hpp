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

#include <cstddef>
#include <list>
#include <map>
#include <memory>
#include <optional>
#include <shared_mutex>

#include <silkworm/infra/concurrency/task.hpp>

#include <absl/container/btree_set.h>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/infra/concurrency/awaitable_condition_variable.hpp>

#include "endpoint/key_value.hpp"
#include "endpoint/state_change.hpp"
#include "transaction.hpp"

namespace silkworm::db::kv::api {

class StateView {
  public:
    virtual ~StateView() = default;

    virtual bool empty() const = 0;

    virtual Task<std::optional<Bytes>> get(std::string_view table, Bytes key) = 0;

    virtual Task<std::optional<Bytes>> get_code(Bytes key) = 0;
};

using StateVersionId = uint64_t;

class StateCache {
  public:
    virtual ~StateCache() = default;

    virtual Task<std::unique_ptr<StateView>> get_view(Transaction& tx) = 0;

    virtual void on_new_block(const api::StateChangeSet& state_changes) = 0;

    virtual size_t latest_data_size() = 0;
    virtual size_t latest_code_size() = 0;

    virtual uint64_t state_hit_count() const = 0;
    virtual uint64_t state_miss_count() const = 0;
    virtual uint64_t state_key_count() const = 0;
    virtual uint64_t state_eviction_count() const = 0;
    virtual uint64_t code_hit_count() const = 0;
    virtual uint64_t code_miss_count() const = 0;
    virtual uint64_t code_key_count() const = 0;
    virtual uint64_t code_eviction_count() const = 0;

    struct ValidationResult {
        bool request_canceled{false};
        bool enabled{false};
        bool latest_state_behind{false};
        bool cache_cleared{false};
        StateVersionId latest_state_version_id{0};
        std::vector<Bytes> state_keys_out_of_sync;
        std::vector<Bytes> code_keys_out_of_sync;
    };
    virtual Task<ValidationResult> validate_current_root(Transaction& tx) = 0;
};

using KeyValueSet = absl::btree_set<KeyValue>;

struct CoherentStateRoot {
    KeyValueSet cache;
    KeyValueSet code_cache;
    bool ready{false};
    bool canonical{false};
    concurrency::AwaitableConditionVariable ready_cond_var;
};

inline constexpr uint64_t kDefaultMaxViews = 5ul;
inline constexpr uint32_t kDefaultMaxStateKeys = 1'000'000u;
inline constexpr uint32_t kDefaultMaxCodeKeys = 10'000u;
inline constexpr uint32_t kDefaultMaxWaitCount = 100u;

struct CoherentCacheConfig {
    uint64_t max_views{kDefaultMaxViews};
    bool with_storage{true};
    bool wait_for_new_block{true};
    uint32_t max_state_keys{kDefaultMaxStateKeys};
    uint32_t max_code_keys{kDefaultMaxCodeKeys};
    std::chrono::milliseconds block_wait_duration{5};
};

class CoherentStateCache;

class CoherentStateView : public StateView {
  public:
    CoherentStateView(StateVersionId version_id, Transaction& tx, CoherentStateCache* cache);

    CoherentStateView(const CoherentStateView&) = delete;
    CoherentStateView& operator=(const CoherentStateView&) = delete;

    bool empty() const override;

    Task<std::optional<Bytes>> get(std::string_view table, Bytes key) override;

    Task<std::optional<Bytes>> get_code(Bytes key) override;

  private:
    StateVersionId version_id_;
    Transaction& tx_;
    CoherentStateCache* cache_;
};

class CoherentStateCache : public StateCache {
  public:
    explicit CoherentStateCache(CoherentCacheConfig config = {});

    CoherentStateCache(const CoherentStateCache&) = delete;
    CoherentStateCache& operator=(const CoherentStateCache&) = delete;

    Task<std::unique_ptr<StateView>> get_view(Transaction& tx) override;

    void on_new_block(const api::StateChangeSet& state_changes) override;

    size_t latest_data_size() override;
    size_t latest_code_size() override;

    uint64_t state_hit_count() const override { return state_hit_count_; }
    uint64_t state_miss_count() const override { return state_miss_count_; }
    uint64_t state_key_count() const override { return state_key_count_; }
    uint64_t state_eviction_count() const override { return state_eviction_count_; }
    uint64_t code_hit_count() const override { return code_hit_count_; }
    uint64_t code_miss_count() const override { return code_miss_count_; }
    uint64_t code_key_count() const override { return code_key_count_; }
    uint64_t code_eviction_count() const override { return code_eviction_count_; }

    Task<ValidationResult> validate_current_root(Transaction& tx) override;

  private:
    friend class CoherentStateView;

    void process_upsert_change(CoherentStateRoot* root, StateVersionId version_id, const api::AccountChange& change);
    void process_code_change(CoherentStateRoot* root, StateVersionId version_id, const api::AccountChange& change);
    void process_delete_change(CoherentStateRoot* root, StateVersionId version_id, const api::AccountChange& change);
    void process_storage_change(CoherentStateRoot* root, StateVersionId version_id, const api::AccountChange& change);
    bool add(KeyValue&& kv, CoherentStateRoot* root, StateVersionId version_id);
    bool add_code(KeyValue&& kv, CoherentStateRoot* root, StateVersionId version_id);
    Task<std::optional<Bytes>> get(StateVersionId version_id, std::string_view table, Bytes key, Transaction& tx);
    Task<std::optional<Bytes>> get_code(StateVersionId version_id, Bytes key, Transaction& tx);
    CoherentStateRoot* get_root(StateVersionId version_id);
    CoherentStateRoot* advance_root(StateVersionId version_id);
    void evict_roots(StateVersionId next_version_id);
    Task<CoherentStateRoot*> wait_for_root_ready(StateVersionId version_id);
    Task<StateVersionId> get_db_state_version(Transaction& tx) const;
    std::pair<KeyValueSet, KeyValueSet> clone_caches(CoherentStateRoot* root);
    void clear_caches(CoherentStateRoot* root);

    CoherentCacheConfig config_;

    std::map<StateVersionId, std::unique_ptr<CoherentStateRoot>> state_view_roots_;
    StateVersionId latest_state_version_id_{0};
    CoherentStateRoot* latest_state_view_{nullptr};
    std::list<KeyValue> state_evictions_;
    std::list<KeyValue> code_evictions_;
    std::shared_mutex rw_mutex_;
    uint32_t new_block_wait_count_{0};

    uint64_t state_hit_count_{0};
    uint64_t state_miss_count_{0};
    uint64_t state_key_count_{0};
    uint64_t state_eviction_count_{0};
    uint64_t code_hit_count_{0};
    uint64_t code_miss_count_{0};
    uint64_t code_key_count_{0};
    uint64_t code_eviction_count_{0};
};

}  // namespace silkworm::db::kv::api
