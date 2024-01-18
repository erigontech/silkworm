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

#include <mutex>

#include <silkworm/infra/concurrency/signal_handler.hpp>
#include <silkworm/node/common/settings.hpp>
#include <silkworm/node/db/etl/util.hpp>
#include <silkworm/node/db/mdbx.hpp>

/*
 * This is a memory-only reduced version of ETL Collector, with compatible interface
 * It can be used to prototype code that will use the full ETL collector or to do performance comparisons
 * between a memory-only impl. and a file-based impl.
 */
namespace silkworm::db::etl {

// Function pointer to process Load on before Load data into tables
using KVLoadFunc = std::function<void(const Bytes& key, const Bytes& value,
                                      db::RWCursorDupSort&, MDBX_put_flags_t)>;

// An adaptor to use map as a collector storage
struct MapStorage : public std::map<Bytes, Bytes> {
    void reserve(size_t) {}  // does nothing, std::map doesn't need to reserve space
    void emplace(const Bytes& key, const Bytes& value) { std::map<Bytes, Bytes>::emplace(key, value); }
    void emplace(Bytes&& key, Bytes&& value) { std::map<Bytes, Bytes>::emplace(std::move(key), std::move(value)); }
    void sort() {}  // does nothing, std::map is always sorted
};

// An adaptor to use vector as a collector storage
struct VectorStorage : public std::vector<std::pair<Bytes, Bytes>> {
    void emplace(const Bytes& key, const Bytes& value) { emplace_back(key, value); }
    void emplace(Bytes&& key, Bytes&& value) { emplace_back(std::move(key), std::move(value)); }
    void sort() { std::sort(begin(), end()); }
};

// Collects data Extracted from db
template <typename CollectorStorage = MapStorage>
class InMemoryCollector {
  public:
    // Not copyable nor movable
    InMemoryCollector(const InMemoryCollector&) = delete;
    InMemoryCollector& operator=(const InMemoryCollector&) = delete;

    explicit InMemoryCollector() = default;

    explicit InMemoryCollector([[maybe_unused]] const NodeSettings* node_settings) {
        entries_.reserve(node_settings->etl_buffer_size);
    }
    explicit InMemoryCollector(const std::filesystem::path&, [[maybe_unused]] size_t optimal_size) {
        entries_.reserve(optimal_size);
    }
    explicit InMemoryCollector([[maybe_unused]] size_t optimal_size) {
        entries_.reserve(optimal_size);
    }

    void collect(const Bytes& key, const Bytes& value) {
        ++size_;
        bytes_size_ += key.size() + value.size();
        entries_.emplace(key, value);
    }

    void collect(Bytes&& key, Bytes&& value) {
        ++size_;
        bytes_size_ += key.size() + value.size();
        entries_.emplace(std::move(key), std::move(value));
    }

    void collect(const Entry& entry) {
        collect(entry.key, entry.value);
    }

    void collect(Entry&& entry) {
        collect(std::move(entry.key), std::move(entry.value));
    }

    //! \brief Loads and optionally transforms collected entries into db
    //! \param [in] target : a cursor opened on target table and owned by caller (can be empty)
    //! \param [in] load_func : Pointer to function transforming collected entries. If NULL no transform is executed
    //! \param [in] flags : Optional put flags for append or upsert (default)
    //! items
    void load(db::RWCursorDupSort& target, const KVLoadFunc& load_func = {},
              MDBX_put_flags_t flags = MDBX_put_flags_t::MDBX_UPSERT) {
        using namespace std::chrono_literals;
        [[maybe_unused]] static const auto kLogInterval{5s};               // Updates processing key (for log purposes) every this time
        [[maybe_unused]] auto log_time{std::chrono::steady_clock::now()};  // To check if an update of key is needed

        set_loading_key({});

        if (empty()) return;

        sort_entries();

        for (const auto& [key, value] : entries_) {
            if (const auto now{std::chrono::steady_clock::now()}; log_time <= now) {
                if (SignalHandler::signalled()) {
                    throw std::runtime_error("Operation cancelled");
                }
                set_loading_key(key);
                log_time = now + kLogInterval;
            }

            if (load_func) {
                load_func(key, value, target, flags);
            } else {
                mdbx::slice k{db::to_slice(key)};
                if (value.empty()) {
                    target.erase(k);
                } else {
                    mdbx::slice v{db::to_slice(value)};
                    mdbx::error::success_or_throw(target.put(k, &v, flags));
                }
            }
        }

        clear();
    }

    //! \brief Returns the number of actually collected items
    [[nodiscard]] size_t size() const { return size_; }

    //! \brief Returns the number of actually collected bytes
    [[nodiscard]] size_t bytes_size() const { return bytes_size_; }

    //! \brief Returns whether this instance is empty (i.e. no items)
    [[nodiscard]] bool empty() const { return size_ == 0; }

    //! \brief Clears contents of collector and reset
    void clear() {
        entries_.clear();
        size_ = 0;
        bytes_size_ = 0;
    }

    //! \brief Returns the hex representation of current load key (for progress tracking)
    [[nodiscard]] std::string get_load_key() const {
        std::unique_lock l{mutex_};
        return loading_key_;
    }

  private:
    size_t size_{0};        // Count of total collected items
    size_t bytes_size_{0};  // Count of total collected bytes

    CollectorStorage entries_;

    void sort_entries() {
        entries_.sort();
    }

    // for progress tracking only
    void set_loading_key(ByteView key) {
        std::unique_lock l{mutex_};
        loading_key_ = to_hex(key, true);
    }
    mutable std::mutex mutex_{};  // To sync loading_key_
    std::string loading_key_{};   // Actual load key (for log purposes)
};

}  // namespace silkworm::db::etl
