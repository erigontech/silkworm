// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include <silkworm/core/common/util.hpp>
#include <silkworm/infra/concurrency/signal_handler.hpp>

#include "collector_settings.hpp"
#include "util.hpp"

/*
 * This is a memory-only reduced version of ETL Collector, with compatible interface
 * It can be used to prototype code that will use the full ETL collector or to do performance comparisons
 * between a memory-only impl. and a file-based impl.
 */
namespace silkworm::datastore::etl {

// Function pointer to process Load on before Load data into tables
using KVLoadFunc = std::function<void(const Bytes& key, const Bytes& value)>;

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

    explicit InMemoryCollector(const CollectorSettings& settings) {
        entries_.reserve(settings.buffer_size);
    }
    explicit InMemoryCollector(const std::filesystem::path&, size_t optimal_size) {
        entries_.reserve(optimal_size);
    }
    explicit InMemoryCollector(size_t optimal_size) {
        entries_.reserve(optimal_size);
    }

    void collect(Entry entry) {
        ++size_;
        bytes_size_ += entry.size();
        entries_.emplace(std::move(entry.key), std::move(entry.value));
    }

    void collect(Bytes key, Bytes value) {
        collect(Entry{std::move(key), std::move(value)});
    }

    //! \brief Loads and optionally transforms collected entries into db
    //! \param [in] load_func : Pointer to function transforming collected entries
    void load(const KVLoadFunc& load_func) {
        using namespace std::chrono_literals;
        [[maybe_unused]] static constexpr std::chrono::seconds kLogInterval{5s};  // Updates processing key (for log purposes) every this time
        [[maybe_unused]] auto log_time{std::chrono::steady_clock::now()};         // To check if an update of key is needed

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

            load_func(key, value);
        }

        clear();
    }

    //! \brief Returns the number of actually collected items
    size_t size() const { return size_; }

    //! \brief Returns the number of actually collected bytes
    size_t bytes_size() const { return bytes_size_; }

    //! \brief Returns whether this instance is empty (i.e. no items)
    bool empty() const { return size_ == 0; }

    //! \brief Clears contents of collector and reset
    void clear() {
        entries_.clear();
        size_ = 0;
        bytes_size_ = 0;
    }

    //! \brief Returns the hex representation of current load key (for progress tracking)
    std::string get_load_key() const {
        std::scoped_lock l{mutex_};
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
        std::scoped_lock l{mutex_};
        loading_key_ = to_hex(key, true);
    }
    mutable std::mutex mutex_{};  // To sync loading_key_
    std::string loading_key_{};   // Actual load key (for log purposes)
};

}  // namespace silkworm::datastore::etl
