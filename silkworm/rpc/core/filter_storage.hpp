// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <chrono>
#include <functional>
#include <limits>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include <silkworm/rpc/types/filter.hpp>
#include <silkworm/rpc/types/log.hpp>

namespace silkworm::rpc {

inline constexpr size_t kDefaultFilterStorageSize = 1024;  // default filter storage size, ie max num for filters in storage
inline constexpr size_t kDefaultMaxFilterAge = 900;        // lasting time for unused filters in seconds (15 min)

enum FilterType {
    kLogs,
    kBlock
};

struct StoredFilter : public Filter {
    FilterType type = FilterType::kLogs;
    uint64_t start = std::numeric_limits<std::uint64_t>::max();
    uint64_t end = std::numeric_limits<std::uint64_t>::max();
    std::vector<Log> logs;
};

struct FilterEntry {
    void renew() { last_access = std::chrono::system_clock::now(); }
    std::chrono::duration<double> age() const { return std::chrono::system_clock::now() - last_access; }

    StoredFilter filter;
    std::chrono::system_clock::time_point last_access = std::chrono::system_clock::now();
};

using Generator = std::function<std::uint64_t()>;

class FilterStorage {
  public:
    explicit FilterStorage(size_t max_size, double max_filter_age = kDefaultMaxFilterAge);
    explicit FilterStorage(Generator& generator, size_t max_size, double max_filter_age = kDefaultMaxFilterAge);

    FilterStorage(const FilterStorage&) = delete;
    FilterStorage& operator=(const FilterStorage&) = delete;

    std::optional<std::string> add_filter(const StoredFilter& filter);
    bool remove_filter(const std::string& filter_id);
    std::optional<std::reference_wrapper<StoredFilter>> get_filter(const std::string& filter_id);

    auto size() const {
        return storage_.size();
    }

  private:
    void clean_up();

    Generator& generator_;
    size_t max_size_;
    std::chrono::duration<double> max_filter_age_;
    std::mutex mutex_;
    std::map<std::string, FilterEntry> storage_;
};

}  // namespace silkworm::rpc
