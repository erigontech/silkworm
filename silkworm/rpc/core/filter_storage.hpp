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

#include <chrono>
#include <functional>
#include <limits>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

#include <silkworm/rpc/types/filter.hpp>
#include <silkworm/rpc/types/log.hpp>

namespace silkworm::rpc {

static const std::size_t kDefaultFilterStorageSize = 1024;  // default filter storage size, ie max num for filters in storage
static const std::size_t kDefaultMaxFilterAge = 900;        // lasting time for unused filters in seconds (15 min)

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
    [[nodiscard]] std::chrono::duration<double> age() const { return std::chrono::system_clock::now() - last_access; }

    StoredFilter filter;
    std::chrono::system_clock::time_point last_access = std::chrono::system_clock::now();
};

using Generator = std::function<std::uint64_t()>;

class FilterStorage {
  public:
    explicit FilterStorage(std::size_t max_size, double max_filter_age = kDefaultMaxFilterAge);
    explicit FilterStorage(Generator& generator, std::size_t max_size, double max_filter_age = kDefaultMaxFilterAge);

    FilterStorage(const FilterStorage&) = delete;
    FilterStorage& operator=(const FilterStorage&) = delete;

    std::optional<std::string> add_filter(const StoredFilter& filter);
    bool remove_filter(const std::string& filter_id);
    std::optional<std::reference_wrapper<StoredFilter>> get_filter(const std::string& filter_id);

    [[nodiscard]] auto size() const {
        return storage_.size();
    }

  private:
    void clean_up();

    Generator& generator_;
    std::size_t max_size_;
    std::chrono::duration<double> max_filter_age_;
    std::mutex mutex_;
    std::map<std::string, FilterEntry> storage_;
};

}  // namespace silkworm::rpc
