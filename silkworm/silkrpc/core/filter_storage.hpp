/*
   Copyright 2023 The Silkrpc Authors

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
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include <silkworm/silkrpc/types/filter.hpp>
#include <silkworm/silkrpc/types/log.hpp>

namespace silkrpc::filter {

enum FilterType {
    logs,
    pending_transactions,
    block
};

struct StoredFilter: public Filter {
    FilterType type = FilterType::logs;
    uint64_t start = std::numeric_limits<std::uint64_t>::max();
    uint64_t end = std::numeric_limits<std::uint64_t>::max();
    std::vector<Log> logs;
};

struct FilterEntry {
    void renew() {last_access = std::chrono::system_clock::now();}
    std::chrono::duration<double> age() { return std::chrono::system_clock::now() - last_access;}

    StoredFilter filter;
    std::chrono::system_clock::time_point last_access = std::chrono::system_clock::now();
};

typedef std::function<std::uint64_t()> Generator;

class FilterStorage {
public:
    explicit FilterStorage(std::size_t max_size, double max_filter_age = DEFAULT_MAX_FILTER_AGE);
    explicit FilterStorage(Generator& generator, std::size_t max_size, double max_filter_age = DEFAULT_MAX_FILTER_AGE);

    FilterStorage(const FilterStorage&) = delete;
    FilterStorage& operator=(const FilterStorage&) = delete;

    std::optional<std::string> add_filter(const StoredFilter& filter);
    bool remove_filter(const std::string& filter_id);
    std::optional<std::reference_wrapper<StoredFilter>> get_filter(const std::string& filter_id);

    auto size() const {
        return storage_.size();
    }

private:
    static const std::size_t DEFAULT_MAX_FILTER_AGE = 0x800;

    void clean_up();

    std::size_t max_size_;
    std::chrono::duration<double> max_filter_age_;
    std::mutex mutex_;
    std::map<std::string, FilterEntry> storage_;
    Generator& generator_;
};

} // namespace silkrpc::filter

